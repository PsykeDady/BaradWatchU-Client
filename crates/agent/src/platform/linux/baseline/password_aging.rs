//! Local ordinary interactive accounts only. chage is the trusted metadata utility;
//! BaradWatchU never opens shadow or requests password/hash output.
use super::{
    context,
    credential_sources::{unavailable, Snapshot},
    files::Files,
    guarded, host, observed,
};
use crate::{
    audit::Outcome,
    observation::{AccountAging, AgingValues, Observation, PasswordAging, Quality},
    platform::{
        command::{CommandRunner, ProbeError},
        linux::environment::Environment,
    },
};
use std::collections::{BTreeMap, BTreeSet};

const SCOPE: &str = "LOCAL_ORDINARY_INTERACTIVE_ACCOUNTS; external/root/system accounts excluded; shell/UID selection is not role attestation";
fn empty() -> PasswordAging {
    PasswordAging {
        quality: Quality::Inconclusive,
        scope: SCOPE.into(),
        creation_defaults: AgingValues::default(),
        accounts: vec![],
        excluded_accounts: 0,
        external_authority_configured: None,
    }
}

pub fn observe(files: &dyn Files, runner: &dyn CommandRunner, env: &Environment) -> Outcome {
    let facts = if !host(env) {
        PasswordAging {
            quality: Quality::Restricted,
            ..empty()
        }
    } else {
        collect(files, runner).unwrap_or_else(|_| empty())
    };
    context(observed(Observation::PasswordAging(facts.clone()), facts.quality, None,
        "local account selection metadata + guarded chage --list; login.defs creation defaults separate",
        SCOPE, "Account aging facts only; no password hashes, raw output, names or home paths retained in report"), env)
}

fn defaults(text: &str) -> Result<BTreeMap<String, i64>, ProbeError> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let words: Vec<_> = line
            .split('#')
            .next()
            .unwrap_or("")
            .split_whitespace()
            .collect();
        if words.is_empty()
            || !matches!(
                words[0],
                "UID_MIN" | "UID_MAX" | "PASS_MAX_DAYS" | "PASS_MIN_DAYS" | "PASS_WARN_AGE"
            )
        {
            continue;
        }
        if words.len() != 2
            || values
                .insert(
                    words[0].into(),
                    words[1].parse().map_err(|_| unavailable())?,
                )
                .is_some()
        {
            return Err(unavailable());
        }
    }
    Ok(values)
}
fn collect(files: &dyn Files, runner: &dyn CommandRunner) -> Result<PasswordAging, ProbeError> {
    let mut source = Snapshot::new(files);
    let config = defaults(&source.required("/etc/login.defs")?)?;
    let min = *config.get("UID_MIN").ok_or_else(unavailable)?;
    let max = *config.get("UID_MAX").ok_or_else(unavailable)?;
    if min < 1 || max < min || max > i64::from(u32::MAX) {
        return Err(unavailable());
    }
    let shell_text = source.required("/etc/shells")?;
    let shells: BTreeSet<_> = shell_text
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|s| s.starts_with('/') && !s.ends_with("/nologin") && !s.ends_with("/false"))
        .collect();
    if shells.is_empty() {
        return Err(unavailable());
    }
    let mut facts = empty();
    facts.creation_defaults = AgingValues {
        maximum_days: config.get("PASS_MAX_DAYS").copied(),
        minimum_days: config.get("PASS_MIN_DAYS").copied(),
        warning_days: config.get("PASS_WARN_AGE").copied(),
    };
    // Do not enumerate network directories or query their password authority.
    if let Some(nss) = source.read("/etc/nsswitch.conf")? {
        let lines: Vec<_> = nss
            .lines()
            .filter_map(|l| l.split('#').next()?.trim().strip_prefix("passwd:"))
            .collect();
        if lines.len() == 1 {
            let tokens: Vec<_> = lines[0].split_whitespace().collect();
            facts.external_authority_configured =
                Some(tokens.iter().any(|s| !matches!(*s, "files" | "systemd")));
        }
    }
    let accounts = source.required("/etc/passwd")?;
    let mut names = BTreeSet::new();
    let mut ids = BTreeSet::new();
    for line in accounts.lines().filter(|s| !s.is_empty()) {
        let fields: Vec<_> = line.split(':').collect();
        if fields.len() != 7 {
            return Err(unavailable());
        }
        let uid: u32 = fields[2].parse().map_err(|_| unavailable())?;
        if !names.insert(fields[0]) || !ids.insert(uid) {
            return Err(unavailable());
        }
        if i64::from(uid) < min || i64::from(uid) > max || !shells.contains(fields[6]) {
            facts.excluded_accounts += 1;
            continue;
        }
        // Refuse legacy non-shadow authentication layouts without interpreting the field.
        if fields[1] != "x"
            || !super::credential_sources::name(fields[0])
            || fields[0].starts_with('-')
            || facts.accounts.len() >= 32
        {
            return Err(unavailable());
        }
        let mut spec = guarded("/usr/bin/chage", &["--list", "--iso8601", "--", fields[0]]);
        spec.output_limit = 4096;
        let (parsed, failure_reason) = match runner.run(&spec) {
            Ok(output) if output.code == Some(0) && output.stderr.trim().is_empty() => (
                parse_chage(&output.stdout).ok(),
                "CHAGE_FORMAT_INCONCLUSIVE",
            ),
            Ok(output) => (
                None,
                match output.code {
                    Some(1) => "CHAGE_ACCESS_DENIED",
                    Some(2) => "CHAGE_OPTIONS_UNSUPPORTED",
                    Some(15) => "CHAGE_DATABASE_UNAVAILABLE",
                    _ => "CHAGE_QUERY_INCONCLUSIVE",
                },
            ),
            Err(error) => (
                None,
                match error.reason {
                    crate::audit::Reason::PermissionDenied => "CHAGE_ACCESS_DENIED",
                    crate::audit::Reason::ReadOnlyGuardUnavailable => "CHAGE_GUARD_UNAVAILABLE",
                    crate::audit::Reason::MissingTool => "CHAGE_TOOL_UNAVAILABLE",
                    crate::audit::Reason::Timeout => "CHAGE_TIMEOUT",
                    _ => "CHAGE_QUERY_INCONCLUSIVE",
                },
            ),
        };
        let (values, expires, quality, reason) = match parsed {
            Some((v, e)) => (v, Some(e), Quality::Verified, "CHAGE_AGING_METADATA"),
            None => (
                AgingValues::default(),
                None,
                Quality::Inconclusive,
                failure_reason,
            ),
        };
        facts.accounts.push(AccountAging {
            id: format!("local-{}", facts.accounts.len() + 1),
            quality,
            values,
            expires,
            reason: reason.into(),
        });
    }
    source.consistent()?;
    facts.quality = Quality::Verified;
    Ok(facts)
}
fn date(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 10
        || b[4] != b'-'
        || b[7] != b'-'
        || b.iter()
            .enumerate()
            .any(|(i, v)| i != 4 && i != 7 && !v.is_ascii_digit())
    {
        return false;
    }
    let year: u32 = s[..4].parse().unwrap_or(0);
    let month: usize = s[5..7].parse().unwrap_or(0);
    let day: u32 = s[8..].parse().unwrap_or(0);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = [
        0,
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    year >= 1970 && month <= 12 && day > 0 && day <= days[month]
}
pub fn parse_chage(text: &str) -> Result<(AgingValues, bool), ProbeError> {
    let mut values = BTreeMap::new();
    for line in text.lines() {
        let (k, v) = line.split_once(':').ok_or_else(unavailable)?;
        if values.insert(k.trim(), v.trim()).is_some() {
            return Err(unavailable());
        }
    }
    let labels = [
        "Last password change",
        "Password expires",
        "Password inactive",
        "Account expires",
        "Minimum number of days between password change",
        "Maximum number of days between password change",
        "Number of days of warning before password expires",
    ];
    if values.len() != labels.len() || labels.iter().any(|k| !values.contains_key(k)) {
        return Err(unavailable());
    }
    for k in &labels[..4] {
        let s = values[k];
        if s != "never" && s != "password must be changed" && !date(s) {
            return Err(unavailable());
        }
    }
    let number = |k: &str| -> Result<i64, ProbeError> {
        let v: i64 = values[k].parse().map_err(|_| unavailable())?;
        if v < -1 {
            Err(unavailable())
        } else {
            Ok(v)
        }
    };
    let min = number(labels[4])?;
    let max = number(labels[5])?;
    let warn = number(labels[6])?;
    // A forced change (last-change day zero) is printed before chage checks
    // maxdays. It does not establish recurring expiry when maxdays is -1.
    let expiry_text = values[labels[1]];
    let forced = expiry_text == "password must be changed";
    let expires = expiry_text != "never" && max >= 0;
    if (expiry_text != "never" && !forced && max < 0) || (min >= 0 && max >= 0 && min > max) {
        return Err(unavailable());
    }
    Ok((
        AgingValues {
            maximum_days: Some(max),
            minimum_days: Some(min),
            warning_days: Some(warn),
        },
        expires,
    ))
}
