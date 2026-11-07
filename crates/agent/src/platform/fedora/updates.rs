use crate::platform::probe::{failure, unsuccessful};
use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    observation::{MetadataState, Observation, RepositoryMetadata, UpdateClass, Updates},
    platform::command::{CommandRunner, CommandSpec, ProbeError},
};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

const FLAGS: &[&str] = &[
    "--cacheonly",
    "--no-plugins",
    "--skip-file-locks",
    "--quiet",
    "--color=never",
    "--setopt=logdir=/dev/null",
    "--setopt=build_cache=False",
    "--setopt=*.build_cache=False",
    "--setopt=*.skip_if_unavailable=False",
    // Query scope must not silently hide pending packages through global excludes.
    // This is process-local; repository and system configuration are never rewritten.
    "--setopt=disable_excludes=*",
];
const SOURCE: &str =
    "DNF5 cache-only check-upgrade + repo info JSON + repoquery upgrades + advisory updates JSON";
const SCOPE: &str = "cached RPM update observations; no refresh, transaction or package changes";
fn command(args: &[&str]) -> CommandSpec {
    let mut all = FLAGS.to_vec();
    all.extend_from_slice(args);
    let mut spec = CommandSpec::new("/usr/bin/dnf5", &all);
    spec.read_only_filesystem = true;
    spec
}
fn invalid(message: &str) -> Outcome {
    failure(
        ProbeError::new(Reason::InvalidOutput, message),
        SOURCE,
        SCOPE,
    )
}
fn query(runner: &dyn CommandRunner, args: &[&str]) -> Result<String, Box<Outcome>> {
    match runner.run(&command(args)) {
        Ok(output) if output.code == Some(0) => Ok(output.stdout),
        Ok(output) => {
            let error = output.stderr.to_ascii_lowercase();
            if error.contains("cache")
                && (error.contains("no cache")
                    || error.contains("missing")
                    || error.contains("cache-only enabled")
                    || error.contains("not found"))
                && !error.contains("permission denied")
                && !error.contains("operation not permitted")
            {
                Err(Box::new(Outcome::new(
                    Status::Warn,
                    Reason::CacheUnavailable,
                    "Required cached metadata is unavailable; no refresh attempted",
                )))
            } else {
                Err(Box::new(unsuccessful(&output, SOURCE, SCOPE)))
            }
        }
        Err(error) => Err(Box::new(failure(error, SOURCE, SCOPE))),
    }
}
fn partial(mut outcome: Outcome, mut facts: Updates) -> Outcome {
    if outcome.reason_code == Reason::CacheUnavailable {
        facts.metadata_state = MetadataState::Missing;
        facts.coverage_complete = false;
    }
    if outcome.evidence.is_empty() {
        outcome = outcome.with_evidence(Evidence::new(
            SOURCE,
            SCOPE,
            &[
                ("cacheOnly", json!(true)),
                ("privileges", json!("caller; no elevation")),
            ],
        ));
    }
    outcome.with_observation(Observation::Updates(facts))
}

#[derive(Deserialize)]
struct Repo {
    id: String,
    is_enabled: bool,
    timestamp: Option<u64>,
    metadata_expire: Option<i64>,
    exclude_pkgs: Option<Vec<String>>,
    include_pkgs: Option<Vec<String>>,
}
#[derive(Deserialize)]
struct Advisory {
    name: String,
    #[serde(rename = "type")]
    kind: String,
    nevra: String,
}

fn package(raw: &str) -> Option<(String, String)> {
    if raw.is_empty()
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-+:~^".contains(&b))
    {
        return None;
    }
    let (nev, arch) = raw.rsplit_once('.')?;
    let mut pieces = nev.rsplitn(3, '-');
    let release = pieces.next()?;
    let version = pieces.next()?;
    let name = pieces.next()?;
    if [release, version, name, arch].iter().any(|v| v.is_empty()) {
        return None;
    }
    if name.contains(':')
        || release.contains(':')
        || !arch.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return None;
    }
    if let Some((epoch, value)) = version.split_once(':') {
        if epoch.parse::<u32>().is_err() || value.is_empty() || value.contains(':') {
            return None;
        }
    }
    // Nonzero epoch is retained; zero is normalized because advisory JSON may omit it.
    let normalized_version = version.strip_prefix("0:").unwrap_or(version);
    Some((
        format!("{name}-{normalized_version}-{release}.{arch}"),
        format!("{name}.{arch}"),
    ))
}

pub fn updates(runner: &dyn CommandRunner) -> Outcome {
    let output = match runner.run(&command(&["check-upgrade"])) {
        Ok(output) => output,
        Err(error) => return failure(error, SOURCE, SCOPE),
    };
    let stderr = output.stderr.to_ascii_lowercase();
    let stdout = output.stdout.to_ascii_lowercase();
    let (status, reason, message) = match output.code {
        Some(100) => (Status::Fail,Reason::UpdatesAvailable,"Pending RPM updates observed in cache; security classification is reported separately"),
        Some(0) if stdout.contains("no enabled repositories") || stderr.contains("no enabled repositories") =>
            return partial(Outcome::new(Status::Warn,Reason::NoEnabledRepositories,"No enabled repositories; no update coverage"), Updates { metadata_state: MetadataState::Missing, ..Updates::default() }),
        Some(0) => (Status::Warn,Reason::NoCachedUpdates,"No pending updates observed in cached metadata; policy evaluates its age and coverage separately"),
        _ if stderr.contains("permission denied") || stderr.contains("operation not permitted") || stderr.contains("superuser") => return unsuccessful(&output,SOURCE,SCOPE),
        _ if stderr.contains("cache") && (stderr.contains("missing") || stderr.contains("not found") || stderr.contains("no cache") || stderr.contains("cache-only enabled") || stderr.contains("cacheonly enabled")) =>
            return partial(Outcome::new(Status::Warn,Reason::CacheUnavailable,"Metadata cache unavailable; no refresh attempted"), Updates::default()),
        _ => return unsuccessful(&output,SOURCE,SCOPE),
    };
    let pending = output.code == Some(100);
    let mut facts = Updates::default();
    if !pending {
        facts.classification = UpdateClass::NoPending;
        facts.pending_packages = Some(0);
        facts.security_advisories = Some(0);
        facts.ordinary_pending = Some(false);
        facts.classification_complete = true;
    } else {
        facts.classification = UpdateClass::UnknownSecurity;
    }
    let repo_json = match query(runner, &["repo", "info", "--enabled", "--json"]) {
        Ok(json) => json,
        Err(outcome) => return partial(*outcome, facts),
    };
    let repos: Vec<Repo> = match serde_json::from_str(&repo_json) {
        Ok(repos) => repos,
        Err(_) => {
            return invalid("Invalid DNF5 repo info JSON")
                .with_observation(Observation::Updates(facts))
        }
    };
    let mut seen = BTreeSet::new();
    facts.coverage_complete = !repos.is_empty();
    for repo in repos {
        if !repo.is_enabled || repo.id.is_empty() || !seen.insert(repo.id.clone()) {
            return invalid("Contradictory or duplicate enabled repository records")
                .with_observation(Observation::Updates(facts));
        }
        if !matches!(repo.exclude_pkgs.as_deref(), Some([]))
            || !matches!(repo.include_pkgs.as_deref(), Some([]))
        {
            facts.coverage_complete = false;
        }
        facts.repositories.push(RepositoryMetadata {
            id: repo.id,
            timestamp_unix_seconds: repo.timestamp,
            expires_after_seconds: repo.metadata_expire,
        });
    }
    facts.repositories.sort_by(|a, b| a.id.cmp(&b.id));
    facts.metadata_state = if facts.repositories.is_empty() {
        MetadataState::Missing
    } else {
        MetadataState::Available
    };
    if pending {
        if facts.repositories.is_empty() {
            return invalid("Update/repository snapshots disagree")
                .with_observation(Observation::Updates(facts));
        }
        let packages = match query(
            runner,
            &[
                "repoquery",
                "--upgrades",
                "--latest-limit=1",
                "--queryformat=%{full_nevra}",
            ],
        ) {
            Ok(packages) => packages,
            Err(outcome) => return partial(*outcome, facts),
        };
        let mut candidates = BTreeMap::new();
        for line in packages.lines().filter(|line| !line.is_empty()) {
            let Some((nevra, name)) = package(line) else {
                return invalid("Invalid DNF5 upgrade package identifier")
                    .with_observation(Observation::Updates(facts));
            };
            candidates.insert(nevra, name);
        }
        if candidates.is_empty() {
            return invalid("Update snapshots disagree; not an atomic package transaction")
                .with_observation(Observation::Updates(facts));
        }
        facts.pending_packages = Some(candidates.len());
        let advisories = match query(runner, &["advisory", "list", "--updates", "--json"]) {
            Ok(advisories) => advisories,
            Err(outcome) => return partial(*outcome, facts),
        };
        let advisories: Vec<Advisory> = match serde_json::from_str(&advisories) {
            Ok(advisories) => advisories,
            Err(_) => {
                return invalid("Invalid DNF5 advisory JSON")
                    .with_observation(Observation::Updates(facts))
            }
        };
        let mut security_names = BTreeSet::new();
        let mut security_advisories = BTreeSet::new();
        let mut ordinary = BTreeSet::new();
        let mut unknown_names = BTreeSet::new();
        for advisory in advisories {
            let Some((nevra, name)) = package(&advisory.nevra) else {
                return invalid("Invalid advisory package identifier")
                    .with_observation(Observation::Updates(facts));
            };
            if advisory.name.is_empty() {
                return invalid("Advisory identity missing")
                    .with_observation(Observation::Updates(facts));
            }
            if advisory.kind == "security"
                && candidates.values().any(|candidate| candidate == &name)
            {
                security_names.insert(name);
                security_advisories.insert(advisory.name);
            } else if matches!(
                advisory.kind.as_str(),
                "bugfix" | "enhancement" | "newpackage"
            ) && candidates.contains_key(&nevra)
            {
                ordinary.insert(nevra);
            } else if !matches!(
                advisory.kind.as_str(),
                "security" | "bugfix" | "enhancement" | "newpackage"
            ) && candidates.values().any(|candidate| candidate == &name)
            {
                unknown_names.insert(name);
            }
        }
        let known: BTreeSet<_> = candidates
            .iter()
            .filter(|(nevra, name)| security_names.contains(*name) || ordinary.contains(*nevra))
            .map(|(nevra, _)| nevra)
            .collect();
        facts.security_advisories = Some(security_advisories.len());
        facts.ordinary_pending = Some(
            ordinary
                .iter()
                .any(|nevra| !security_names.contains(&candidates[nevra])),
        );
        facts.classification_complete = known.len() == candidates.len() && unknown_names.is_empty();
        facts.classification = if !security_advisories.is_empty() {
            UpdateClass::SecurityPending
        } else if facts.classification_complete {
            UpdateClass::OrdinaryPending
        } else {
            UpdateClass::UnknownSecurity
        };
    }
    Outcome::new(status, reason, message)
        .with_evidence(Evidence::new(
            SOURCE,
            SCOPE,
            &[
                ("exitCode", json!(output.code)),
                ("cacheOnly", json!(true)),
                ("cacheFreshnessVerified", json!(false)),
                ("pluginsEnabled", json!(false)),
                ("systemRepositoryLock", json!(false)),
                ("excludesDisabledForQuery", json!(true)),
                (
                    "filesystemGuard",
                    json!("Linux Landlock ABI >=3; filesystem writes denied"),
                ),
                ("privileges", json!("caller; no elevation")),
            ],
        ))
        .with_observation(Observation::Updates(facts))
}
