//! Read-only Netfilter INPUT observations. No inference from service presence alone.
use super::{context, error, guarded, host, observed, query};
use crate::{
    audit::{Evidence, Outcome, Reason},
    observation::{Filtering, Firewall, FirewallManager, Observation, Quality},
    platform::{
        command::{CommandRunner, ProbeError},
        linux::environment::Environment,
    },
};
use serde_json::{json, Value};
use std::collections::{BTreeMap, BTreeSet};
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Input {
    AllDropped,
    NoFiltering,
    Unknown,
}
fn invalid() -> ProbeError {
    ProbeError::new(
        Reason::InvalidOutput,
        "Malformed or unsupported firewall inspection evidence",
    )
}
/// Only a deliberately small, provable subset is conclusive. Arbitrary rule
/// reachability, jumps, sets and manager policies require future analysis.
pub fn nft(text: &str) -> Result<(Input, Input), ProbeError> {
    let v: Value = serde_json::from_str(text).map_err(|_| invalid())?;
    let items = v
        .get("nftables")
        .and_then(Value::as_array)
        .ok_or_else(invalid)?;
    let mut dormant = BTreeSet::new();
    let mut chains = BTreeMap::new();
    let mut rules: BTreeMap<(String, String, String), Vec<&Value>> = BTreeMap::new();
    let mut other = false;
    for item in items {
        if let Some(t) = item.get("table") {
            let family = t
                .get("family")
                .and_then(Value::as_str)
                .ok_or_else(invalid)?;
            let name = t.get("name").and_then(Value::as_str).ok_or_else(invalid)?;
            if t.get("flags")
                .and_then(Value::as_array)
                .is_some_and(|flags| !flags.is_empty())
            {
                dormant.insert((family.to_owned(), name.to_owned()));
            }
        } else if let Some(c) = item.get("chain") {
            let key = key(c)?;
            if chains.insert(key, c).is_some() {
                return Err(invalid());
            }
        } else if let Some(r) = item.get("rule") {
            rules.entry(key(r)?).or_default().push(
                r.get("expr")
                    .and_then(Value::as_array)
                    .map(|_| r)
                    .ok_or_else(invalid)?,
            );
        } else if item.get("metainfo").is_none() {
            other = true
        }
    }
    let mut v4 = Input::NoFiltering;
    let mut v6 = Input::NoFiltering;
    for (key, c) in &chains {
        if dormant.contains(&(key.0.clone(), key.1.clone())) {
            other = true;
            continue;
        }
        if c.get("hook").is_none() {
            if rules.contains_key(key) {
                other = true
            }
            continue;
        }
        if c.get("hook").and_then(Value::as_str) != Some("input")
            || c.get("type").and_then(Value::as_str) != Some("filter")
        {
            other = true;
            continue;
        }
        let expr = rules.get(key).map(Vec::as_slice).unwrap_or_default();
        let first_drops = expr.first().is_some_and(|r| {
            let e = r["expr"].as_array().expect("validated array");
            !e.is_empty()
                && e.last().is_some_and(|x| {
                    x.as_object().is_some_and(|o| o.len() == 1)
                        && (x.get("drop") == Some(&Value::Null) || x.get("reject").is_some())
                })
                && e[..e.len() - 1].iter().all(|x| {
                    x.as_object()
                        .is_some_and(|o| o.len() == 1 && o.contains_key("counter"))
                })
        });
        let state = if first_drops
            || expr.is_empty() && c.get("policy").and_then(Value::as_str) == Some("drop")
        {
            Input::AllDropped
        } else if expr.is_empty() && c.get("policy").and_then(Value::as_str) == Some("accept") {
            Input::NoFiltering
        } else {
            Input::Unknown
        };
        for target in match key.0.as_str() {
            "inet" => vec![&mut v4, &mut v6],
            "ip" => vec![&mut v4],
            "ip6" => vec![&mut v6],
            _ => {
                other = true;
                vec![]
            }
        } {
            *target = combine(*target, state);
        }
    }
    if rules.keys().any(|k| !chains.contains_key(k)) {
        return Err(invalid());
    }
    if other {
        if v4 != Input::AllDropped {
            v4 = Input::Unknown
        }
        if v6 != Input::AllDropped {
            v6 = Input::Unknown
        }
    }
    Ok((v4, v6))
}
fn key(v: &Value) -> Result<(String, String, String), ProbeError> {
    let s = |k| {
        v.get(k)
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .ok_or_else(invalid)
    };
    Ok((
        s("family")?,
        s("table")?,
        s(if v.get("chain").is_some() {
            "chain"
        } else {
            "name"
        })?,
    ))
}
fn combine(a: Input, b: Input) -> Input {
    if a == Input::AllDropped || b == Input::AllDropped {
        Input::AllDropped
    } else if a == Input::Unknown || b == Input::Unknown {
        Input::Unknown
    } else {
        Input::NoFiltering
    }
}
pub fn iptables(text: &str) -> Result<Input, ProbeError> {
    let mut filter = false;
    let mut completed = false;
    let mut policy = None;
    let mut input_rules = Vec::new();
    let mut unknown = false;
    let mut in_table = false;
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if let Some(table) = line.strip_prefix('*') {
            if in_table {
                return Err(invalid());
            }
            in_table = true;
            filter = table == "filter";
            if !filter {
                unknown = true
            }
            continue;
        }
        if line == "COMMIT" {
            if !in_table {
                return Err(invalid());
            }
            in_table = false;
            if filter {
                completed = true
            }
            filter = false;
            continue;
        }
        if !in_table {
            return Err(invalid());
        }
        if filter {
            if line.starts_with(":INPUT ") {
                if policy.is_some() {
                    return Err(invalid());
                }
                policy = line.split_whitespace().nth(1)
            } else if line.starts_with("-A INPUT ") {
                input_rules.push(line)
            } else if !line.starts_with(':') {
                unknown = true
            }
        }
    }
    if in_table {
        return Err(invalid());
    }
    if input_rules
        .first()
        .is_some_and(|l| matches!(*l, "-A INPUT -j DROP" | "-A INPUT -j REJECT"))
        || completed && policy == Some("DROP") && input_rules.is_empty()
    {
        return Ok(Input::AllDropped);
    }
    if unknown || !input_rules.is_empty() {
        return Ok(Input::Unknown);
    }
    if text.trim().is_empty() || completed && policy == Some("ACCEPT") {
        Ok(Input::NoFiltering)
    } else {
        Ok(Input::Unknown)
    }
}
pub fn managers(text: &str) -> Result<Vec<FirewallManager>, ProbeError> {
    let expected = [
        "firewalld.service",
        "nftables.service",
        "ufw.service",
        "iptables.service",
        "ip6tables.service",
    ];
    let mut parsed = BTreeMap::new();
    for block in text.trim().split("\n\n") {
        let mut fields = BTreeMap::new();
        for line in block.lines() {
            let (k, v) = line.split_once('=').ok_or_else(invalid)?;
            if fields.insert(k, v).is_some() {
                return Err(invalid());
            }
        }
        let id = *fields.get("Id").ok_or_else(invalid)?;
        if !expected.contains(&id) || parsed.contains_key(id) {
            return Err(invalid());
        }
        let installed = match fields.get("LoadState").copied() {
            Some("loaded" | "masked") => Some(true),
            Some("not-found") => Some(false),
            _ => None,
        };
        let active = match fields.get("ActiveState").copied() {
            Some("active") => Some(true),
            Some("inactive" | "failed") => Some(false),
            _ => None,
        };
        let running = match fields.get("SubState").copied() {
            Some("running") => Some(true),
            Some("dead" | "exited" | "failed") => Some(false),
            _ => None,
        };
        parsed.insert(
            id,
            FirewallManager {
                name: id.trim_end_matches(".service").to_owned(),
                installed,
                active,
                running,
            },
        );
    }
    if parsed.len() != expected.len() {
        return Err(invalid());
    }
    let mut result = Vec::new();
    for id in expected {
        result.push(parsed.remove(id).expect("complete unit set"))
    }
    Ok(result)
}
fn result(f: Firewall, message: &str) -> Outcome {
    let positive = match f.filtering {
        Filtering::VerifiedInputFiltering => Some(true),
        Filtering::NoFilteringInInspectedInputBackends => Some(false),
        Filtering::Unknown => None,
    };
    observed(
        Observation::Firewall(f.clone()),
        f.quality,
        positive,
        "systemd manager properties + nft JSON + IPv4/IPv6 iptables-save",
        "host Netfilter INPUT only; no traffic tests or general rule-policy certification",
        message,
    )
}
pub fn firewall(runner: &dyn CommandRunner, env: &Environment) -> Outcome {
    let mut f = Firewall {
        quality: Quality::Restricted,
        managers: vec![],
        filtering: Filtering::Unknown,
        ipv4_verified: false,
        ipv6_verified: false,
        multiple_managers: false,
    };
    if !host(env) {
        return context(result(f,"Host firewall scope unavailable in container/unknown context; host buses are not queried"),env);
    }
    let mut issues = Vec::new();
    let mut fatal = None;
    match query(
        runner,
        "/usr/bin/systemctl",
        &[
            "--system",
            "--no-pager",
            "--no-ask-password",
            "show",
            "firewalld.service",
            "nftables.service",
            "ufw.service",
            "iptables.service",
            "ip6tables.service",
            "--property=Id,LoadState,ActiveState,SubState",
        ],
    )
    .and_then(|s| managers(&s))
    {
        Ok(m) => f.managers = m,
        Err(e) => {
            issues.push(json!({"source":"systemd managers","reason":e.reason}));
            if !matches!(e.reason, Reason::MissingTool | Reason::PermissionDenied) {
                fatal = Some(e)
            }
        }
    }
    let mut n = (Input::Unknown, Input::Unknown);
    let mut v4 = Input::Unknown;
    let mut v6 = Input::Unknown;
    let mut rule_tools = 0;
    for (name, args, index) in [
        (
            "/usr/bin/nft",
            vec!["--json", "--numeric", "list", "ruleset"],
            0,
        ),
        (
            "/usr/bin/iptables-save",
            vec!["--modprobe", "/usr/bin/false"],
            1,
        ),
        (
            "/usr/bin/ip6tables-save",
            vec!["--modprobe", "/usr/bin/false"],
            2,
        ),
    ] {
        let spec = guarded(name, &args);
        let r = runner.run(&spec).and_then(|o| {
            if o.code != Some(0) || !o.stderr.trim().is_empty() {
                let denied = o.stderr.to_ascii_lowercase();
                return Err(ProbeError::new(
                    if denied.contains("permission denied")
                        || denied.contains("operation not permitted")
                        || denied.contains("must be root")
                    {
                        Reason::PermissionDenied
                    } else {
                        Reason::ExecutionFailed
                    },
                    "Rule inspection failed; no privilege escalation",
                ));
            }
            if index == 0 {
                n = nft(&o.stdout)?
            } else if index == 1 {
                v4 = iptables(&o.stdout)?
            } else {
                v6 = iptables(&o.stdout)?
            }
            Ok(())
        });
        match r {
            Ok(()) => rule_tools += 1,
            Err(e) => {
                issues.push(json!({"source":name,"reason":e.reason}));
                if !matches!(e.reason, Reason::MissingTool | Reason::PermissionDenied) {
                    fatal = Some(e)
                }
            }
        }
    }
    let active: BTreeSet<_> = f
        .managers
        .iter()
        .filter(|m| m.active == Some(true))
        .map(|m| {
            if m.name == "ip6tables" {
                "iptables"
            } else {
                m.name.as_str()
            }
        })
        .collect();
    f.multiple_managers = active.len() > 1;
    let managers_known = f.managers.len() == 5
        && f.managers
            .iter()
            .all(|m| m.installed.is_some() && m.active.is_some());
    let ipv4 = combine(n.0, v4);
    let ipv6 = combine(n.1, v6);
    f.ipv4_verified = ipv4 == Input::AllDropped;
    f.ipv6_verified = ipv6 == Input::AllDropped;
    if managers_known && !f.multiple_managers && f.ipv4_verified && f.ipv6_verified {
        f.filtering = Filtering::VerifiedInputFiltering;
        f.quality = Quality::Verified
    } else if managers_known
        && !f.multiple_managers
        && n == (Input::NoFiltering, Input::NoFiltering)
        && v4 == Input::NoFiltering
        && v6 == Input::NoFiltering
    {
        f.filtering = Filtering::NoFilteringInInspectedInputBackends;
        f.quality = Quality::Verified
    } else {
        f.quality = if rule_tools == 0 && issues.iter().all(|v| v["reason"] == "MISSING_TOOL") {
            Quality::Missing
        } else {
            Quality::Inconclusive
        }
    }
    let mut outcome=result(f,"Service state is separate from verified INPUT filtering; complex/inaccessible rules remain inconclusive")
        .with_evidence(Evidence::new("Readonly command inspection outcomes","no addresses, ports, chains or raw rules reported",&[("inspectionIssues",json!(issues))]));
    if let Some(e) = fatal {
        outcome = error(outcome, e)
    }
    context(outcome, env)
}
