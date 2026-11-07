use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    platform::{
        command::{CommandRunner, CommandSpec, SystemRunner},
        AuditPlatform,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Service {
    Active,
    Inactive,
    Failed,
    Unknown,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Antivirus {
    candidate_prevention: Option<bool>,
    candidate_signature_mtime: Option<u64>,
    daemon: Service,
    updater: Service,
    on_access: Service,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Resolver {
    Unknown,
    LoopbackOnly,
    Mixed,
    Other,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum Nss {
    Unknown,
    FilesPresent,
    FilesAbsent,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Filtering {
    hosts_sink_entries: Option<u64>,
    resolver: Resolver,
    nss: Nss,
    candidate_dnsmasq_rules: Option<u64>,
    dnsmasq: Service,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum VpnState {
    Connected,
    AuthRequired,
    Connecting,
    Disconnected,
    Error,
    Unknown,
    Unavailable,
}
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Vpn {
    state: VpnState,
}

pub fn parse_facts(id: &str, text: &str) -> Result<Value, String> {
    fn decode<T: serde::de::DeserializeOwned + Serialize>(text: &str) -> Result<Value, String> {
        let data: T = serde_json::from_str(text).map_err(|_| "Invalid collector output")?;
        serde_json::to_value(data).map_err(|_| "Invalid collector output".into())
    }
    if text.len() > 8192 {
        return Err("Collector output exceeds limit".into());
    }
    match id {
        "SEC-003" => decode::<Antivirus>(text),
        "SEC-004" => decode::<Filtering>(text),
        "SEC-011" => decode::<Vpn>(text),
        _ => Err("Unknown script ID".into()),
    }
}
fn inconclusive(reason: Reason, message: &str) -> Outcome {
    Outcome::new(Status::Warn, reason, message)
}
pub fn collect_script(id: &str, runner: &dyn CommandRunner) -> Outcome {
    let source = match id {
        "SEC-003" => include_str!("../../../../scripts/audit/SEC-003.sh"),
        "SEC-004" => include_str!("../../../../scripts/audit/SEC-004.sh"),
        "SEC-011" => include_str!("../../../../scripts/audit/SEC-011.sh"),
        _ => return inconclusive(Reason::InvalidOutput, "Unknown shipped script ID"),
    };
    let mut spec = CommandSpec::new("/usr/bin/bash", &["--noprofile", "--norc", "-c", source]);
    spec.read_only_filesystem = true;
    spec.timeout = Duration::from_secs(10);
    spec.output_limit = 8192;
    let output = match runner.run(&spec) {
        Ok(out) => out,
        Err(error) => {
            return inconclusive(
                error.reason,
                "Guarded collector unavailable; no unsafe retry",
            )
        }
    };
    if output.code != Some(0) || !output.stderr.is_empty() {
        return inconclusive(
            Reason::EvidenceUnavailable,
            "Collector failed or emitted diagnostics; raw output discarded",
        );
    }
    match parse_facts(id, &output.stdout) {
        Ok(facts) => inconclusive(Reason::EvidenceInconclusive, match id {
            "SEC-003" => "ClamAV service indicators only: signatures, scan coverage and prevention unverified",
            "SEC-004" => "Hosts and dnsmasq candidate indicators only: loaded lists, NSS precedence, DoH, VPN and enterprise enforcement unverified",
            _ => "Cato-reported state only: tunnel reachability, routing and corporate filtering unverified",
        }).with_evidence(Evidence::new("shipped embedded Bash collector v1", "local configuration/status indicators; not enforcement", &[
            ("facts", facts), ("enforcementVerified", json!(false)), ("atomicSnapshot", json!(false)),
        ])),
        Err(_) => inconclusive(Reason::InvalidOutput, "Unexpected collector format; raw output discarded"),
    }
}
pub(super) fn native_script(platform: &dyn AuditPlatform, id: &str) -> Outcome {
    if !platform.operating_system().is_ok_and(|os| os.supported) {
        return inconclusive(
            Reason::UnsupportedPlatform,
            "Shipped scripts target native Arch/Fedora only",
        );
    }
    #[cfg(target_os = "linux")]
    {
        use crate::platform::linux::environment::{self, Kind, SystemSignals};
        let env = environment::detect(&SystemRunner, &SystemSignals);
        if env.kind != Kind::NativeHost {
            return inconclusive(
                Reason::EvidenceUnavailable,
                "Native host not established; scripts skipped",
            );
        }
        collect_script(id, &SystemRunner)
    }
    #[cfg(not(target_os = "linux"))]
    inconclusive(
        Reason::UnsupportedPlatform,
        "No script runtime for this platform",
    )
}
