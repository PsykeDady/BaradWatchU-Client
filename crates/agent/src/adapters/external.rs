//! Explicit executable + argv; no language detection, implicit shell or policy commands.
use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    check_port::{Availability, CheckEvidence, ExecutionState},
    observation::{BootState, Observation, Quality, SecureBoot},
    platform::command::{CommandRunner, CommandSpec},
};
use serde::Deserialize;
use serde_json::json;
use std::{path::PathBuf, time::Duration};

/// Constructed ONLY by trusted installation/compiled registry code, never deserialized.
pub struct ExternalSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub timeout: Duration,
    pub output_limit: usize,
}
#[derive(Debug, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
enum State {
    Available,
    Unknown,
    NotApplicable,
    Error,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Document {
    schema_version: String,
    check_id: String,
    availability: State,
    data: Option<Data>,
}
#[derive(Debug, Deserialize)]
#[serde(
    tag = "kind",
    content = "values",
    deny_unknown_fields,
    rename_all = "SCREAMING_SNAKE_CASE"
)]
enum Data {
    VpnIndicators(Vpn),
    SecureBoot(Boot),
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Vpn {
    state: VpnState,
}
#[derive(Debug, Deserialize, serde::Serialize)]
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
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Boot {
    state: BootState,
    secure_boot: Option<bool>,
    setup_mode: Option<bool>,
}

pub fn unavailable(execution: ExecutionState, reason: Reason) -> CheckEvidence {
    CheckEvidence {
        execution,
        availability: Availability::Unknown,
        outcome: Outcome::new(
            Status::Warn,
            reason,
            "Registered adapter did not provide usable evidence; diagnostics discarded",
        ),
    }
}
pub fn parse(id: &str, text: &str) -> Result<CheckEvidence, &'static str> {
    let doc: Document = serde_json::from_str(text).map_err(|_| "Malformed evidence document")?;
    if doc.schema_version != "baradwatchu.check-evidence.v1" || doc.check_id != id {
        return Err("Evidence identity/schema mismatch");
    }
    let availability = match doc.availability {
        State::Available => Availability::Available,
        State::Unknown => Availability::Unknown,
        State::NotApplicable => Availability::NotApplicable,
        State::Error => Availability::Error,
    };
    let mut outcome = Outcome::new(
        Status::Warn,
        Reason::EvidenceInconclusive,
        "Adapter evidence collected; compliance is evaluated separately",
    );
    match (availability, doc.data) {
        (Availability::Available, Some(Data::VpnIndicators(vpn))) if id == "SEC-011" => {
            outcome = outcome.with_evidence(Evidence::new(
                "registered local adapter",
                "client-reported VPN state; not reachability or enforcement",
                &[
                    ("facts", json!({"state":vpn.state})),
                    ("enforcementVerified", json!(false)),
                ],
            ));
        }
        (Availability::Available, Some(Data::SecureBoot(boot))) if id == "SEC-013" => {
            outcome.observation = Some(Observation::SecureBoot(SecureBoot {
                quality: Quality::Verified,
                state: boot.state,
                secure_boot: boot.secure_boot,
                setup_mode: boot.setup_mode,
            }));
        }
        (Availability::Available, _) => {
            return Err("Available evidence must match registered ID contract")
        }
        (_, Some(_)) => return Err("Unavailable evidence must not carry facts"),
        (Availability::Error, None) => {
            outcome = Outcome::new(
                Status::Error,
                Reason::EvidenceUnavailable,
                "Adapter reported an evidence collection error",
            )
        }
        (Availability::NotApplicable, None) => {
            outcome = Outcome::new(
                Status::NotApplicable,
                Reason::UnsupportedPlatform,
                "Adapter reported check not applicable",
            )
        }
        _ => {}
    }
    Ok(CheckEvidence {
        execution: ExecutionState::Completed,
        availability,
        outcome,
    })
}
pub fn execute(id: &str, spec: &ExternalSpec, runner: &dyn CommandRunner) -> CheckEvidence {
    if !spec.program.is_absolute()
        || spec.timeout.is_zero()
        || spec.timeout > Duration::from_secs(60)
        || !(256..=262144).contains(&spec.output_limit)
    {
        return unavailable(ExecutionState::NotStarted, Reason::InvalidOutput);
    }
    let mut cmd = CommandSpec::new("", &[]);
    cmd.program = spec.program.clone();
    cmd.args = spec.args.clone();
    cmd.args.extend([
        "--check-id".into(),
        id.into(),
        "--schema".into(),
        "baradwatchu.check-evidence.v1".into(),
    ]);
    cmd.timeout = spec.timeout;
    cmd.output_limit = spec.output_limit;
    // Current installed registrations are Linux-only. Fail closed if the existing
    // guard is unavailable; do not invent a cross-platform sandbox or unsafe retry.
    cmd.read_only_filesystem = true;
    match runner.run(&cmd) {
        Err(e) => unavailable(
            match e.reason {
                Reason::MissingTool => ExecutionState::MissingExecutable,
                Reason::Timeout => ExecutionState::Timeout,
                Reason::OutputLimit => ExecutionState::OutputLimit,
                Reason::ReadOnlyGuardUnavailable => ExecutionState::NotStarted,
                _ => ExecutionState::Failed,
            },
            e.reason,
        ),
        Ok(out) if out.code != Some(0) => {
            unavailable(ExecutionState::UnexpectedExit, Reason::ExecutionFailed)
        }
        Ok(out) => {
            // stderr is bounded by runner but never persisted, echoed or parsed.
            if out.stdout.len() > spec.output_limit || out.stderr.len() > spec.output_limit {
                return unavailable(ExecutionState::OutputLimit, Reason::OutputLimit);
            }
            parse(id, &out.stdout).unwrap_or_else(|_| {
                unavailable(ExecutionState::InvalidEvidence, Reason::InvalidOutput)
            })
        }
    }
}
