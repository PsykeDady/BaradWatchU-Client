//! Shared unprivileged Linux security observations. No policy thresholds or mutating operations.
pub mod credential_sources;
pub mod files;
pub mod firewall;
pub mod firmware;
pub mod password_aging;
pub mod password_pam;
pub mod password_quality;
pub mod screen_lock;
use super::environment::{Environment, Kind};
use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    observation::{Observation, Quality},
    platform::command::{CommandRunner, CommandSpec, ProbeError},
};
use serde_json::json;
use std::time::Duration;

pub fn guarded(program: &str, args: &[&str]) -> CommandSpec {
    let mut spec = CommandSpec::new(program, args);
    spec.read_only_filesystem = true;
    spec.timeout = Duration::from_secs(5);
    spec
}
pub fn query(
    runner: &dyn CommandRunner,
    program: &str,
    args: &[&str],
) -> Result<String, ProbeError> {
    let output = runner.run(&guarded(program, args))?;
    if output.code == Some(0) && output.stderr.trim().is_empty() {
        return Ok(output.stdout);
    }
    let diagnostic = output.stderr.to_ascii_lowercase();
    Err(ProbeError::new(
        if diagnostic.contains("permission denied")
            || diagnostic.contains("operation not permitted")
            || diagnostic.contains("access denied")
            || diagnostic.contains("accessdenied")
        {
            Reason::PermissionDenied
        } else {
            Reason::ExecutionFailed
        },
        "Read-only inspection query failed; raw diagnostics omitted",
    ))
}
pub fn observed(
    observation: Observation,
    quality: Quality,
    positive: Option<bool>,
    source: &str,
    scope: &str,
    message: &str,
) -> Outcome {
    let status = match quality {
        Quality::Verified => match positive {
            Some(true) => Status::Pass,
            Some(false) => Status::Fail,
            None => Status::Warn,
        },
        Quality::NotApplicable => Status::NotApplicable,
        _ => Status::Warn,
    };
    Outcome::new(
        status,
        match quality {
            Quality::Verified => Reason::SecurityStateObserved,
            Quality::Missing => Reason::EvidenceUnavailable,
            Quality::NotApplicable => Reason::HeadlessSession,
            _ => Reason::EvidenceInconclusive,
        },
        message,
    )
    .with_evidence(Evidence::new(
        source,
        scope,
        &[
            ("quality", json!(quality)),
            ("privileges", json!("caller; no elevation")),
        ],
    ))
    .with_observation(observation)
}
pub fn error(mut outcome: Outcome, error: ProbeError) -> Outcome {
    outcome.status = Status::Error;
    outcome.reason_code = error.reason;
    outcome.message = error.message;
    outcome
}
pub fn context(mut outcome: Outcome, env: &Environment) -> Outcome {
    if !host(env) {
        // No hardware/rule/session source was consulted. Do not advertise an
        // expected probe source as evidence when only context was observed.
        outcome.evidence.clear();
    }
    outcome.with_evidence(Evidence::new(
        "Existing Linux execution-environment assessment",
        "scope only; not host attestation",
        &[
            ("executionEnvironment", json!(env.kind)),
            ("environmentReason", json!(env.reason)),
            ("environmentProbeError", json!(env.probe_error)),
            ("hostProbesSkipped", json!(!host(env))),
        ],
    ))
}
pub fn host(env: &Environment) -> bool {
    env.kind == Kind::NativeHost
}
