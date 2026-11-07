//! Common native-probe failures, without package-manager-specific assumptions.
use super::command::{CommandOutput, ProbeError};
use crate::audit::{Evidence, Outcome, Reason, Status};
use serde_json::json;

pub(crate) fn failure(error: ProbeError, source: &str, scope: &str) -> Outcome {
    Outcome::new(Status::Error, error.reason, error.message).with_evidence(Evidence::new(
        source,
        scope,
        &[("privileges", json!("caller; no elevation"))],
    ))
}
pub(crate) fn unsuccessful(output: &CommandOutput, source: &str, scope: &str) -> Outcome {
    let message = output.stderr.to_ascii_lowercase();
    let reason = if message.contains("permission denied")
        || message.contains("operation not permitted")
        || message.contains("superuser")
    {
        Reason::PermissionDenied
    } else {
        Reason::ExecutionFailed
    };
    failure(
        ProbeError::new(
            reason,
            "Inspection command failed; no compliance conclusion",
        ),
        source,
        scope,
    )
    .with_evidence(Evidence::new(
        source,
        scope,
        &[("exitCode", json!(output.code))],
    ))
}
