//! Technology-neutral application port. Legacy Outcome remains an observation view,
//! not a policy decision; external adapters cannot supply its PASS/FAIL fields.
use crate::audit::Outcome;
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ExecutionState {
    Completed,
    NotStarted,
    MissingExecutable,
    Timeout,
    OutputLimit,
    InvalidEvidence,
    UnexpectedExit,
    Failed,
}
#[derive(Clone, Copy, Debug, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Availability {
    Available,
    Unknown,
    NotApplicable,
    Error,
}
#[derive(Clone, Debug)]
pub struct CheckEvidence {
    pub execution: ExecutionState,
    pub availability: Availability,
    pub outcome: Outcome,
}
pub trait CheckExecutor {
    fn execute(&self, check_id: &str) -> CheckEvidence;
    /// Provenance only; compliance must never branch on this value.
    fn implementation(&self, _check_id: &str) -> &'static str {
        "REGISTERED_ADAPTER"
    }
}
