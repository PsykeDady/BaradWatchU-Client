//! Platform-neutral, versioned observations. No OS commands or server dependency.
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, time::SystemTime};

pub const REPORT_SCHEMA: &str = "baradwatchu.audit-report.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Status {
    Pass,
    Fail,
    Warn,
    Error,
    NotApplicable,
}

impl std::fmt::Display for Status {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::NotApplicable => "NOT_APPLICABLE",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Reason {
    OsIdentified,
    UnsupportedPlatform,
    OsIdentityUnavailable,
    MissingOsRelease,
    InvalidOsRelease,
    MissingTool,
    ReadOnlyGuardUnavailable,
    PermissionDenied,
    ExecutionFailed,
    Timeout,
    OutputLimit,
    InvalidOutput,
    CacheUnavailable,
    NoCachedUpdates,
    UpdatesAvailable,
    NoEnabledRepositories,
    RootEncrypted,
    RootUnencrypted,
    EncryptionInconclusive,
    UpdateScopeInconclusive,
    SecurityStateObserved,
    EvidenceInconclusive,
    EvidenceUnavailable,
    HeadlessSession,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    pub source: String,
    pub scope: String,
    pub values: BTreeMap<String, Value>,
}

impl Evidence {
    pub fn new(source: &str, scope: &str, values: &[(&str, Value)]) -> Self {
        Self {
            source: source.to_owned(),
            scope: scope.to_owned(),
            values: values
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Outcome {
    pub status: Status,
    pub reason_code: Reason,
    pub message: String,
    pub evidence: Vec<Evidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observation: Option<crate::observation::Observation>,
}

impl Outcome {
    pub fn new(status: Status, reason_code: Reason, message: impl Into<String>) -> Self {
        Self {
            status,
            reason_code,
            message: message.into(),
            evidence: vec![],
            observation: None,
        }
    }
    pub fn with_evidence(mut self, evidence: Evidence) -> Self {
        self.evidence.push(evidence);
        self
    }
    pub fn with_observation(mut self, observation: crate::observation::Observation) -> Self {
        self.observation = Some(observation);
        self
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OperatingSystem {
    pub family: String,
    pub architecture: String,
    pub distribution_id: Option<String>,
    pub name: Option<String>,
    pub version_id: Option<String>,
    pub variant_id: Option<String>,
    pub identity_source: Option<String>,
    pub supported: bool,
    pub support_reason: String,
}

impl OperatingSystem {
    pub fn unidentified(family: &str) -> Self {
        Self {
            family: family.to_owned(),
            architecture: std::env::consts::ARCH.to_owned(),
            distribution_id: None,
            name: None,
            version_id: None,
            variant_id: None,
            identity_source: None,
            supported: false,
            support_reason: "OS identity unavailable or outside the Fedora RPM/DNF5 baseline"
                .to_owned(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckMetadata {
    pub id: String,
    pub name: String,
    pub description: String,
    pub version: String,
}

pub trait Check {
    fn metadata(&self) -> CheckMetadata;
    fn evaluate(&self) -> Outcome;
}

pub trait Clock {
    fn now_unix_ms(&self) -> Result<u64, String>;
}

pub struct SystemClock;
impl Clock for SystemClock {
    fn now_unix_ms(&self) -> Result<u64, String> {
        let duration = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|_| "System clock predates the Unix epoch".to_owned())?;
        duration
            .as_millis()
            .try_into()
            .map_err(|_| "Timestamp overflow".to_owned())
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckResult {
    pub check: CheckMetadata,
    pub observed_at_unix_ms: u64,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Summary {
    pub total: usize,
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub error: usize,
    pub not_applicable: usize,
}

impl Summary {
    pub fn from_results(results: &[CheckResult]) -> Self {
        let mut summary = Self {
            total: results.len(),
            ..Self::default()
        };
        for result in results {
            match result.outcome.status {
                Status::Pass => summary.pass += 1,
                Status::Fail => summary.fail += 1,
                Status::Warn => summary.warn += 1,
                Status::Error => summary.error += 1,
                Status::NotApplicable => summary.not_applicable += 1,
            }
        }
        summary
    }
    pub fn overall(&self, supported: bool) -> Status {
        if self.error > 0 {
            Status::Error
        } else if self.fail > 0 {
            Status::Fail
        } else if self.warn > 0 || !supported || self.pass == 0 || self.not_applicable > 0 {
            Status::Warn
        } else {
            Status::Pass
        }
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub schema_version: String,
    pub agent_version: String,
    pub started_at_unix_ms: u64,
    pub completed_at_unix_ms: u64,
    pub operating_system: OperatingSystem,
    pub overall: Status,
    pub summary: Summary,
    pub results: Vec<CheckResult>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy_evaluation: Option<crate::policy::PolicyEvaluation>,
}

impl AuditReport {
    /// CLI codes: execution error 1, usage 2, noncompliance 3, incomplete 4.
    pub fn exit_code(&self) -> u8 {
        match self
            .policy_evaluation
            .as_ref()
            .map_or(self.overall, |evaluation| evaluation.overall)
        {
            Status::Pass => 0,
            Status::Error => 1,
            Status::Fail => 3,
            Status::Warn | Status::NotApplicable => 4,
        }
    }
    pub fn human_readable(&self) -> String {
        use std::fmt::Write;
        let mut text = format!(
            "BaradWatchU Client {} — standalone audit\nOS: {} {} ({})\nScope: {}\n",
            self.agent_version,
            self.operating_system
                .distribution_id
                .as_deref()
                .unwrap_or(&self.operating_system.family),
            self.operating_system
                .version_id
                .as_deref()
                .unwrap_or("version unavailable"),
            self.operating_system.architecture,
            self.operating_system.support_reason
        );
        for result in &self.results {
            let _ = writeln!(
                text,
                "[{}] {} — {}\n  {}\n  Observed at: {} ms since Unix epoch",
                result.outcome.status,
                result.check.id,
                result.check.name,
                result.outcome.message,
                result.observed_at_unix_ms
            );
            for evidence in &result.outcome.evidence {
                let _ = writeln!(
                    text,
                    "  Evidence: {} [{}] {}",
                    evidence.source,
                    evidence.scope,
                    serde_json::to_string(&evidence.values).unwrap_or_default()
                );
            }
        }
        let s = &self.summary;
        let _ = writeln!(
            text,
            "Overall: {} | total={} PASS={} FAIL={} WARN={} ERROR={} NOT_APPLICABLE={}",
            self.overall, s.total, s.pass, s.fail, s.warn, s.error, s.not_applicable
        );
        if let Some(evaluation) = &self.policy_evaluation {
            let _ = writeln!(
                text,
                "Policy {}: {} (mandatory checks determine compliance)",
                evaluation.policy.id, evaluation.overall
            );
            for check in &evaluation.checks {
                let _ = writeln!(
                    text,
                    "  {} {} [{}]: {} — {}",
                    check.check_id,
                    if check.mandatory {
                        "mandatory"
                    } else {
                        "informational"
                    },
                    if check.enabled { "enabled" } else { "disabled" },
                    check
                        .status
                        .map_or_else(|| "DISABLED".to_owned(), |status| status.to_string()),
                    check.reasons.join(", ")
                );
            }
            if !evaluation.context_reasons.is_empty() {
                let _ = writeln!(text, "  Context: {}", evaluation.context_reasons.join(", "));
            }
        }
        text
    }
}

pub fn run(
    os: OperatingSystem,
    checks: &[&dyn Check],
    clock: &dyn Clock,
) -> Result<AuditReport, String> {
    let started_at_unix_ms = clock.now_unix_ms()?;
    let mut results = Vec::with_capacity(checks.len());
    for check in checks {
        results.push(CheckResult {
            check: check.metadata(),
            observed_at_unix_ms: clock.now_unix_ms()?,
            outcome: check.evaluate(),
        });
    }
    let summary = Summary::from_results(&results);
    let overall = summary.overall(os.supported);
    Ok(AuditReport {
        schema_version: REPORT_SCHEMA.to_owned(),
        agent_version: env!("CARGO_PKG_VERSION").to_owned(),
        started_at_unix_ms,
        completed_at_unix_ms: clock.now_unix_ms()?,
        operating_system: os,
        overall,
        summary,
        results,
        policy_evaluation: None,
    })
}
