//! Strict local policy and pure evaluation. Never mutates observations or invokes probes.
use crate::{audit::{AuditReport, Status}, observation::{MetadataState, Observation, UpdateClass}};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path};

pub const POLICY_SCHEMA: &str = "baradwatchu.audit-policy.v1";
pub const EVALUATION_SCHEMA: &str = "baradwatchu.policy-evaluation.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Uncertain { Warn, Fail, Error }
impl Uncertain {
    fn status(self) -> Status { match self { Self::Warn => Status::Warn, Self::Fail => Status::Fail, Self::Error => Status::Error } }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct EvidencePolicy {
    pub missing: Uncertain,
    pub stale: Uncertain,
    pub inconclusive: Uncertain,
    pub unsupported: Uncertain,
}
impl Default for EvidencePolicy {
    fn default() -> Self { Self { missing: Uncertain::Warn, stale: Uncertain::Warn, inconclusive: Uncertain::Warn, unsupported: Uncertain::Warn } }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PendingAction { Fail, Warn, Allow }
impl PendingAction {
    fn status(self) -> Status { match self { Self::Fail => Status::Fail, Self::Warn => Status::Warn, Self::Allow => Status::Pass } }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EncryptionRequirement { Luks, NotRequired }

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct UpdatePolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub ordinary_updates: PendingAction,
    pub security_updates: PendingAction,
    pub max_metadata_age_seconds: u32,
}
impl Default for UpdatePolicy {
    fn default() -> Self {
        Self { enabled: true, mandatory: true, evidence: EvidencePolicy::default(), ordinary_updates: PendingAction::Fail,
            security_updates: PendingAction::Fail, max_metadata_age_seconds: 86400 }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct EncryptionPolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub requirement: EncryptionRequirement,
}
impl Default for EncryptionPolicy {
    fn default() -> Self { Self { enabled: true, mandatory: true, evidence: EvidencePolicy::default(), requirement: EncryptionRequirement::Luks } }
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Checks {
    #[serde(rename = "SEC-001")]
    pub updates: UpdatePolicy,
    #[serde(rename = "SEC-006")]
    pub encryption: EncryptionPolicy,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct Policy {
    pub schema_version: String,
    #[serde(default = "default_id")]
    pub id: String,
    #[serde(default)]
    pub checks: Checks,
}
fn default_id() -> String { "local-default".to_owned() }
impl Default for Policy {
    fn default() -> Self { Self { schema_version: POLICY_SCHEMA.to_owned(), id: default_id(), checks: Checks::default() } }
}
impl Policy {
    pub fn from_json(text: &str) -> Result<Self, String> {
        let policy: Self = serde_json::from_str(text).map_err(|error| format!("Invalid policy JSON: {error}"))?;
        policy.validate()?;
        Ok(policy)
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|error| format!("Cannot read policy {}: {error}", path.display()))?;
        if !file.metadata().map_err(|error| error.to_string())?.is_file() { return Err("Policy must be a regular JSON file".to_owned()); }
        let mut text = String::new();
        file.take(65537).read_to_string(&mut text).map_err(|error| format!("Cannot read policy: {error}"))?;
        if text.len() > 65536 { return Err("Policy exceeds 64 KiB".to_owned()); }
        Self::from_json(&text)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != POLICY_SCHEMA { return Err(format!("Unsupported policy schemaVersion; expected {POLICY_SCHEMA}")); }
        if self.id.is_empty() || self.id.len() > 128 || !self.id.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)) {
            return Err("Policy id must contain 1..128 ASCII letters/digits/._-".to_owned());
        }
        if self.checks.updates.max_metadata_age_seconds == 0 { return Err("maxMetadataAgeSeconds must be positive".to_owned()); }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Evaluation {
    pub check_id: String,
    pub enabled: bool,
    pub mandatory: bool,
    /// None means DISABLED, never PASS. Raw results omit unexecuted probes.
    pub status: Option<Status>,
    pub reasons: Vec<String>,
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EvaluationSummary {
    pub enabled: usize, pub disabled: usize, pub mandatory: usize, pub informational: usize,
    pub pass: usize, pub fail: usize, pub warn: usize, pub error: usize,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEvaluation {
    pub schema_version: String,
    pub policy: Policy,
    pub overall: Status,
    pub summary: EvaluationSummary,
    pub checks: Vec<Evaluation>,
    pub context_reasons: Vec<String>,
}
fn severity(status: Status) -> u8 {
    match status { Status::Error => 4, Status::Fail => 3, Status::Warn | Status::NotApplicable => 2, Status::Pass => 1 }
}
fn add(status: &mut Status, reasons: &mut Vec<String>, candidate: Status, reason: &str) {
    if severity(candidate) > severity(*status) { *status = candidate; }
    reasons.push(reason.to_owned());
}

/// A validated policy + borrowed report produce a separate assessment; no OS access.
pub fn evaluate(policy: &Policy, report: &AuditReport) -> Result<PolicyEvaluation, String> {
    policy.validate()?;
    let settings = [ ("SEC-001", policy.checks.updates.enabled, policy.checks.updates.mandatory, &policy.checks.updates.evidence),
        ("SEC-006", policy.checks.encryption.enabled, policy.checks.encryption.mandatory, &policy.checks.encryption.evidence) ];
    let mut checks = Vec::new();
    let mut summary = EvaluationSummary::default();
    let mut overall = Status::Pass;
    for (id, enabled, mandatory, evidence) in settings {
        let mut evaluation = Evaluation { check_id: id.to_owned(), enabled, mandatory, status: None, reasons: vec![] };
        if !enabled { summary.disabled += 1; evaluation.reasons.push("DISABLED_BY_POLICY".to_owned()); checks.push(evaluation); continue; }
        summary.enabled += 1;
        if mandatory { summary.mandatory += 1; } else { summary.informational += 1; }
        let matches: Vec<_> = report.results.iter().filter(|result| result.check.id == id).collect();
        let (status, reasons) = if matches.len() > 1 {
            (Status::Error, vec!["AMBIGUOUS_OBSERVATIONS".to_owned()])
        } else if let Some(result) = matches.first() {
            assess(id, &result.outcome, policy, evidence, report.completed_at_unix_ms / 1000)
        } else { (evidence.missing.status(), vec!["MISSING_OBSERVATION".to_owned()]) };
        evaluation.status = Some(status);
        evaluation.reasons = reasons;
        match status { Status::Pass => summary.pass += 1, Status::Fail => summary.fail += 1,
            Status::Error => summary.error += 1, Status::Warn | Status::NotApplicable => summary.warn += 1 }
        if mandatory && severity(status) > severity(overall) { overall = status; }
        checks.push(evaluation);
    }
    let mut context_reasons = vec![];
    if report.results.iter().any(|r| r.check.id == "SYS-OS-001" && r.outcome.status == Status::Error) {
        add(&mut overall, &mut context_reasons, Status::Error, "OS_IDENTITY_ERROR");
    }
    if !report.operating_system.supported { add(&mut overall, &mut context_reasons, Status::Warn, "UNSUPPORTED_PLATFORM"); }
    if summary.mandatory == 0 { add(&mut overall, &mut context_reasons, Status::Warn, "NO_ENABLED_MANDATORY_CHECKS"); }
    Ok(PolicyEvaluation { schema_version: EVALUATION_SCHEMA.to_owned(), policy: policy.clone(), overall, summary, checks, context_reasons })
}

fn assess(id: &str, outcome: &crate::audit::Outcome, policy: &Policy, evidence: &EvidencePolicy, now: u64) -> (Status, Vec<String>) {
    if outcome.status == Status::Error { return (Status::Error, vec![format!("PROBE_ERROR:{:?}", outcome.reason_code)]); }
    if outcome.status == Status::NotApplicable { return (evidence.unsupported.status(), vec!["UNSUPPORTED_EVIDENCE".to_owned()]); }
    let Some(observation) = &outcome.observation else { return (evidence.missing.status(), vec!["MISSING_TYPED_OBSERVATION".to_owned()]); };
    let mut status = Status::Pass;
    let mut reasons = Vec::new();
    match (id, observation) {
        ("SEC-001", Observation::Updates(updates)) => {
            if updates.metadata_state == MetadataState::Missing {
                add(&mut status,&mut reasons,evidence.missing.status(),"MISSING_METADATA");
            } else if updates.metadata_state != MetadataState::Available || !updates.coverage_complete || updates.repositories.is_empty() {
                add(&mut status,&mut reasons,evidence.inconclusive.status(),"UNKNOWN_METADATA_COVERAGE");
            } else {
                for repo in &updates.repositories {
                    match (repo.timestamp_unix_seconds, repo.expires_after_seconds) {
                        (Some(timestamp), Some(expires)) if timestamp > 0 && timestamp <= now && expires >= -1 => {
                            let age = now - timestamp;
                            if age > u64::from(policy.checks.updates.max_metadata_age_seconds) || (expires >= 0 && age >= expires as u64) {
                                add(&mut status,&mut reasons,evidence.stale.status(),"STALE_METADATA");
                            }
                        }
                        _ => add(&mut status,&mut reasons,evidence.inconclusive.status(),"UNKNOWN_METADATA_TIMESTAMP"),
                    }
                }
            }
            match updates.classification {
                UpdateClass::NoPending if updates.pending_packages == Some(0) && updates.security_advisories == Some(0) && updates.classification_complete => reasons.push("NO_PENDING_UPDATES_OBSERVED".to_owned()),
                UpdateClass::OrdinaryPending if updates.pending_packages.is_some_and(|n| n > 0) && updates.security_advisories == Some(0) && updates.ordinary_pending == Some(true) && updates.classification_complete =>
                    add(&mut status,&mut reasons,policy.checks.updates.ordinary_updates.status(),"ORDINARY_UPDATES_PENDING"),
                UpdateClass::SecurityPending if updates.pending_packages.is_some_and(|n| n > 0) && updates.security_advisories.is_some_and(|n| n > 0) => {
                    add(&mut status,&mut reasons,policy.checks.updates.security_updates.status(),"SECURITY_UPDATES_PENDING");
                    // Other pending packages may also be ordinary; do not ignore their configured rule.
                    if updates.ordinary_pending == Some(true) {
                        add(&mut status,&mut reasons,policy.checks.updates.ordinary_updates.status(),"ORDINARY_UPDATES_PENDING");
                    }
                    if !updates.classification_complete { add(&mut status,&mut reasons,evidence.inconclusive.status(),"INCOMPLETE_SECURITY_CLASSIFICATION"); }
                }
                UpdateClass::UnknownSecurity => {
                    add(&mut status,&mut reasons,evidence.inconclusive.status(),"UNKNOWN_SECURITY_CLASSIFICATION");
                    if policy.checks.updates.ordinary_updates == PendingAction::Fail && policy.checks.updates.security_updates == PendingAction::Fail {
                        add(&mut status,&mut reasons,Status::Fail,"ANY_PENDING_UPDATES_DISALLOWED");
                    }
                }
                UpdateClass::Unknown => add(&mut status,&mut reasons,evidence.inconclusive.status(),"UNKNOWN_UPDATE_AVAILABILITY"),
                _ => add(&mut status,&mut reasons,Status::Error,"INCONSISTENT_UPDATE_OBSERVATION"),
            }
        }
        ("SEC-006", Observation::RootEncryption(root)) => {
            if !root.topology_complete || root.paths.is_empty() {
                add(&mut status,&mut reasons,evidence.inconclusive.status(),"INCOMPLETE_ROOT_TOPOLOGY");
            } else if root.paths.iter().any(|path| path.devices.is_empty()) {
                add(&mut status,&mut reasons,Status::Error,"INCONSISTENT_ROOT_OBSERVATION");
            } else if policy.checks.encryption.requirement == EncryptionRequirement::NotRequired {
                reasons.push("ROOT_ENCRYPTION_EXPLICITLY_NOT_REQUIRED".to_owned());
            } else if root.paths.iter().all(|path| path.luks_protected) {
                reasons.push("ALL_ROOT_BACKING_PATHS_LUKS_PROTECTED".to_owned());
            } else { add(&mut status,&mut reasons,Status::Fail,"UNENCRYPTED_ROOT_BACKING_PATH"); }
        }
        _ => add(&mut status,&mut reasons,Status::Error,"OBSERVATION_TYPE_MISMATCH"),
    }
    reasons.sort(); reasons.dedup();
    (status, reasons)
}
