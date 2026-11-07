//! Strict local policy and pure evaluation. Never mutates observations or invokes probes.
use crate::{
    audit::{AuditReport, Status},
    observation::{MetadataState, Observation, UpdateClass},
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path};
mod credentials;
pub use credentials::{AgingPolicy, ComplexityPolicy, WarningPolicy};

pub const POLICY_SCHEMA: &str = "baradwatchu.audit-policy.v1";
pub const POLICY_SCHEMA_V2: &str = "baradwatchu.audit-policy.v2";
pub const POLICY_SCHEMA_V3: &str = "baradwatchu.audit-policy.v3";
pub const EVALUATION_SCHEMA: &str = "baradwatchu.policy-evaluation.v1";

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Uncertain {
    Warn,
    Fail,
    Error,
}
impl Uncertain {
    fn status(self) -> Status {
        match self {
            Self::Warn => Status::Warn,
            Self::Fail => Status::Fail,
            Self::Error => Status::Error,
        }
    }
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
    fn default() -> Self {
        Self {
            missing: Uncertain::Warn,
            stale: Uncertain::Warn,
            inconclusive: Uncertain::Warn,
            unsupported: Uncertain::Warn,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PendingAction {
    Fail,
    Warn,
    Allow,
}
impl PendingAction {
    fn status(self) -> Status {
        match self {
            Self::Fail => Status::Fail,
            Self::Warn => Status::Warn,
            Self::Allow => Status::Pass,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EncryptionRequirement {
    Luks,
    NotRequired,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct UpdatePolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub ordinary_updates: PendingAction,
    pub security_updates: PendingAction,
    pub max_metadata_age_seconds: u32,
    pub max_observation_age_seconds: u32,
}
impl Default for UpdatePolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mandatory: true,
            evidence: EvidencePolicy::default(),
            ordinary_updates: PendingAction::Fail,
            security_updates: PendingAction::Fail,
            max_metadata_age_seconds: 86400,
            max_observation_age_seconds: 300,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct EncryptionPolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub requirement: EncryptionRequirement,
    pub max_observation_age_seconds: u32,
}
impl Default for EncryptionPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mandatory: true,
            evidence: EvidencePolicy::default(),
            requirement: EncryptionRequirement::Luks,
            max_observation_age_seconds: 300,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct ControlPolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub required: bool,
    pub max_observation_age_seconds: u32,
}
impl Default for ControlPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mandatory: true,
            evidence: EvidencePolicy::default(),
            required: true,
            max_observation_age_seconds: 300,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct ScreenPolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub required: bool,
    pub max_observation_age_seconds: u32,
    pub max_timeout_seconds: u32,
    pub require_lock_on_resume: bool,
    /// Additive v2 criterion; omission/false retains the original policy semantics.
    #[serde(skip_serializing_if = "is_false")]
    pub require_immediate_password: bool,
}
fn is_false(value: &bool) -> bool {
    !value
}
impl Default for ScreenPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mandatory: true,
            evidence: EvidencePolicy::default(),
            required: true,
            max_observation_age_seconds: 300,
            max_timeout_seconds: 300,
            require_lock_on_resume: false,
            require_immediate_password: false,
        }
    }
}
fn control_present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<ControlPolicy>, D::Error> {
    ControlPolicy::deserialize(d).map(Some)
}
fn screen_present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<ScreenPolicy>, D::Error> {
    ScreenPolicy::deserialize(d).map(Some)
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SensitiveTarget {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SensitivePolicy {
    #[serde(default = "bool_true")]
    pub enabled: bool,
    #[serde(default = "bool_true")]
    pub mandatory: bool,
    #[serde(default)]
    pub evidence: EvidencePolicy,
    #[serde(default = "default_age")]
    pub max_observation_age_seconds: u32,
    #[serde(default)]
    pub targets: Vec<SensitiveTarget>,
}
fn bool_true() -> bool {
    true
}
fn default_age() -> u32 {
    300
}
pub(crate) fn validate_targets(targets: &[SensitiveTarget]) -> Result<(), String> {
    let mut ids = std::collections::BTreeSet::new();
    if targets.len() > 32 {
        return Err("At most 32 sensitive targets are allowed".into());
    }
    for target in targets {
        let valid_id = !target.id.is_empty()
            && target.id.len() <= 64
            && target
                .id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c));
        let valid_path = target.path.as_deref().is_some_and(|s| {
            !s.is_empty()
                && s.len() <= 4096
                && !s.chars().any(char::is_control)
                && Path::new(s).is_absolute()
                && Path::new(s).components().all(|c| {
                    !matches!(
                        c,
                        std::path::Component::ParentDir | std::path::Component::CurDir
                    )
                })
        });
        if !valid_id || !ids.insert(&target.id) || !valid_path {
            return Err("Invalid sensitive target id or absolute path".into());
        }
    }
    Ok(())
}
fn sensitive_present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<SensitivePolicy>, D::Error> {
    SensitivePolicy::deserialize(d).map(Some)
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct Checks {
    #[serde(
        rename = "SEC-008",
        default,
        deserialize_with = "credentials::aging_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_aging: Option<AgingPolicy>,
    #[serde(
        rename = "SEC-009",
        default,
        deserialize_with = "credentials::warning_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_warning: Option<WarningPolicy>,
    #[serde(
        rename = "SEC-010",
        default,
        deserialize_with = "credentials::complexity_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub password_complexity: Option<ComplexityPolicy>,
    #[serde(rename = "SEC-001")]
    pub updates: UpdatePolicy,
    #[serde(rename = "SEC-006")]
    pub encryption: EncryptionPolicy,
    #[serde(
        rename = "SEC-007",
        default,
        deserialize_with = "screen_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub screen_lock: Option<ScreenPolicy>,
    #[serde(
        rename = "SEC-012",
        default,
        deserialize_with = "control_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub tpm: Option<ControlPolicy>,
    #[serde(
        rename = "SEC-013",
        default,
        deserialize_with = "control_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub secure_boot: Option<ControlPolicy>,
    #[serde(
        rename = "SEC-014",
        default,
        deserialize_with = "control_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub firewall: Option<ControlPolicy>,
    #[serde(
        rename = "SEC-015",
        default,
        deserialize_with = "control_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub home_encryption: Option<ControlPolicy>,
    #[serde(
        rename = "SEC-016",
        default,
        deserialize_with = "sensitive_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub sensitive_encryption: Option<SensitivePolicy>,
    #[serde(
        rename = "SEC-017",
        default,
        deserialize_with = "control_present",
        skip_serializing_if = "Option::is_none"
    )]
    pub swap_protection: Option<ControlPolicy>,
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
fn default_id() -> String {
    "local-default".to_owned()
}
impl Default for Policy {
    fn default() -> Self {
        Self {
            schema_version: POLICY_SCHEMA.to_owned(),
            id: default_id(),
            checks: Checks::default(),
        }
    }
}
impl Policy {
    pub(crate) fn redacted_for_report(&self) -> Self {
        let mut result = self.clone();
        if let Some(p) = &mut result.checks.sensitive_encryption {
            for target in &mut p.targets {
                target.path = None;
            }
        }
        result
    }
    /// Explicit baseline for the expanded CLI; Default retains legacy v1 semantics.
    pub fn linux_baseline() -> Self {
        let mut p = Self {
            schema_version: POLICY_SCHEMA_V2.to_owned(),
            id: "linux-baseline".into(),
            ..Self::default()
        };
        p.fill_v2();
        p
    }
    fn fill_v2(&mut self) {
        self.checks
            .screen_lock
            .get_or_insert_with(ScreenPolicy::default);
        self.checks.tpm.get_or_insert_with(ControlPolicy::default);
        self.checks
            .secure_boot
            .get_or_insert_with(ControlPolicy::default);
        self.checks
            .firewall
            .get_or_insert_with(ControlPolicy::default);
    }
    pub fn enabled(&self, id: &str) -> bool {
        self.settings().iter().any(|s| s.0 == id && s.1)
    }
    fn settings(&self) -> Vec<(&str, bool, bool, &EvidencePolicy, u32)> {
        let mut s = vec![
            (
                "SEC-001",
                self.checks.updates.enabled,
                self.checks.updates.mandatory,
                &self.checks.updates.evidence,
                self.checks.updates.max_observation_age_seconds,
            ),
            (
                "SEC-006",
                self.checks.encryption.enabled,
                self.checks.encryption.mandatory,
                &self.checks.encryption.evidence,
                self.checks.encryption.max_observation_age_seconds,
            ),
        ];
        if let Some(p) = &self.checks.screen_lock {
            s.push((
                "SEC-007",
                p.enabled,
                p.mandatory,
                &p.evidence,
                p.max_observation_age_seconds,
            ))
        }
        for (id, p) in [
            ("SEC-012", &self.checks.tpm),
            ("SEC-013", &self.checks.secure_boot),
            ("SEC-014", &self.checks.firewall),
            ("SEC-015", &self.checks.home_encryption),
        ] {
            if let Some(p) = p {
                s.push((
                    id,
                    p.enabled,
                    p.mandatory,
                    &p.evidence,
                    p.max_observation_age_seconds,
                ))
            }
        }
        if let Some(p) = &self.checks.sensitive_encryption {
            s.push((
                "SEC-016",
                p.enabled,
                p.mandatory,
                &p.evidence,
                p.max_observation_age_seconds,
            ));
        }
        if let Some(p) = &self.checks.swap_protection {
            s.push((
                "SEC-017",
                p.enabled,
                p.mandatory,
                &p.evidence,
                p.max_observation_age_seconds,
            ));
        }
        if let Some(p) = &self.checks.password_aging {
            s.push((
                "SEC-008",
                p.enabled,
                p.mandatory,
                &p.evidence,
                p.max_observation_age_seconds,
            ));
        }
        if let Some(p) = &self.checks.password_warning {
            s.push((
                "SEC-009",
                p.enabled,
                p.mandatory,
                &p.evidence,
                p.max_observation_age_seconds,
            ));
        }
        if let Some(p) = &self.checks.password_complexity {
            s.push((
                "SEC-010",
                p.enabled,
                p.mandatory,
                &p.evidence,
                p.max_observation_age_seconds,
            ));
        }
        s
    }
    pub fn from_json(text: &str) -> Result<Self, String> {
        let mut policy: Self =
            serde_json::from_str(text).map_err(|error| format!("Invalid policy JSON: {error}"))?;
        if matches!(
            policy.schema_version.as_str(),
            POLICY_SCHEMA_V2 | POLICY_SCHEMA_V3
        ) {
            policy.fill_v2();
        }
        policy.validate()?;
        Ok(policy)
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        if !std::fs::metadata(path)
            .map_err(|error| format!("Cannot read policy {}: {error}", path.display()))?
            .is_file()
        {
            return Err("Policy must be a regular JSON file".to_owned());
        }
        let file = File::open(path)
            .map_err(|error| format!("Cannot read policy {}: {error}", path.display()))?;
        if !file
            .metadata()
            .map_err(|error| error.to_string())?
            .is_file()
        {
            return Err("Policy must be a regular JSON file".to_owned());
        }
        let mut text = String::new();
        file.take(65537)
            .read_to_string(&mut text)
            .map_err(|error| format!("Cannot read policy: {error}"))?;
        if text.len() > 65536 {
            return Err("Policy exceeds 64 KiB".to_owned());
        }
        Self::from_json(&text)
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != POLICY_SCHEMA_V3
            && (self.checks.password_aging.is_some()
                || self.checks.password_warning.is_some()
                || self.checks.password_complexity.is_some())
        {
            return Err("Credential controls require explicit policy v3".into());
        }
        if let Some(p) = &self.checks.password_aging {
            if p.maximum_days == 0 || p.maximum_days > 36500 || p.minimum_days > p.maximum_days {
                return Err("Invalid password age limits".into());
            }
        }
        if self
            .checks
            .password_warning
            .as_ref()
            .is_some_and(|p| p.minimum_days == 0 || p.minimum_days > 36500)
        {
            return Err("Invalid password warning limit".into());
        }
        if let Some(p) = &self.checks.password_complexity {
            if !(6..=1024).contains(&p.minimum_length)
                || p.minimum_classes > 4
                || [
                    p.minimum_uppercase,
                    p.minimum_lowercase,
                    p.minimum_digits,
                    p.minimum_special,
                ]
                .iter()
                .any(|n| *n > 1024)
            {
                return Err("Invalid password complexity limits".into());
            }
        }
        if ![POLICY_SCHEMA, POLICY_SCHEMA_V2, POLICY_SCHEMA_V3]
            .contains(&self.schema_version.as_str())
        {
            return Err(format!(
                "Unsupported policy schemaVersion; expected {POLICY_SCHEMA}, {POLICY_SCHEMA_V2} or {POLICY_SCHEMA_V3}"
            ));
        }
        let new_checks = self.checks.screen_lock.is_some()
            || self.checks.tpm.is_some()
            || self.checks.secure_boot.is_some()
            || self.checks.firewall.is_some();
        if self.schema_version == POLICY_SCHEMA && new_checks {
            return Err("New Linux baseline controls require explicit policy v2".into());
        }
        if self.schema_version != POLICY_SCHEMA_V3
            && (self.checks.home_encryption.is_some()
                || self.checks.sensitive_encryption.is_some()
                || self.checks.swap_protection.is_some())
        {
            return Err("Encryption coverage controls require explicit policy v3".into());
        }
        if matches!(
            self.schema_version.as_str(),
            POLICY_SCHEMA_V2 | POLICY_SCHEMA_V3
        ) && (self.checks.screen_lock.is_none()
            || self.checks.tpm.is_none()
            || self.checks.secure_boot.is_none()
            || self.checks.firewall.is_none())
        {
            return Err("Policy v2 must be normalized with all baseline settings".into());
        }
        if self.settings().iter().any(|s| s.4 == 0) {
            return Err("Observation age limits must be positive".into());
        }
        if let Some(p) = &self.checks.sensitive_encryption {
            validate_targets(&p.targets)?;
        }
        if let Some(p) = &self.checks.screen_lock {
            if p.max_timeout_seconds == 0
                || (!p.required && (p.require_lock_on_resume || p.require_immediate_password))
            {
                return Err(
                    "Screen-lock timeout must be positive; resume/immediate-password requirements need required=true"
                        .into(),
                );
            }
        }

        if self.id.is_empty()
            || self.id.len() > 128
            || !self
                .id
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            return Err("Policy id must contain 1..128 ASCII letters/digits/._-".to_owned());
        }
        if self.checks.updates.max_metadata_age_seconds == 0
            || self.checks.updates.max_observation_age_seconds == 0
            || self.checks.encryption.max_observation_age_seconds == 0
        {
            return Err("Metadata and observation age limits must be positive".to_owned());
        }
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
    pub enabled: usize,
    pub disabled: usize,
    pub mandatory: usize,
    pub informational: usize,
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub error: usize,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyEvaluation {
    pub schema_version: String,
    pub policy: Policy,
    pub overall: Status,
    pub compliance_scope: String,
    pub summary: EvaluationSummary,
    pub checks: Vec<Evaluation>,
    pub context_reasons: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_monitoring: Option<LocalMonitoringSummary>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalMonitoringSummary {
    pub target_ids: Vec<String>,
}
fn severity(status: Status) -> u8 {
    match status {
        Status::Error => 4,
        Status::Fail => 3,
        Status::Warn | Status::NotApplicable => 2,
        Status::Pass => 1,
    }
}
fn add(status: &mut Status, reasons: &mut Vec<String>, candidate: Status, reason: &str) {
    if severity(candidate) > severity(*status) {
        *status = candidate;
    }
    reasons.push(reason.to_owned());
}

/// A validated policy + borrowed report produce a separate assessment; no OS access.
pub fn evaluate(policy: &Policy, report: &AuditReport) -> Result<PolicyEvaluation, String> {
    policy.validate()?;
    if report.schema_version != crate::audit::REPORT_SCHEMA
        && !(policy.schema_version == POLICY_SCHEMA_V3
            && report.schema_version == "baradwatchu.audit-report.v2")
    {
        return Err("Unsupported observation report schema".to_owned());
    }
    let settings = policy.settings();
    let mut checks = Vec::new();
    let mut summary = EvaluationSummary::default();
    let mut overall = Status::Pass;
    for (id, enabled, mandatory, evidence, max_age) in settings {
        let mut evaluation = Evaluation {
            check_id: id.to_owned(),
            enabled,
            mandatory,
            status: None,
            reasons: vec![],
        };
        if !enabled {
            summary.disabled += 1;
            evaluation.reasons.push("DISABLED_BY_POLICY".to_owned());
            checks.push(evaluation);
            continue;
        }
        summary.enabled += 1;
        if mandatory {
            summary.mandatory += 1;
        } else {
            summary.informational += 1;
        }
        let matches: Vec<_> = report
            .results
            .iter()
            .filter(|result| result.check.id == id)
            .collect();
        let (mut status, mut reasons) = if matches.len() > 1 {
            (Status::Error, vec!["AMBIGUOUS_OBSERVATIONS".to_owned()])
        } else if let Some(result) = matches.first() {
            assess(
                id,
                &result.outcome,
                policy,
                evidence,
                report.completed_at_unix_ms / 1000,
            )
        } else {
            (
                evidence.missing.status(),
                vec!["MISSING_OBSERVATION".to_owned()],
            )
        };
        if let Some(result) = matches.first() {
            if result.observed_at_unix_ms == 0
                || result.observed_at_unix_ms > report.completed_at_unix_ms
            {
                add(
                    &mut status,
                    &mut reasons,
                    evidence.inconclusive.status(),
                    "UNKNOWN_OBSERVATION_TIME",
                );
            } else if report.completed_at_unix_ms - result.observed_at_unix_ms
                > u64::from(max_age) * 1000
            {
                add(
                    &mut status,
                    &mut reasons,
                    evidence.stale.status(),
                    "STALE_OBSERVATION",
                );
            }
        }
        reasons.sort();
        reasons.dedup();
        evaluation.status = Some(status);
        evaluation.reasons = reasons;
        match status {
            Status::Pass => summary.pass += 1,
            Status::Fail => summary.fail += 1,
            Status::Error => summary.error += 1,
            Status::Warn | Status::NotApplicable => summary.warn += 1,
        }
        if mandatory && severity(status) > severity(overall) {
            overall = status;
        }
        checks.push(evaluation);
    }
    let mut context_reasons = vec![];
    if report
        .results
        .iter()
        .filter(|r| r.check.id == "SYS-OS-001")
        .count()
        != 1
    {
        add(
            &mut overall,
            &mut context_reasons,
            Status::Error,
            "MISSING_OR_AMBIGUOUS_OS_IDENTITY",
        );
    }
    if report
        .results
        .iter()
        .any(|r| r.check.id == "SYS-OS-001" && r.outcome.status == Status::Error)
    {
        add(
            &mut overall,
            &mut context_reasons,
            Status::Error,
            "OS_IDENTITY_ERROR",
        );
    }
    if !report.operating_system.supported {
        add(
            &mut overall,
            &mut context_reasons,
            Status::Warn,
            "UNSUPPORTED_PLATFORM",
        );
    }
    if summary.mandatory == 0 {
        add(
            &mut overall,
            &mut context_reasons,
            Status::Warn,
            "NO_ENABLED_MANDATORY_CHECKS",
        );
    }
    Ok(PolicyEvaluation {
        schema_version: if policy.schema_version == POLICY_SCHEMA_V3 {
            "baradwatchu.policy-evaluation.v2"
        } else {
            EVALUATION_SCHEMA
        }
        .to_owned(),
        policy: policy.redacted_for_report(),
        overall,
        compliance_scope: "ENABLED_MANDATORY_CHECKS".to_owned(),
        summary,
        checks,
        context_reasons,
        local_monitoring: None,
    })
}

fn assess(
    id: &str,
    outcome: &crate::audit::Outcome,
    policy: &Policy,
    evidence: &EvidencePolicy,
    now: u64,
) -> (Status, Vec<String>) {
    if outcome.status == Status::Error {
        return (Status::Error, vec!["PROBE_ERROR".to_owned()]);
    }
    if matches!(id, "SEC-008" | "SEC-009" | "SEC-010") {
        return credentials::assess(id, outcome, policy, evidence);
    }
    if matches!(id, "SEC-015" | "SEC-016" | "SEC-017") {
        return assess_coverage(id, outcome, policy, evidence);
    }
    if matches!(id, "SEC-007" | "SEC-012" | "SEC-013" | "SEC-014") {
        return assess_baseline(id, outcome, policy, evidence);
    }
    if outcome.status == Status::NotApplicable {
        return (
            evidence.unsupported.status(),
            vec!["UNSUPPORTED_EVIDENCE".to_owned()],
        );
    }
    let Some(observation) = &outcome.observation else {
        return (
            evidence.missing.status(),
            vec!["MISSING_TYPED_OBSERVATION".to_owned()],
        );
    };
    let mut status = Status::Pass;
    let mut reasons = Vec::new();
    match (id, observation) {
        ("SEC-001", Observation::Updates(updates)) => {
            if updates.metadata_state == MetadataState::Missing {
                add(
                    &mut status,
                    &mut reasons,
                    evidence.missing.status(),
                    "MISSING_METADATA",
                );
            } else {
                if updates.metadata_state != MetadataState::Available
                    || !updates.coverage_complete
                    || updates.repositories.is_empty()
                {
                    add(
                        &mut status,
                        &mut reasons,
                        evidence.inconclusive.status(),
                        "UNKNOWN_METADATA_COVERAGE",
                    );
                }
                for repo in &updates.repositories {
                    match (repo.timestamp_unix_seconds, repo.expires_after_seconds) {
                        (Some(timestamp), Some(expires))
                            if timestamp > 0 && timestamp <= now && expires >= -1 =>
                        {
                            let age = now - timestamp;
                            if age > u64::from(policy.checks.updates.max_metadata_age_seconds)
                                || (expires >= 0 && age >= expires as u64)
                            {
                                add(
                                    &mut status,
                                    &mut reasons,
                                    evidence.stale.status(),
                                    "STALE_METADATA",
                                );
                            }
                        }
                        _ => add(
                            &mut status,
                            &mut reasons,
                            evidence.inconclusive.status(),
                            "UNKNOWN_METADATA_TIMESTAMP",
                        ),
                    }
                }
            }
            match updates.classification {
                UpdateClass::NoPending
                    if updates.pending_packages == Some(0)
                        && updates.security_advisories == Some(0)
                        && updates.ordinary_pending == Some(false)
                        && updates.classification_complete =>
                {
                    reasons.push("NO_PENDING_UPDATES_OBSERVED".to_owned())
                }
                UpdateClass::OrdinaryPending
                    if updates.pending_packages.is_some_and(|n| n > 0)
                        && updates.security_advisories == Some(0)
                        && updates.ordinary_pending == Some(true)
                        && updates.classification_complete =>
                {
                    add(
                        &mut status,
                        &mut reasons,
                        policy.checks.updates.ordinary_updates.status(),
                        "ORDINARY_UPDATES_PENDING",
                    )
                }
                UpdateClass::SecurityPending
                    if updates.pending_packages.is_some_and(|n| n > 0)
                        && updates.security_advisories.is_some_and(|n| n > 0)
                        && (!updates.classification_complete
                            || updates.ordinary_pending.is_some()) =>
                {
                    add(
                        &mut status,
                        &mut reasons,
                        policy.checks.updates.security_updates.status(),
                        "SECURITY_UPDATES_PENDING",
                    );
                    // Other pending packages may also be ordinary; do not ignore their configured rule.
                    if updates.ordinary_pending == Some(true) {
                        add(
                            &mut status,
                            &mut reasons,
                            policy.checks.updates.ordinary_updates.status(),
                            "ORDINARY_UPDATES_PENDING",
                        );
                    }
                    if !updates.classification_complete {
                        add(
                            &mut status,
                            &mut reasons,
                            evidence.inconclusive.status(),
                            "INCOMPLETE_SECURITY_CLASSIFICATION",
                        );
                    }
                }
                UpdateClass::UnknownSecurity if updates.pending_packages != Some(0) => {
                    add(
                        &mut status,
                        &mut reasons,
                        evidence.inconclusive.status(),
                        "UNKNOWN_SECURITY_CLASSIFICATION",
                    );
                    if policy.checks.updates.ordinary_updates == PendingAction::Fail
                        && policy.checks.updates.security_updates == PendingAction::Fail
                    {
                        add(
                            &mut status,
                            &mut reasons,
                            Status::Fail,
                            "ANY_PENDING_UPDATES_DISALLOWED",
                        );
                    }
                    if updates.ordinary_pending == Some(true) {
                        add(
                            &mut status,
                            &mut reasons,
                            policy.checks.updates.ordinary_updates.status(),
                            "ORDINARY_UPDATES_PENDING",
                        );
                    }
                }
                UpdateClass::Unknown => add(
                    &mut status,
                    &mut reasons,
                    evidence.inconclusive.status(),
                    "UNKNOWN_UPDATE_AVAILABILITY",
                ),
                _ => add(
                    &mut status,
                    &mut reasons,
                    Status::Error,
                    "INCONSISTENT_UPDATE_OBSERVATION",
                ),
            }
        }
        ("SEC-006", Observation::RootEncryption(root)) => {
            if !root.topology_complete || root.paths.is_empty() {
                add(
                    &mut status,
                    &mut reasons,
                    evidence.inconclusive.status(),
                    "INCOMPLETE_ROOT_TOPOLOGY",
                );
            } else if root.paths.iter().any(|path| path.devices.is_empty()) {
                add(
                    &mut status,
                    &mut reasons,
                    Status::Error,
                    "INCONSISTENT_ROOT_OBSERVATION",
                );
            } else if policy.checks.encryption.requirement == EncryptionRequirement::NotRequired {
                reasons.push("ROOT_ENCRYPTION_EXPLICITLY_NOT_REQUIRED".to_owned());
            } else if root.paths.iter().all(|path| path.luks_protected) {
                reasons.push("ALL_ROOT_BACKING_PATHS_LUKS_PROTECTED".to_owned());
            } else {
                add(
                    &mut status,
                    &mut reasons,
                    Status::Fail,
                    "UNENCRYPTED_ROOT_BACKING_PATH",
                );
            }
        }
        _ => add(
            &mut status,
            &mut reasons,
            Status::Error,
            "OBSERVATION_TYPE_MISMATCH",
        ),
    }
    reasons.sort();
    reasons.dedup();
    (status, reasons)
}

fn assess_coverage(
    id: &str,
    outcome: &crate::audit::Outcome,
    policy: &Policy,
    evidence: &EvidencePolicy,
) -> (Status, Vec<String>) {
    use crate::observation::{Protection, Quality};
    if outcome.status == Status::NotApplicable
        && outcome.reason_code == crate::audit::Reason::UnsupportedPlatform
    {
        return (
            evidence.unsupported.status(),
            vec!["UNSUPPORTED_EVIDENCE".into()],
        );
    }
    let Some(Observation::EncryptionCoverage(facts)) = &outcome.observation else {
        return (
            evidence.missing.status(),
            vec!["MISSING_COVERAGE_OBSERVATION".into()],
        );
    };
    if facts.items.is_empty() {
        return (evidence.missing.status(), vec!["EMPTY_COVERAGE".into()]);
    }
    let ids: std::collections::BTreeSet<_> = facts.items.iter().map(|i| i.id.as_str()).collect();
    if ids.len() != facts.items.len() {
        return (Status::Error, vec!["DUPLICATE_COVERAGE_ID".into()]);
    }
    if id == "SEC-016" {
        let Some(config) = &policy.checks.sensitive_encryption else {
            return (Status::Error, vec!["MISSING_CHECK_POLICY".into()]);
        };
        let expected: std::collections::BTreeSet<_> =
            config.targets.iter().map(|t| t.id.as_str()).collect();
        if ids != expected {
            return (Status::Error, vec!["TARGET_COVERAGE_MISMATCH".into()]);
        }
    }
    if id == "SEC-015" && (facts.items.len() != 1 || !ids.contains("home")) {
        return (Status::Error, vec!["HOME_COVERAGE_MISMATCH".into()]);
    }
    let required = match id {
        "SEC-015" => policy.checks.home_encryption.as_ref().map(|p| p.required),
        "SEC-016" => Some(true),
        "SEC-017" => policy.checks.swap_protection.as_ref().map(|p| p.required),
        _ => None,
    };
    let Some(required) = required else {
        return (Status::Error, vec!["MISSING_CHECK_POLICY".into()]);
    };
    if matches!(
        facts.quality,
        Quality::Missing | Quality::Restricted | Quality::Unsupported
    ) {
        return (
            evidence.inconclusive.status(),
            vec!["COVERAGE_UNAVAILABLE".into()],
        );
    }
    if facts.quality == Quality::NotApplicable
        && !(id == "SEC-017"
            && facts.items.len() == 1
            && facts.items[0].protection == Protection::NotApplicable)
    {
        return (Status::Error, vec!["INCONSISTENT_COVERAGE_QUALITY".into()]);
    }
    let mut status = Status::Pass;
    let mut reasons = Vec::new();
    for item in &facts.items {
        let technology = item.technology.as_deref();
        let consistent = match item.protection {
            Protection::Protected => match technology {
                Some("ECRYPTFS" | "CRYFS" | "LUKS") => {
                    item.at_rest == Some(true) && (id == "SEC-017" || item.mounted == Some(true))
                }
                Some("DM_CRYPT") => id == "SEC-017" && item.at_rest == Some(true),
                Some("ZRAM_VOLATILE") => id == "SEC-017" && item.at_rest == Some(false),
                _ => false,
            },
            Protection::Unprotected => technology == Some("PLAINTEXT_BACKING"),
            Protection::NotApplicable => id == "SEC-017" && technology == Some("NO_ACTIVE_SWAP"),
            Protection::Inconclusive => true,
        };
        if !consistent {
            return (
                Status::Error,
                vec!["INCONSISTENT_COVERAGE_OBSERVATION".into()],
            );
        }
        match item.protection {
            Protection::Protected => reasons.push("PROTECTED_COVERAGE_OBSERVED".into()),
            Protection::Unprotected if required => add(
                &mut status,
                &mut reasons,
                Status::Fail,
                "UNPROTECTED_COVERAGE_OBSERVED",
            ),
            Protection::Unprotected => reasons.push("PROTECTION_NOT_REQUIRED".into()),
            Protection::Inconclusive => add(
                &mut status,
                &mut reasons,
                evidence.inconclusive.status(),
                "INCONCLUSIVE_COVERAGE",
            ),
            Protection::NotApplicable if id == "SEC-017" && facts.items.len() == 1 => {
                return (Status::NotApplicable, vec!["NO_ACTIVE_SWAP".into()])
            }
            Protection::NotApplicable => add(
                &mut status,
                &mut reasons,
                evidence.unsupported.status(),
                "COVERAGE_NOT_APPLICABLE",
            ),
        }
    }
    if facts.quality == Quality::Inconclusive {
        add(
            &mut status,
            &mut reasons,
            evidence.inconclusive.status(),
            "INCONCLUSIVE_EVIDENCE",
        );
    }
    (status, reasons)
}

fn assess_baseline(
    id: &str,
    outcome: &crate::audit::Outcome,
    policy: &Policy,
    evidence: &EvidencePolicy,
) -> (Status, Vec<String>) {
    use crate::observation::{BootState, Filtering, Quality};
    if outcome.status == Status::NotApplicable
        && outcome.reason_code == crate::audit::Reason::UnsupportedPlatform
    {
        return (
            evidence.unsupported.status(),
            vec!["UNSUPPORTED_EVIDENCE".into()],
        );
    }
    let quality = match (id, &outcome.observation) {
        ("SEC-007", Some(Observation::ScreenLock(f))) => f.quality,
        ("SEC-012", Some(Observation::Tpm(f))) => f.quality,
        ("SEC-013", Some(Observation::SecureBoot(f))) => f.quality,
        ("SEC-014", Some(Observation::Firewall(f))) => f.quality,
        (_, None) => {
            return (
                evidence.missing.status(),
                vec!["MISSING_TYPED_OBSERVATION".into()],
            )
        }
        _ => return (Status::Error, vec!["OBSERVATION_TYPE_MISMATCH".into()]),
    };
    let uncertain = match quality {
        Quality::Missing => Some((evidence.missing.status(), "MISSING_EVIDENCE")),
        Quality::Unsupported => Some((evidence.unsupported.status(), "UNSUPPORTED_EVIDENCE")),
        Quality::Inconclusive => Some((evidence.inconclusive.status(), "INCONCLUSIVE_EVIDENCE")),
        Quality::Restricted => Some((evidence.inconclusive.status(), "RESTRICTED_HOST_SCOPE")),
        Quality::NotApplicable if id == "SEC-007" => {
            Some((Status::NotApplicable, "HEADLESS_NOT_APPLICABLE"))
        }
        Quality::NotApplicable => Some((evidence.unsupported.status(), "UNSUPPORTED_EVIDENCE")),
        Quality::Verified => None,
    };
    if let Some((s, r)) = uncertain {
        return (s, vec![r.into()]);
    }
    let mut reasons = vec![];
    let mut status = Status::Pass;
    let required = match id {
        "SEC-007" => policy.checks.screen_lock.as_ref().map(|p| p.required),
        "SEC-012" => policy.checks.tpm.as_ref().map(|p| p.required),
        "SEC-013" => policy.checks.secure_boot.as_ref().map(|p| p.required),
        "SEC-014" => policy.checks.firewall.as_ref().map(|p| p.required),
        _ => None,
    };
    let Some(required) = required else {
        return (Status::Error, vec!["MISSING_CHECK_POLICY".into()]);
    };
    let criterion = match outcome.observation.as_ref().expect("typed observation") {
        Observation::SecureBoot(f) => match (f.state, f.secure_boot, f.setup_mode) {
            (BootState::Enabled, Some(true), Some(false)) => Some(true),
            (BootState::Disabled, Some(false), Some(_)) => Some(false),
            (BootState::NonUefiBoot, None, None) => Some(false),
            _ => None,
        },
        Observation::Tpm(f) => {
            if f.devices.iter().all(|d| {
                matches!(d.version_major, Some(1 | 2))
                    && d.character_device_verified
                    && d.read_permission == Some(true)
            }) {
                Some(f.devices.iter().any(|d| d.version_major == Some(2)))
            } else {
                None
            }
        }
        Observation::Firewall(f) => {
            let known = f.managers.len() == 5
                && f.managers
                    .iter()
                    .all(|m| m.installed.is_some() && m.active.is_some());
            if f.multiple_managers || !known {
                None
            } else {
                match (f.filtering, f.ipv4_verified, f.ipv6_verified) {
                    (Filtering::VerifiedInputFiltering, true, true) => Some(true),
                    (Filtering::NoFilteringInInspectedInputBackends, false, false) => Some(false),
                    _ => None,
                }
            }
        }
        Observation::ScreenLock(f) => {
            let p = policy.checks.screen_lock.as_ref().expect("screen policy");
            let (Some(idle), Some(grace)) = (f.idle_timeout_seconds, f.grace_seconds) else {
                return (Status::Error, vec!["INCONSISTENT_VERIFIED_EVIDENCE".into()]);
            };
            if [
                f.capability,
                f.configuration_enabled,
                f.automatic_lock,
                f.password_required,
                f.lock_on_resume,
            ]
            .iter()
            .any(Option::is_none)
                || (f.automatic_lock == Some(true) && idle == 0)
                || (f.configuration_enabled == Some(true) && f.password_required == Some(false))
            {
                None
            } else {
                let timeout = idle.checked_add(grace);
                if required && p.require_immediate_password && grace != 0 {
                    add(
                        &mut status,
                        &mut reasons,
                        Status::Fail,
                        "IMMEDIATE_PASSWORD_REQUIRED",
                    );
                }
                if required && timeout.map_or(true, |s| s > p.max_timeout_seconds) {
                    add(
                        &mut status,
                        &mut reasons,
                        Status::Fail,
                        "SCREEN_LOCK_TIMEOUT_EXCEEDED",
                    )
                }
                if required && p.require_lock_on_resume && f.lock_on_resume != Some(true) {
                    add(
                        &mut status,
                        &mut reasons,
                        Status::Fail,
                        "LOCK_ON_RESUME_REQUIRED",
                    )
                }
                Some(
                    f.capability == Some(true)
                        && f.configuration_enabled == Some(true)
                        && f.automatic_lock == Some(true)
                        && f.password_required == Some(true),
                )
            }
        }
        _ => None,
    };
    match criterion {
        None => add(
            &mut status,
            &mut reasons,
            Status::Error,
            "INCONSISTENT_VERIFIED_EVIDENCE",
        ),
        Some(false) if required => add(
            &mut status,
            &mut reasons,
            Status::Fail,
            "REQUIRED_STATE_NOT_OBSERVED",
        ),
        Some(_) => reasons.push(
            if required {
                "REQUIRED_STATE_OBSERVED"
            } else {
                "KNOWN_STATE_EXPLICITLY_NOT_REQUIRED"
            }
            .into(),
        ),
    }
    (status, reasons)
}
