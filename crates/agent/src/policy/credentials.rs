//! Opt-in v3 credential criteria. Facts remain independent of these thresholds.
use super::{add, EvidencePolicy};
use crate::{
    audit::{Outcome, Status},
    observation::{Observation, Quality},
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct AgingPolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub max_observation_age_seconds: u32,
    pub maximum_days: u32,
    pub minimum_days: u32,
}
impl Default for AgingPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mandatory: true,
            evidence: EvidencePolicy::default(),
            max_observation_age_seconds: 300,
            maximum_days: 60,
            minimum_days: 1,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct WarningPolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub max_observation_age_seconds: u32,
    pub minimum_days: u32,
}
impl Default for WarningPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mandatory: true,
            evidence: EvidencePolicy::default(),
            max_observation_age_seconds: 300,
            minimum_days: 10,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase", default)]
pub struct ComplexityPolicy {
    pub enabled: bool,
    pub mandatory: bool,
    pub evidence: EvidencePolicy,
    pub max_observation_age_seconds: u32,
    pub minimum_length: u32,
    pub minimum_classes: u32,
    pub minimum_uppercase: u32,
    pub minimum_lowercase: u32,
    pub minimum_digits: u32,
    pub minimum_special: u32,
}
impl Default for ComplexityPolicy {
    fn default() -> Self {
        Self {
            enabled: true,
            mandatory: true,
            evidence: EvidencePolicy::default(),
            max_observation_age_seconds: 300,
            minimum_length: 14,
            minimum_classes: 4,
            minimum_uppercase: 1,
            minimum_lowercase: 1,
            minimum_digits: 1,
            minimum_special: 1,
        }
    }
}
pub(super) fn aging_present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<AgingPolicy>, D::Error> {
    AgingPolicy::deserialize(d).map(Some)
}
pub(super) fn warning_present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<WarningPolicy>, D::Error> {
    WarningPolicy::deserialize(d).map(Some)
}
pub(super) fn complexity_present<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Option<ComplexityPolicy>, D::Error> {
    ComplexityPolicy::deserialize(d).map(Some)
}

pub(super) fn assess(
    id: &str,
    outcome: &Outcome,
    p: &super::Policy,
    evidence: &EvidencePolicy,
) -> (Status, Vec<String>) {
    if outcome.status == Status::NotApplicable {
        return (
            evidence.unsupported.status(),
            vec!["UNSUPPORTED_EVIDENCE".into()],
        );
    }
    if outcome.observation.is_none() {
        return (
            evidence.missing.status(),
            vec!["MISSING_TYPED_OBSERVATION".into()],
        );
    }
    let unknown = || {
        (
            evidence.inconclusive.status(),
            vec!["CREDENTIAL_EVIDENCE_INCONCLUSIVE".into()],
        )
    };
    let mut status = Status::Pass;
    let mut reasons = vec![];
    match (id, &outcome.observation) {
        ("SEC-008" | "SEC-009", Some(Observation::PasswordAging(f))) => {
            if f.quality != Quality::Verified || f.accounts.is_empty() {
                return unknown();
            }
            for a in &f.accounts {
                if a.quality != Quality::Verified {
                    add(
                        &mut status,
                        &mut reasons,
                        evidence.inconclusive.status(),
                        "ACCOUNT_AGING_UNAVAILABLE",
                    );
                    continue;
                }
                let criterion = if id == "SEC-008" {
                    let c = p.checks.password_aging.as_ref().expect("enabled criterion");
                    match (a.values.maximum_days, a.values.minimum_days, a.expires) {
                        (Some(max), Some(min), Some(expires)) => Some(
                            expires
                                && max >= 0
                                && max <= i64::from(c.maximum_days)
                                && min.max(0) >= i64::from(c.minimum_days)
                                && min <= max,
                        ),
                        _ => None,
                    }
                } else {
                    let c = p
                        .checks
                        .password_warning
                        .as_ref()
                        .expect("enabled criterion");
                    match (a.values.warning_days, a.values.maximum_days, a.expires) {
                        (Some(warn), Some(max), Some(expires)) => Some(
                            expires && max > 0 && warn >= i64::from(c.minimum_days) && warn <= max,
                        ),
                        _ => None,
                    }
                };
                match criterion {
                    Some(true) => reasons.push("EFFECTIVE_ACCOUNT_AGING_SATISFIES_POLICY".into()),
                    Some(false) => add(
                        &mut status,
                        &mut reasons,
                        Status::Fail,
                        if id == "SEC-008" {
                            "ACCOUNT_AGING_OUTSIDE_POLICY"
                        } else {
                            "ACCOUNT_WARNING_OUTSIDE_POLICY"
                        },
                    ),
                    None => add(
                        &mut status,
                        &mut reasons,
                        evidence.inconclusive.status(),
                        "INCOMPLETE_ACCOUNT_AGING",
                    ),
                }
            }
        }
        ("SEC-010", Some(Observation::PasswordComplexity(f))) => {
            if f.quality != Quality::Verified || f.stacks.is_empty() {
                return unknown();
            }
            let c = p
                .checks
                .password_complexity
                .as_ref()
                .expect("enabled criterion");
            let mut applicable = 0;
            for s in &f.stacks {
                if s.quality == Quality::Verified
                    && s.password_changes_denied
                    && !s.enforcement_proven
                    && s.requirements.is_none()
                {
                    reasons.push("STACK_DENIES_PASSWORD_CHANGES".into());
                    continue;
                }
                applicable += 1;
                if s.quality != Quality::Verified || !s.enforcement_proven {
                    add(
                        &mut status,
                        &mut reasons,
                        evidence.inconclusive.status(),
                        "PAM_ENFORCEMENT_NOT_PROVEN",
                    );
                    continue;
                }
                let Some(r) = &s.requirements else {
                    return unknown();
                };
                if r.enforcing != Some(true) || r.enforce_for_root != Some(true) {
                    add(
                        &mut status,
                        &mut reasons,
                        evidence.inconclusive.status(),
                        "PAM_ENFORCEMENT_NOT_PROVEN",
                    );
                    continue;
                }
                let (Some(length), Some(classes), [Some(u), Some(l), Some(d), Some(o)]) =
                    (r.minimum_length, r.minimum_classes, r.credits)
                else {
                    add(
                        &mut status,
                        &mut reasons,
                        evidence.inconclusive.status(),
                        "PWQUALITY_SETTINGS_UNKNOWN",
                    );
                    continue;
                };
                // Positive credits can reduce true length. Do not equate minlen with length.
                let credits = [u, l, d, o];
                let credited_length =
                    i64::from(length) - credits.iter().map(|v| i64::from((*v).max(0))).sum::<i64>();
                let minima = [
                    c.minimum_uppercase,
                    c.minimum_lowercase,
                    c.minimum_digits,
                    c.minimum_special,
                ];
                let individually_required = credits.iter().filter(|v| **v < 0).count() as i64;
                let ok = credited_length >= i64::from(c.minimum_length)
                    && i64::from(classes).max(individually_required)
                        >= i64::from(c.minimum_classes)
                    && credits
                        .iter()
                        .zip(minima)
                        .all(|(v, n)| -i64::from(*v).min(0) >= i64::from(n));
                if ok {
                    reasons.push("PAM_CONFIGURED_REQUIREMENTS_SATISFY_POLICY".into());
                } else {
                    add(
                        &mut status,
                        &mut reasons,
                        Status::Fail,
                        "PAM_REQUIREMENTS_BELOW_POLICY",
                    );
                }
            }
            if applicable == 0 {
                return unknown();
            }
        }
        _ => return unknown(),
    }
    (status, reasons)
}
