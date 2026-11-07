mod common;
use baradwatchu_agent::{
    audit::{AuditReport, Outcome, Reason, Status},
    checks::builtin,
    observation::*,
    policy::*,
};
use common::*;
fn report() -> AuditReport {
    builtin::standalone(&platform(), &FixedClock).unwrap()
}
fn updates(report: &mut AuditReport, facts: Updates) {
    report.results[1].outcome.observation = Some(Observation::Updates(facts));
}
fn root_facts(report: &mut AuditReport, facts: RootEncryption) {
    report.results[2].outcome.observation = Some(Observation::RootEncryption(facts));
}
fn ordinary() -> Updates {
    Updates {
        classification: UpdateClass::OrdinaryPending,
        pending_packages: Some(1),
        ordinary_pending: Some(true),
        ..fresh_updates()
    }
}
fn security() -> Updates {
    Updates {
        classification: UpdateClass::SecurityPending,
        pending_packages: Some(1),
        security_advisories: Some(1),
        ..fresh_updates()
    }
}
fn valid_json() -> serde_json::Value {
    serde_json::to_value(Policy::default()).unwrap()
}

#[test]
fn sample_matches_strict_defaults_and_partial_policies_do_not_weaken_omitted_checks() {
    let sample = Policy::from_json(include_str!("../../../policies/default.json")).unwrap();
    assert_eq!(sample, Policy::default());
    let minimal = Policy::from_json(r#"{"schemaVersion":"baradwatchu.audit-policy.v1"}"#).unwrap();
    assert_eq!(minimal, sample);
    let partial=Policy::from_json(r#"{"schemaVersion":"baradwatchu.audit-policy.v1","checks":{"SEC-001":{"ordinaryUpdates":"ALLOW"}}}"#).unwrap();
    assert!(partial.checks.updates.enabled && partial.checks.updates.mandatory);
    assert_eq!(
        partial.checks.encryption.requirement,
        EncryptionRequirement::Luks
    );
}
#[test]
fn rejects_unknown_fields_at_every_level() {
    for path in [
        vec!["surprise"],
        vec!["checks", "SEC-999"],
        vec!["checks", "SEC-001", "typo"],
        vec!["checks", "SEC-006", "typo"],
        vec!["checks", "SEC-001", "evidence", "typo"],
    ] {
        let mut value = valid_json();
        let mut target = &mut value;
        for key in &path[..path.len() - 1] {
            target = &mut target[*key];
        }
        target[path[path.len() - 1]] = serde_json::json!(true);
        assert!(Policy::from_json(&value.to_string()).is_err(), "{path:?}");
    }
}
#[test]
fn rejects_invalid_versions_types_actions_age_and_identifiers() {
    for (field, value) in [
        (
            "schemaVersion",
            serde_json::json!("baradwatchu.audit-policy.v99"),
        ),
        ("id", serde_json::json!("")),
        ("id", serde_json::json!("unsafe/name")),
    ] {
        let mut p = valid_json();
        p[field] = value;
        assert!(Policy::from_json(&p.to_string()).is_err());
    }
    for (field, value) in [
        ("enabled", serde_json::json!("false")),
        ("mandatory", serde_json::Value::Null),
        ("ordinaryUpdates", serde_json::json!("IGNORE")),
        ("maxMetadataAgeSeconds", serde_json::json!(0)),
        ("maxMetadataAgeSeconds", serde_json::json!(-1)),
        ("maxMetadataAgeSeconds", serde_json::json!(1.5)),
        ("maxObservationAgeSeconds", serde_json::json!(0)),
    ] {
        let mut p = valid_json();
        p["checks"]["SEC-001"][field] = value;
        assert!(Policy::from_json(&p.to_string()).is_err());
    }
    for field in ["missing", "stale", "inconclusive", "unsupported"] {
        let mut p = valid_json();
        p["checks"]["SEC-006"]["evidence"][field] = serde_json::json!("PASS");
        assert!(Policy::from_json(&p.to_string()).is_err());
    }
    let mut p = valid_json();
    p["checks"]["SEC-006"]["requirement"] = serde_json::json!("ANY_ENCRYPTION");
    assert!(Policy::from_json(&p.to_string()).is_err());
    assert!(Policy::from_json("{}").is_err());
    assert!(Policy::from_json("[]").is_err());
    assert!(Policy::from_json(
        r#"{"schemaVersion":"baradwatchu.audit-policy.v1","id":"a","id":"b"}"#
    )
    .is_err());
}
#[test]
fn fresh_known_observations_pass_without_rewriting_legacy_warning() {
    let raw = report();
    assert_eq!(raw.results[1].outcome.status, Status::Warn);
    let result = evaluate(&Policy::default(), &raw).unwrap();
    assert_eq!(result.overall, Status::Pass);
    assert_eq!(result.compliance_scope, "ENABLED_MANDATORY_CHECKS");
    assert_eq!(raw.results[1].outcome.status, Status::Warn);
}
#[test]
fn policy_evaluation_never_changes_raw_results_or_evidence() {
    let mut raw = report();
    raw.results[2].outcome.status = Status::Fail;
    let mut facts = root();
    facts.paths[0].luks_protected = false;
    root_facts(&mut raw, facts);
    let before = serde_json::to_string(&raw).unwrap();
    let strict = evaluate(&Policy::default(), &raw).unwrap();
    assert_eq!(strict.overall, Status::Fail);
    let mut p = Policy::default();
    p.checks.encryption.requirement = EncryptionRequirement::NotRequired;
    let relaxed = evaluate(&p, &raw).unwrap();
    assert_eq!(relaxed.overall, Status::Pass);
    assert_eq!(serde_json::to_string(&raw).unwrap(), before);
    assert_eq!(raw.results[2].outcome.status, Status::Fail);
}
#[test]
fn pending_actions_distinguish_ordinary_security_and_mixed_cases() {
    let mut raw = report();
    let mut p = Policy::default();
    p.checks.updates.ordinary_updates = PendingAction::Allow;
    updates(&mut raw, ordinary());
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Pass);
    updates(&mut raw, security());
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Fail);
    p.checks.updates.security_updates = PendingAction::Allow;
    p.checks.updates.ordinary_updates = PendingAction::Fail;
    assert_eq!(
        evaluate(&p, &raw).unwrap().overall,
        Status::Pass,
        "security-only update must not invent ordinary updates"
    );
    let mut mixed = security();
    mixed.pending_packages = Some(2);
    mixed.ordinary_pending = Some(true);
    updates(&mut raw, mixed);
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Fail);
    p.checks.updates.ordinary_updates = PendingAction::Warn;
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Warn);
}
#[test]
fn unknown_classification_never_passes_even_if_all_known_classes_are_allowed() {
    let mut raw = report();
    let unknown = Updates {
        classification: UpdateClass::UnknownSecurity,
        pending_packages: Some(1),
        classification_complete: false,
        ordinary_pending: Some(false),
        ..fresh_updates()
    };
    updates(&mut raw, unknown);
    for ordinary in [
        PendingAction::Allow,
        PendingAction::Warn,
        PendingAction::Fail,
    ] {
        for security in [
            PendingAction::Allow,
            PendingAction::Warn,
            PendingAction::Fail,
        ] {
            let mut p = Policy::default();
            p.checks.updates.ordinary_updates = ordinary;
            p.checks.updates.security_updates = security;
            assert_ne!(
                evaluate(&p, &raw).unwrap().checks[0].status,
                Some(Status::Pass)
            );
        }
    }
}
#[test]
fn known_ordinary_violation_is_not_hidden_by_unknown_security_classification() {
    let mut raw = report();
    updates(
        &mut raw,
        Updates {
            classification: UpdateClass::UnknownSecurity,
            pending_packages: Some(2),
            classification_complete: false,
            ordinary_pending: Some(true),
            ..fresh_updates()
        },
    );
    let mut p = Policy::default();
    p.checks.updates.security_updates = PendingAction::Allow;
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Fail);
}
#[test]
fn incomplete_security_coverage_does_not_pass_when_security_updates_are_allowed() {
    let mut raw = report();
    let mut data = security();
    data.classification_complete = false;
    updates(&mut raw, data);
    let mut p = Policy::default();
    p.checks.updates.security_updates = PendingAction::Allow;
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Warn);
}
#[test]
fn stale_metadata_and_unknown_coverage_are_independently_evaluated() {
    let mut raw = report();
    let mut data = fresh_updates();
    data.repositories[0].timestamp_unix_seconds = Some(NOW - 90000);
    data.coverage_complete = false;
    updates(&mut raw, data);
    let mut p = Policy::default();
    p.checks.updates.evidence.stale = Uncertain::Error;
    let result = evaluate(&p, &raw).unwrap();
    assert_eq!(result.overall, Status::Error);
    assert!(result.checks[0].reasons.contains(&"STALE_METADATA".into()));
    assert!(result.checks[0]
        .reasons
        .contains(&"UNKNOWN_METADATA_COVERAGE".into()));
}
#[test]
fn missing_and_unknown_metadata_never_pass() {
    for state in [MetadataState::Missing, MetadataState::Unknown] {
        let mut raw = report();
        let mut data = fresh_updates();
        data.metadata_state = state;
        updates(&mut raw, data);
        assert_eq!(
            evaluate(&Policy::default(), &raw).unwrap().overall,
            Status::Warn
        );
    }
    for timestamp in [None, Some(0), Some(NOW + 1)] {
        let mut raw = report();
        let mut data = fresh_updates();
        data.repositories[0].timestamp_unix_seconds = timestamp;
        updates(&mut raw, data);
        assert_ne!(
            evaluate(&Policy::default(), &raw).unwrap().overall,
            Status::Pass
        );
    }
}
#[test]
fn repo_expiration_and_policy_max_age_both_bound_metadata() {
    let mut raw = report();
    let mut data = fresh_updates();
    data.repositories[0].expires_after_seconds = Some(10);
    updates(&mut raw, data);
    assert_eq!(
        evaluate(&Policy::default(), &raw).unwrap().overall,
        Status::Warn
    );
    let mut data = fresh_updates();
    data.repositories[0].expires_after_seconds = Some(-1);
    updates(&mut raw, data);
    let mut p = Policy::default();
    p.checks.updates.max_metadata_age_seconds = 10;
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Warn);
}
#[test]
fn all_uncertain_handlers_can_tighten_but_never_allow_unknown_evidence() {
    for (action, status) in [
        (Uncertain::Warn, Status::Warn),
        (Uncertain::Fail, Status::Fail),
        (Uncertain::Error, Status::Error),
    ] {
        let mut raw = report();
        raw.results[2].outcome.observation = None;
        let mut p = Policy::default();
        p.checks.encryption.evidence.missing = action;
        assert_eq!(evaluate(&p, &raw).unwrap().overall, status);
        let mut raw = report();
        let mut data = root();
        data.topology_complete = false;
        root_facts(&mut raw, data);
        p.checks.encryption.evidence.inconclusive = action;
        assert_eq!(evaluate(&p, &raw).unwrap().overall, status);
        let mut raw = report();
        raw.results[2].observed_at_unix_ms = (NOW - 1000) * 1000;
        p.checks.encryption.evidence.stale = action;
        assert_eq!(evaluate(&p, &raw).unwrap().overall, status);
        let mut raw = report();
        raw.results[2].outcome = Outcome::new(
            Status::NotApplicable,
            Reason::UnsupportedPlatform,
            "fixture",
        );
        p.checks.encryption.evidence.unsupported = action;
        assert_eq!(evaluate(&p, &raw).unwrap().overall, status);
    }
}
#[test]
fn optional_encryption_still_cannot_certify_ambiguous_topology() {
    let mut p = Policy::default();
    p.checks.encryption.requirement = EncryptionRequirement::NotRequired;
    let mut raw = report();
    let mut data = root();
    data.topology_complete = false;
    root_facts(&mut raw, data);
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Warn);
}
#[test]
fn probe_errors_cannot_be_downgraded_by_evidence_settings() {
    let mut raw = report();
    raw.results[1].outcome =
        Outcome::new(Status::Error, Reason::ReadOnlyGuardUnavailable, "fixture");
    assert_eq!(
        evaluate(&Policy::default(), &raw).unwrap().overall,
        Status::Error
    );
}
#[test]
fn informational_failure_remains_visible_without_failing_mandatory_compliance() {
    let mut raw = report();
    updates(&mut raw, ordinary());
    let mut p = Policy::default();
    p.checks.updates.mandatory = false;
    let result = evaluate(&p, &raw).unwrap();
    assert_eq!(result.overall, Status::Pass);
    assert_eq!(result.checks[0].status, Some(Status::Fail));
    assert_eq!(result.summary.informational, 1);
    raw.results[1].outcome = Outcome::new(Status::Error, Reason::MissingTool, "fixture");
    let result = evaluate(&p, &raw).unwrap();
    assert_eq!(result.overall, Status::Pass);
    assert_eq!(result.checks[0].status, Some(Status::Error));
}
#[test]
fn disabled_checks_execute_no_probes_and_emit_no_fake_raw_result() {
    let platform = platform();
    let mut p = Policy::default();
    p.checks.updates.enabled = false;
    let raw = builtin::standalone_with_policy(&platform, &FixedClock, &p).unwrap();
    assert_eq!(*platform.calls.borrow(), ["os", "root"]);
    assert_eq!(raw.results.len(), 2);
    let evaluation = raw.policy_evaluation.unwrap();
    assert_eq!(evaluation.checks[0].status, None);
    assert_eq!(evaluation.summary.disabled, 1);
}
#[test]
fn empty_mandatory_coverage_and_unsupported_context_cannot_be_pass() {
    let raw = report();
    let mut p = Policy::default();
    p.checks.updates.enabled = false;
    p.checks.encryption.enabled = false;
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Warn);
    p.checks.updates.enabled = true;
    p.checks.encryption.enabled = true;
    p.checks.updates.mandatory = false;
    p.checks.encryption.mandatory = false;
    assert_eq!(evaluate(&p, &raw).unwrap().overall, Status::Warn);
    let mut unsupported = report();
    unsupported.operating_system.supported = false;
    assert_eq!(
        evaluate(&Policy::default(), &unsupported).unwrap().overall,
        Status::Warn
    );
}
#[test]
fn duplicate_missing_identity_and_inconsistent_facts_are_errors() {
    let mut raw = report();
    raw.results.remove(0);
    assert_eq!(
        evaluate(&Policy::default(), &raw).unwrap().overall,
        Status::Error
    );
    let mut raw = report();
    let duplicate = serde_json::from_value(serde_json::to_value(&raw.results[1]).unwrap()).unwrap();
    raw.results.push(duplicate);
    assert_eq!(
        evaluate(&Policy::default(), &raw).unwrap().overall,
        Status::Error
    );
    let mut raw = report();
    let mut facts = fresh_updates();
    facts.classification = UpdateClass::SecurityPending;
    updates(&mut raw, facts);
    assert_eq!(
        evaluate(&Policy::default(), &raw).unwrap().overall,
        Status::Error
    );
}
#[test]
fn legacy_v1_deserializes_without_typed_observations_or_policy_fields() {
    let raw = report();
    let mut json = serde_json::to_value(&raw).unwrap();
    for result in json["results"].as_array_mut().unwrap() {
        result.as_object_mut().unwrap().remove("observation");
    }
    let legacy: AuditReport = serde_json::from_value(json).unwrap();
    assert!(legacy.policy_evaluation.is_none());
    assert_eq!(legacy.schema_version, "baradwatchu.audit-report.v1");
    assert_eq!(
        evaluate(&Policy::default(), &legacy).unwrap().overall,
        Status::Warn
    );
}
#[test]
fn extended_json_roundtrips_and_preserves_original_v1_fields() {
    let raw =
        builtin::standalone_with_policy(&platform(), &FixedClock, &Policy::default()).unwrap();
    let restored: AuditReport =
        serde_json::from_str(&serde_json::to_string(&raw).unwrap()).unwrap();
    assert_eq!(restored, raw);
    assert_eq!(raw.overall, Status::Warn);
    assert_eq!(
        raw.policy_evaluation.as_ref().unwrap().overall,
        Status::Pass
    );
    assert_eq!(raw.exit_code(), 0);
}
