mod common;
use baradwatchu_agent::{
    audit::{AuditReport, OperatingSystem, Outcome, Reason, Status},
    checks::builtin,
    local_config::LocalConfig,
    observation::{CoverageItem, EncryptionCoverage, Observation, Protection, Quality},
    platform::{command::ProbeError, AuditPlatform},
    policy::{Policy, SensitiveTarget},
};
use common::{FakePlatform, FixedClock};
use std::cell::RefCell;

fn item(
    id: &str,
    state: Protection,
    tech: Option<&str>,
    mounted: Option<bool>,
    at_rest: Option<bool>,
) -> CoverageItem {
    CoverageItem {
        id: id.into(),
        protection: state,
        technology: tech.map(str::to_owned),
        mounted,
        at_rest,
        source: Some("FIXTURE".into()),
    }
}
fn observed(item: CoverageItem, status: Status) -> Outcome {
    let q = if status == Status::Warn {
        Quality::Inconclusive
    } else {
        Quality::Verified
    };
    Outcome::new(status, Reason::SecurityStateObserved, "fixture").with_observation(
        Observation::EncryptionCoverage(EncryptionCoverage {
            quality: q,
            items: vec![item],
        }),
    )
}
struct Host {
    base: FakePlatform,
    home: Outcome,
    sensitive: Outcome,
    swap: Outcome,
    targets: RefCell<Vec<String>>,
}
impl AuditPlatform for Host {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        self.base.operating_system()
    }
    fn pending_updates(&self) -> Outcome {
        self.base.pending_updates()
    }
    fn root_encryption(&self) -> Outcome {
        self.base.root_encryption()
    }
    fn home_encryption(&self) -> Outcome {
        self.home.clone()
    }
    fn sensitive_encryption(&self, targets: &[SensitiveTarget]) -> Outcome {
        *self.targets.borrow_mut() = targets.iter().filter_map(|t| t.path.clone()).collect();
        self.sensitive.clone()
    }
    fn swap_protection(&self) -> Outcome {
        self.swap.clone()
    }
    fn encryption_discovery(&self) -> Outcome {
        Outcome::new(
            Status::Pass,
            Reason::SecurityStateObserved,
            "Discovery only; not compliance",
        )
    }
}
fn host() -> Host {
    let mut base = common::platform();
    base.root.observation = Some(Observation::RootEncryption({
        let mut r = common::root();
        r.paths[0].luks_protected = false;
        r
    }));
    base.root.status = Status::Fail;
    Host {
        base,
        home: observed(
            item(
                "home",
                Protection::Protected,
                Some("ECRYPTFS"),
                Some(true),
                Some(true),
            ),
            Status::Pass,
        ),
        sensitive: observed(
            item(
                "vault",
                Protection::Protected,
                Some("CRYFS"),
                Some(true),
                Some(true),
            ),
            Status::Pass,
        ),
        swap: observed(
            item(
                "swap-0",
                Protection::Protected,
                Some("ZRAM_VOLATILE"),
                None,
                Some(false),
            ),
            Status::Pass,
        ),
        targets: RefCell::new(vec![]),
    }
}
fn policy() -> Policy {
    Policy::from_json(r#"{"schemaVersion":"baradwatchu.audit-policy.v3","checks":{
      "SEC-001":{"enabled":false},"SEC-006":{"mandatory":false},
      "SEC-007":{"enabled":false},"SEC-012":{"enabled":false},"SEC-013":{"enabled":false},"SEC-014":{"enabled":false},
      "SEC-015":{"mandatory":true},
      "SEC-016":{"targets":[{"id":"vault","path":"/private/secret-vault"}]},
      "SEC-017":{"mandatory":true}
    }}"#).unwrap()
}
fn status(report: &AuditReport, id: &str) -> Option<Status> {
    report
        .policy_evaluation
        .as_ref()
        .unwrap()
        .checks
        .iter()
        .find(|c| c.check_id == id)
        .unwrap()
        .status
}

#[test]
fn independent_scopes_v3_redaction_and_report_roundtrip() {
    let host = host();
    let report = builtin::standalone_with_policy(&host, &FixedClock, &policy()).unwrap();
    assert_eq!(report.schema_version, "baradwatchu.audit-report.v2");
    assert_eq!(status(&report, "SEC-006"), Some(Status::Fail));
    assert_eq!(status(&report, "SEC-015"), Some(Status::Pass));
    assert_eq!(status(&report, "SEC-016"), Some(Status::Pass));
    assert_eq!(status(&report, "SEC-017"), Some(Status::Pass));
    assert_eq!(
        report.policy_evaluation.as_ref().unwrap().overall,
        Status::Pass
    );
    assert_eq!(&*host.targets.borrow(), &["/private/secret-vault"]);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("/private/secret-vault"));
    assert_eq!(serde_json::from_str::<AuditReport>(&json).unwrap(), report);
}

#[test]
fn unrelated_scope_failure_or_uncertainty_does_not_rewrite_other_checks() {
    let mut h = host();
    h.sensitive = observed(
        item("vault", Protection::Inconclusive, None, None, None),
        Status::Warn,
    );
    h.swap = observed(
        item(
            "swap-0",
            Protection::Unprotected,
            Some("PLAINTEXT_BACKING"),
            None,
            Some(false),
        ),
        Status::Fail,
    );
    let r = builtin::standalone_with_policy(&h, &FixedClock, &policy()).unwrap();
    assert_eq!(status(&r, "SEC-015"), Some(Status::Pass));
    assert_eq!(status(&r, "SEC-016"), Some(Status::Warn));
    assert_eq!(status(&r, "SEC-017"), Some(Status::Fail));
    assert_eq!(r.policy_evaluation.unwrap().overall, Status::Fail);
}

#[test]
fn malformed_coverage_cannot_become_policy_pass() {
    let mut h = host();
    h.sensitive = observed(
        item("vault", Protection::Protected, Some("CRYFS"), None, None),
        Status::Pass,
    );
    let r = builtin::standalone_with_policy(&h, &FixedClock, &policy()).unwrap();
    assert_eq!(status(&r, "SEC-016"), Some(Status::Error));
}

#[test]
fn disabled_sensitive_check_does_not_access_paths() {
    let h = host();
    let mut p = policy();
    p.checks.sensitive_encryption.as_mut().unwrap().enabled = false;
    let report = builtin::standalone_with_policy(&h, &FixedClock, &p).unwrap();
    assert!(h.targets.borrow().is_empty());
    assert!(report.results.iter().all(|r| r.check.id != "SEC-016"));
    assert_eq!(status(&report, "SEC-016"), None);
}

#[test]
fn incorrect_target_identifier_is_not_accepted() {
    let mut h = host();
    h.sensitive = observed(
        item(
            "other",
            Protection::Protected,
            Some("CRYFS"),
            Some(true),
            Some(true),
        ),
        Status::Pass,
    );
    let report = builtin::standalone_with_policy(&h, &FixedClock, &policy()).unwrap();
    assert_eq!(status(&report, "SEC-016"), Some(Status::Error));
}

#[test]
fn legacy_policies_reject_new_controls_and_keep_legacy_report() {
    let v1 = Policy::from_json(include_str!("../../../policies/default.json")).unwrap();
    let v2 = Policy::from_json(include_str!("../../../policies/linux-baseline.json")).unwrap();
    assert_eq!(
        builtin::standalone_with_policy(&common::platform(), &FixedClock, &v1)
            .unwrap()
            .schema_version,
        "baradwatchu.audit-report.v1"
    );
    assert_eq!(
        builtin::standalone_with_policy(&common::platform(), &FixedClock, &v2)
            .unwrap()
            .schema_version,
        "baradwatchu.audit-report.v1"
    );
    for version in ["v1", "v2"] {
        let json = format!(
            r#"{{"schemaVersion":"baradwatchu.audit-policy.{version}","checks":{{"SEC-015":{{}}}}}}"#
        );
        assert!(Policy::from_json(&json).is_err());
    }
}

#[test]
fn target_paths_are_bounded_absolute_unique_and_explicit() {
    for target in [
        r#"{"id":"x","path":"relative"}"#,
        r#"{"id":"x","path":"/a/../b"}"#,
        r#"{"id":"x"}"#,
        r#"{"id":"x","path":null}"#,
        r#"{"id":"bad id","path":"/a"}"#,
    ] {
        let json = format!(
            r#"{{"schemaVersion":"baradwatchu.audit-policy.v3","checks":{{"SEC-016":{{"targets":[{target}]}}}}}}"#
        );
        assert!(Policy::from_json(&json).is_err(), "{target}");
    }
    let dup = r#"{"schemaVersion":"baradwatchu.audit-policy.v3","checks":{"SEC-016":{"targets":[{"id":"x","path":"/a"},{"id":"x","path":"/b"}]}}}"#;
    assert!(Policy::from_json(dup).is_err());
}

fn local(json: &str) -> LocalConfig {
    LocalConfig::from_json(json).unwrap()
}

#[test]
fn local_targets_are_additive_and_policy_snapshot_stays_separate() {
    let mut h = host();
    let admin = item("vault", Protection::Inconclusive, None, None, None);
    let extra = item(
        "local-extra",
        Protection::Protected,
        Some("CRYFS"),
        Some(true),
        Some(true),
    );
    h.sensitive = Outcome::new(Status::Warn, Reason::EvidenceInconclusive, "fixture")
        .with_observation(Observation::EncryptionCoverage(EncryptionCoverage {
            quality: Quality::Inconclusive,
            items: vec![admin, extra],
        }));
    let config = local(
        r#"{"schemaVersion":"baradwatchu.local-monitoring.v1","sensitiveTargets":[{"id":"local-extra","path":"/private/local-vault"}]}"#,
    );
    let p = policy();
    let r = builtin::standalone_with_local_config(&h, &FixedClock, &p, Some(&config)).unwrap();
    assert_eq!(status(&r, "SEC-016"), Some(Status::Warn));
    assert_eq!(h.targets.borrow().len(), 2);
    let eval = r.policy_evaluation.as_ref().unwrap();
    assert!(
        eval.checks
            .iter()
            .find(|c| c.check_id == "SEC-016")
            .unwrap()
            .mandatory
    );
    assert_eq!(
        eval.policy
            .checks
            .sensitive_encryption
            .as_ref()
            .unwrap()
            .targets
            .len(),
        1
    );
    assert_eq!(
        eval.local_monitoring.as_ref().unwrap().target_ids,
        ["local-extra"]
    );
    let text = serde_json::to_string(&r).unwrap();
    assert!(!text.contains("/private/secret-vault"));
    assert!(!text.contains("/private/local-vault"));
}

#[test]
fn local_config_cannot_replace_remove_or_disable_policy_targets() {
    let p = policy();
    let duplicate = local(
        r#"{"schemaVersion":"baradwatchu.local-monitoring.v1","sensitiveTargets":[{"id":"vault","path":"/different"}]}"#,
    );
    let h = host();
    assert!(builtin::standalone_with_local_config(&h, &FixedClock, &p, Some(&duplicate)).is_err());
    assert!(h.base.calls.borrow().is_empty());
    assert!(LocalConfig::from_json(
        r#"{"schemaVersion":"baradwatchu.local-monitoring.v1","mandatory":false}"#
    )
    .is_err());
    let empty =
        local(r#"{"schemaVersion":"baradwatchu.local-monitoring.v1","sensitiveTargets":[]}"#);
    let effective = empty.effective_policy(&p).unwrap();
    assert!(
        effective
            .checks
            .sensitive_encryption
            .as_ref()
            .unwrap()
            .mandatory
    );
    assert_eq!(
        effective
            .checks
            .sensitive_encryption
            .as_ref()
            .unwrap()
            .targets,
        p.checks.sensitive_encryption.as_ref().unwrap().targets
    );
    assert!(empty.effective_policy(&Policy::default()).is_err());
    let additional = local(
        r#"{"schemaVersion":"baradwatchu.local-monitoring.v1","sensitiveTargets":[{"id":"extra","path":"/extra"}]}"#,
    );
    let mut disabled = p.clone();
    disabled
        .checks
        .sensitive_encryption
        .as_mut()
        .unwrap()
        .enabled = false;
    assert!(additional.effective_policy(&disabled).is_err());
}

#[test]
fn removed_policy_and_local_config_options_are_rejected() {
    use baradwatchu_agent::cli;
    use std::ffi::OsString;
    let args = vec![
        OsString::from("audit"),
        OsString::from("--policy"),
        OsString::from("policies/encryption-coverage.example.json"),
        OsString::from("--local-config"),
        OsString::from("/nonexistent-baradwatchu-local-config"),
    ];
    let error = cli::run(&args).expect_err("legacy audit options must be rejected");
    assert_eq!(error.code, 2);
}

#[test]
fn discovery_never_satisfies_required_scope_without_targets() {
    let mut p = policy();
    p.checks
        .sensitive_encryption
        .as_mut()
        .unwrap()
        .targets
        .clear();
    let mut h = host();
    h.sensitive = Outcome::new(Status::Warn, Reason::EvidenceInconclusive, "no targets")
        .with_observation(Observation::EncryptionCoverage(EncryptionCoverage {
            quality: Quality::Inconclusive,
            items: vec![],
        }));
    let r = builtin::standalone_with_policy(&h, &FixedClock, &p).unwrap();
    assert!(r
        .results
        .iter()
        .any(|r| r.check.id == "SYS-ENC-001" && r.outcome.status == Status::Pass));
    assert_eq!(status(&r, "SEC-016"), Some(Status::Warn));
    assert_ne!(r.policy_evaluation.unwrap().overall, Status::Pass);
}

#[test]
fn local_targets_without_policy_check_are_informational() {
    let mut p = policy();
    p.checks.sensitive_encryption = None;
    let mut h = host();
    h.sensitive = observed(
        item(
            "local-extra",
            Protection::Protected,
            Some("CRYFS"),
            Some(true),
            Some(true),
        ),
        Status::Pass,
    );
    let config = local(
        r#"{"schemaVersion":"baradwatchu.local-monitoring.v1","sensitiveTargets":[{"id":"local-extra","path":"/private/local"}]}"#,
    );
    let r = builtin::standalone_with_local_config(&h, &FixedClock, &p, Some(&config)).unwrap();
    let eval = r.policy_evaluation.unwrap();
    assert!(
        !eval
            .checks
            .iter()
            .find(|c| c.check_id == "SEC-016")
            .unwrap()
            .mandatory
    );
    assert!(eval.policy.checks.sensitive_encryption.is_none());
}
