use baradwatchu_agent::{
    audit::*,
    checks::builtin,
    platform::{command::ProbeError, AuditPlatform},
};
use serde_json::json;

struct FixedClock;
impl Clock for FixedClock {
    fn now_unix_ms(&self) -> Result<u64, String> {
        Ok(1_800_000_000_123)
    }
}
struct SyntheticCheck(Status);
impl Check for SyntheticCheck {
    fn metadata(&self) -> CheckMetadata {
        CheckMetadata {
            id: "TEST-001".into(),
            name: "Fixture".into(),
            description: "Synthetic test evidence".into(),
            version: "1.0.0".into(),
        }
    }
    fn evaluate(&self) -> Outcome {
        Outcome::new(
            self.0,
            Reason::EncryptionInconclusive,
            "Synthetic observation",
        )
        .with_evidence(Evidence::new(
            "fixture",
            "test only",
            &[("sample", json!(true))],
        ))
    }
}
fn os(supported: bool) -> OperatingSystem {
    let mut os = OperatingSystem::unidentified("linux");
    os.distribution_id = Some(if supported { "fedora" } else { "arch" }.into());
    os.supported = supported;
    os
}

#[test]
fn result_serialization_roundtrip_and_exact_wire_fields() {
    for (status, name) in [
        (Status::Pass, "PASS"),
        (Status::Fail, "FAIL"),
        (Status::Warn, "WARN"),
        (Status::Error, "ERROR"),
        (Status::NotApplicable, "NOT_APPLICABLE"),
    ] {
        let report = run(os(true), &[&SyntheticCheck(status)], &FixedClock).unwrap();
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(value["schemaVersion"], "baradwatchu.audit-report.v1");
        assert_eq!(value["agentVersion"], env!("CARGO_PKG_VERSION"));
        assert_eq!(value["results"][0]["status"], name);
        assert_eq!(
            value["results"][0]["observedAtUnixMs"],
            1_800_000_000_123u64
        );
        assert_eq!(value["results"][0]["check"]["id"], "TEST-001");
        assert_eq!(value["results"][0]["reasonCode"], "ENCRYPTION_INCONCLUSIVE");
        assert_eq!(value["results"][0]["evidence"][0]["values"]["sample"], true);
        assert!(value.get("deviceId").is_none());
        assert!(value.get("policyVersion").is_none());
        let restored: AuditReport = serde_json::from_value(value).unwrap();
        assert_eq!(report, restored);
    }
}

#[test]
fn summary_counts_all_five_states_and_is_order_independent() {
    let checks = [
        SyntheticCheck(Status::Pass),
        SyntheticCheck(Status::Fail),
        SyntheticCheck(Status::Warn),
        SyntheticCheck(Status::Error),
        SyntheticCheck(Status::NotApplicable),
    ];
    let refs: Vec<&dyn Check> = checks.iter().map(|c| c as &dyn Check).collect();
    let report = run(os(true), &refs, &FixedClock).unwrap();
    assert_eq!(
        report.summary,
        Summary {
            total: 5,
            pass: 1,
            fail: 1,
            warn: 1,
            error: 1,
            not_applicable: 1
        }
    );
    assert_eq!(report.overall, Status::Error);
    let mut reversed = report.results;
    reversed.reverse();
    assert_eq!(report.summary, Summary::from_results(&reversed));
}

#[test]
fn outcome_precedence_and_cli_codes() {
    for (statuses, overall, code) in [
        (vec![Status::Pass], Status::Pass, 0),
        (vec![Status::Pass, Status::Fail], Status::Fail, 3),
        (vec![Status::Fail, Status::Error], Status::Error, 1),
        (vec![Status::Warn], Status::Warn, 4),
        (vec![Status::NotApplicable], Status::Warn, 4),
        (vec![Status::Pass, Status::NotApplicable], Status::Warn, 4),
        (vec![], Status::Warn, 4),
    ] {
        let checks: Vec<_> = statuses.into_iter().map(SyntheticCheck).collect();
        let refs: Vec<&dyn Check> = checks.iter().map(|c| c as &dyn Check).collect();
        let report = run(os(true), &refs, &FixedClock).unwrap();
        assert_eq!(report.overall, overall);
        assert_eq!(report.exit_code(), code);
    }
}

struct Unsupported;
impl AuditPlatform for Unsupported {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        Ok(os(false))
    }
    fn pending_updates(&self) -> Outcome {
        panic!("Fedora probes must not run on unsupported OS")
    }
    fn root_encryption(&self) -> Outcome {
        panic!("Fedora probes must not run on unsupported OS")
    }
}
#[test]
fn unsupported_os_has_identity_but_no_fedora_probes_or_overall_pass() {
    let report = builtin::standalone(&Unsupported, &FixedClock).unwrap();
    assert_eq!(report.summary.pass, 1);
    assert_eq!(report.summary.not_applicable, 2);
    assert_eq!(report.overall, Status::Warn);
    assert_eq!(report.exit_code(), 4);
    assert_eq!(
        report
            .results
            .iter()
            .map(|r| r.check.id.as_str())
            .collect::<Vec<_>>(),
        ["SYS-OS-001", "SEC-001", "SEC-006"]
    );
    assert_eq!(
        serde_json::to_string(&report).unwrap(),
        serde_json::to_string(&builtin::standalone(&Unsupported, &FixedClock).unwrap()).unwrap()
    );
    assert!(report.human_readable().contains("NOT_APPLICABLE"));
    assert!(report.human_readable().contains("Evidence:"));
}
struct Unidentified;
impl AuditPlatform for Unidentified {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        Err(ProbeError::new(
            Reason::PermissionDenied,
            "Fixture permission error",
        ))
    }
    fn pending_updates(&self) -> Outcome {
        panic!("must not run")
    }
    fn root_encryption(&self) -> Outcome {
        panic!("must not run")
    }
}
#[test]
fn os_detection_error_is_not_unsupported_or_pass() {
    let report = builtin::standalone(&Unidentified, &FixedClock).unwrap();
    assert_eq!(report.summary.error, 3);
    assert_eq!(report.exit_code(), 1);
    assert_eq!(
        report.results[0].outcome.reason_code,
        Reason::PermissionDenied
    );
    assert_eq!(
        report.results[1].outcome.reason_code,
        Reason::OsIdentityUnavailable
    );
}
#[test]
fn clock_failure_aborts_instead_of_inventing_timestamp() {
    struct BadClock;
    impl Clock for BadClock {
        fn now_unix_ms(&self) -> Result<u64, String> {
            Err("invalid clock".into())
        }
    }
    assert!(builtin::standalone(&Unsupported, &BadClock).is_err());
}
