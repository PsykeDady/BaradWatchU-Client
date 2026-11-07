mod common;
use baradwatchu_agent::{
    audit::{AuditReport, OperatingSystem, Outcome, Reason, Status},
    checks::builtin,
    observation::*,
    platform::{command::ProbeError, AuditPlatform},
    policy::*,
};
use common::{FixedClock, NOW};
use std::cell::RefCell;

struct Host {
    os: OperatingSystem,
    states: RefCell<[Outcome; 4]>,
    calls: RefCell<Vec<&'static str>>,
}
fn observation(f: Observation) -> Outcome {
    Outcome::new(Status::Pass, Reason::SecurityStateObserved, "fixture").with_observation(f)
}
fn host(id: &str) -> Host {
    let mut os = common::platform().os;
    os.distribution_id = Some(id.into());
    Host {
        os,
        states: RefCell::new([
            observation(Observation::ScreenLock(ScreenLock {
                quality: Quality::Verified,
                session_scope: "CURRENT_USER_SINGLE_PLASMA6_WAYLAND_SESSION_CONFIGURATION".into(),
                capability: Some(true),
                configuration_enabled: Some(true),
                automatic_lock: Some(true),
                idle_timeout_seconds: Some(240),
                grace_seconds: Some(5),
                password_required: Some(true),
                lock_on_resume: Some(true),
                current_screen_saver_active: Some(false),
            })),
            observation(Observation::Tpm(Tpm {
                quality: Quality::Verified,
                devices: vec![TpmDevice {
                    version_major: Some(2),
                    character_device_verified: true,
                    read_permission: Some(true),
                }],
            })),
            observation(Observation::SecureBoot(SecureBoot {
                quality: Quality::Verified,
                state: BootState::Enabled,
                secure_boot: Some(true),
                setup_mode: Some(false),
            })),
            observation(Observation::Firewall(Firewall {
                quality: Quality::Verified,
                managers: ["firewalld", "nftables", "ufw", "iptables", "ip6tables"]
                    .iter()
                    .map(|n| FirewallManager {
                        name: (*n).into(),
                        installed: Some(false),
                        active: Some(false),
                        running: Some(false),
                    })
                    .collect(),
                filtering: Filtering::VerifiedInputFiltering,
                ipv4_verified: true,
                ipv6_verified: true,
                multiple_managers: false,
            })),
        ]),
        calls: RefCell::new(vec![]),
    }
}
impl Host {
    fn state(&self, i: usize, label: &'static str) -> Outcome {
        self.calls.borrow_mut().push(label);
        self.states.borrow()[i].clone()
    }
}
impl AuditPlatform for Host {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        self.calls.borrow_mut().push("os");
        Ok(self.os.clone())
    }
    fn pending_updates(&self) -> Outcome {
        self.calls.borrow_mut().push("updates");
        common::platform().updates
    }
    fn root_encryption(&self) -> Outcome {
        self.calls.borrow_mut().push("root");
        common::platform().root
    }
    fn screen_lock(&self) -> Outcome {
        self.state(0, "screen")
    }
    fn tpm(&self) -> Outcome {
        self.state(1, "tpm")
    }
    fn secure_boot(&self) -> Outcome {
        self.state(2, "boot")
    }
    fn firewall(&self) -> Outcome {
        self.state(3, "firewall")
    }
}
fn raw() -> AuditReport {
    builtin::standalone_with_policy(&host("arch"), &FixedClock, &Policy::linux_baseline()).unwrap()
}
fn quality(f: &mut Observation, q: Quality) {
    match f {
        Observation::ScreenLock(f) => f.quality = q,
        Observation::Tpm(f) => f.quality = q,
        Observation::SecureBoot(f) => f.quality = q,
        Observation::Firewall(f) => f.quality = q,
        _ => panic!(),
    }
}

#[test]
fn tpm_v2_requires_verified_presence_and_accessibility() {
    let policy = Policy::linux_baseline();
    for (version, verified, permission, quality, expected) in [
        (Some(2), true, Some(true), Quality::Verified, Status::Pass),
        (Some(1), true, Some(true), Quality::Verified, Status::Fail),
        (
            Some(2),
            true,
            Some(false),
            Quality::Inconclusive,
            Status::Warn,
        ),
        (Some(2), true, None, Quality::Inconclusive, Status::Warn),
        (None, true, Some(true), Quality::Inconclusive, Status::Warn),
        (Some(2), false, None, Quality::Inconclusive, Status::Warn),
    ] {
        let mut report = raw();
        let Some(Observation::Tpm(tpm)) = report.results[4].outcome.observation.as_mut() else {
            panic!()
        };
        tpm.quality = quality;
        tpm.devices[0] = TpmDevice {
            version_major: version,
            character_device_verified: verified,
            read_permission: permission,
        };
        assert_eq!(
            evaluate(&policy, &report).unwrap().checks[3].status,
            Some(expected)
        );
    }
}
fn negative(f: &mut Observation) {
    match f {
        Observation::ScreenLock(f) => f.automatic_lock = Some(false),
        Observation::Tpm(f) => f.devices[0].version_major = Some(1),
        Observation::SecureBoot(f) => {
            f.state = BootState::Disabled;
            f.secure_boot = Some(false)
        }
        Observation::Firewall(f) => {
            f.filtering = Filtering::NoFilteringInInspectedInputBackends;
            f.ipv4_verified = false;
            f.ipv6_verified = false
        }
        _ => panic!(),
    }
}

#[test]
fn explicit_v2_sample_and_omitted_fields_are_strict_and_v1_stays_legacy() {
    assert_eq!(
        Policy::from_json(include_str!("../../../policies/linux-baseline.json")).unwrap(),
        Policy::linux_baseline()
    );
    let p = Policy::from_json(r#"{"schemaVersion":"baradwatchu.audit-policy.v2"}"#).unwrap();
    assert!(p.checks.firewall.as_ref().unwrap().required);
    assert_eq!(
        p.checks.screen_lock.as_ref().unwrap().max_timeout_seconds,
        300
    );
    let v1 = Policy::from_json(include_str!("../../../policies/default.json")).unwrap();
    assert_eq!(v1, Policy::default());
    assert!(!serde_json::to_string(&v1).unwrap().contains("SEC-007"));
    for id in ["SEC-007", "SEC-012", "SEC-013", "SEC-014"] {
        for value in [serde_json::json!({}), serde_json::Value::Null] {
            let mut j = serde_json::to_value(&v1).unwrap();
            j["checks"][id] = value;
            assert!(Policy::from_json(&j.to_string()).is_err());
        }
    }
}
#[test]
fn v2_rejects_null_unknown_duplicate_and_invalid_settings() {
    for id in ["SEC-007", "SEC-012", "SEC-013", "SEC-014"] {
        for v in [
            serde_json::Value::Null,
            serde_json::json!({"typo":true}),
            serde_json::json!({"required":"yes"}),
            serde_json::json!({"maxObservationAgeSeconds":0}),
            serde_json::json!({"evidence":{"inconclusive":"PASS"}}),
        ] {
            let mut j = serde_json::to_value(Policy::linux_baseline()).unwrap();
            j["checks"][id] = v;
            assert!(Policy::from_json(&j.to_string()).is_err(), "{id}");
        }
    }
    for v in [
        serde_json::json!({"maxTimeoutSeconds":0}),
        serde_json::json!({"maxTimeoutSeconds":-1}),
        serde_json::json!({"required":false,"requireLockOnResume":true}),
    ] {
        let mut j = serde_json::to_value(Policy::linux_baseline()).unwrap();
        j["checks"]["SEC-007"] = v;
        assert!(Policy::from_json(&j.to_string()).is_err());
    }
    assert!(Policy::from_json(r#"{"schemaVersion":"baradwatchu.audit-policy.v2","checks":{"SEC-013":{"required":true,"required":false}}}"#).is_err());
}
#[test]
fn same_shared_check_dispatch_for_arch_and_fedora() {
    for id in ["arch", "fedora"] {
        let h = host(id);
        let r =
            builtin::standalone_with_policy(&h, &FixedClock, &Policy::linux_baseline()).unwrap();
        assert_eq!(
            *h.calls.borrow(),
            ["os", "updates", "root", "screen", "tpm", "boot", "firewall"]
        );
        assert_eq!(
            r.results
                .iter()
                .map(|r| r.check.id.as_str())
                .collect::<Vec<_>>(),
            [
                "SYS-OS-001",
                "SEC-001",
                "SEC-006",
                "SEC-007",
                "SEC-012",
                "SEC-013",
                "SEC-014"
            ]
        );
        assert_eq!(r.policy_evaluation.unwrap().overall, Status::Pass);
    }
}
#[test]
fn v1_keeps_three_results_and_disabled_v2_controls_execute_no_probes() {
    let h = host("arch");
    assert_eq!(
        builtin::standalone_with_policy(&h, &FixedClock, &Policy::default())
            .unwrap()
            .results
            .len(),
        3
    );
    assert_eq!(*h.calls.borrow(), ["os", "updates", "root"]);
    let mut p = Policy::linux_baseline();
    p.checks.screen_lock.as_mut().unwrap().enabled = false;
    p.checks.tpm.as_mut().unwrap().enabled = false;
    p.checks.secure_boot.as_mut().unwrap().enabled = false;
    p.checks.firewall.as_mut().unwrap().enabled = false;
    let h = host("arch");
    let r = builtin::standalone_with_policy(&h, &FixedClock, &p).unwrap();
    assert_eq!(*h.calls.borrow(), ["os", "updates", "root"]);
    let e = r.policy_evaluation.unwrap();
    assert_eq!(e.summary.disabled, 4);
    assert!(e.checks[2..].iter().all(|c| c.status.is_none()));
}
#[test]
fn unsupported_distribution_never_runs_new_probes() {
    let mut h = host("manjaro");
    h.os.supported = false;
    let r = builtin::standalone_with_policy(&h, &FixedClock, &Policy::linux_baseline()).unwrap();
    assert_eq!(*h.calls.borrow(), ["os"]);
    assert_eq!(r.exit_code(), 4);
    assert!(r.results[1..]
        .iter()
        .all(|r| r.outcome.status == Status::NotApplicable));
    let mut p = Policy::linux_baseline();
    p.checks.screen_lock.as_mut().unwrap().evidence.unsupported = Uncertain::Fail;
    for c in [
        &mut p.checks.tpm,
        &mut p.checks.secure_boot,
        &mut p.checks.firewall,
    ] {
        c.as_mut().unwrap().evidence.unsupported = Uncertain::Fail;
    }
    let e = evaluate(&p, &r).unwrap();
    assert!(e.checks[2..].iter().all(|c| c.status == Some(Status::Fail)));
}
#[test]
fn mandatory_and_informational_new_checks_have_distinct_gating_without_evidence_changes() {
    for i in 3..7 {
        let mut r = raw();
        negative(r.results[i].outcome.observation.as_mut().unwrap());
        let before = serde_json::to_string(&r).unwrap();
        let mut p = Policy::linux_baseline();
        assert_eq!(evaluate(&p, &r).unwrap().overall, Status::Fail);
        p.checks.screen_lock.as_mut().unwrap().mandatory = false;
        p.checks.tpm.as_mut().unwrap().mandatory = false;
        p.checks.secure_boot.as_mut().unwrap().mandatory = false;
        p.checks.firewall.as_mut().unwrap().mandatory = false;
        let e = evaluate(&p, &r).unwrap();
        assert_eq!(e.overall, Status::Pass);
        assert_eq!(e.checks[i - 1].status, Some(Status::Fail));
        r.results[i].outcome.status = Status::Error;
        assert_eq!(evaluate(&p, &r).unwrap().overall, Status::Pass);
        r.results[i].outcome.status = Status::Pass;
        assert_eq!(serde_json::to_string(&r).unwrap(), before);
    }
}
#[test]
fn missing_restricted_stale_unsupported_and_inconclusive_never_pass() {
    for i in 3..7 {
        for q in [
            Quality::Missing,
            Quality::Restricted,
            Quality::Unsupported,
            Quality::Inconclusive,
        ] {
            let mut r = raw();
            quality(r.results[i].outcome.observation.as_mut().unwrap(), q);
            assert_eq!(
                evaluate(&Policy::linux_baseline(), &r).unwrap().checks[i - 1].status,
                Some(Status::Warn)
            );
        }
        let mut r = raw();
        r.results[i].observed_at_unix_ms = (NOW - 301) * 1000;
        assert_eq!(
            evaluate(&Policy::linux_baseline(), &r).unwrap().checks[i - 1].status,
            Some(Status::Warn)
        );
        r.results[i].outcome.observation = None;
        assert_ne!(
            evaluate(&Policy::linux_baseline(), &r).unwrap().checks[i - 1].status,
            Some(Status::Pass)
        );
    }
}
#[test]
fn configured_uncertainty_and_execution_errors_stay_strict() {
    for (action, status) in [
        (Uncertain::Warn, Status::Warn),
        (Uncertain::Fail, Status::Fail),
        (Uncertain::Error, Status::Error),
    ] {
        let mut p = Policy::linux_baseline();
        p.checks.screen_lock.as_mut().unwrap().evidence.inconclusive = action;
        for c in [
            &mut p.checks.tpm,
            &mut p.checks.secure_boot,
            &mut p.checks.firewall,
        ] {
            c.as_mut().unwrap().evidence.inconclusive = action;
        }
        for i in 3..7 {
            let mut r = raw();
            quality(
                r.results[i].outcome.observation.as_mut().unwrap(),
                Quality::Inconclusive,
            );
            assert_eq!(evaluate(&p, &r).unwrap().checks[i - 1].status, Some(status));
            r.results[i].outcome.status = Status::Error;
            assert_eq!(
                evaluate(&p, &r).unwrap().checks[i - 1].status,
                Some(Status::Error)
            );
        }
    }
}
#[test]
fn not_required_permits_only_known_states_and_does_not_mutate_observations() {
    let mut p = Policy::linux_baseline();
    p.checks.screen_lock.as_mut().unwrap().required = false;
    for c in [
        &mut p.checks.tpm,
        &mut p.checks.secure_boot,
        &mut p.checks.firewall,
    ] {
        c.as_mut().unwrap().required = false;
    }
    for i in 3..7 {
        let mut r = raw();
        negative(r.results[i].outcome.observation.as_mut().unwrap());
        let before = serde_json::to_value(&r).unwrap();
        assert_eq!(evaluate(&p, &r).unwrap().overall, Status::Pass);
        assert_eq!(serde_json::to_value(&r).unwrap(), before);
        quality(
            r.results[i].outcome.observation.as_mut().unwrap(),
            Quality::Inconclusive,
        );
        assert_ne!(evaluate(&p, &r).unwrap().overall, Status::Pass);
    }
}
#[test]
fn timeout_counts_password_grace_and_optional_resume_requirement() {
    let mut p = Policy::linux_baseline();
    let mut r = raw();
    let Some(Observation::ScreenLock(f)) = &mut r.results[3].outcome.observation else {
        panic!()
    };
    f.idle_timeout_seconds = Some(300);
    f.grace_seconds = Some(5);
    f.lock_on_resume = Some(false);
    assert_eq!(evaluate(&p, &r).unwrap().overall, Status::Fail);
    p.checks.screen_lock.as_mut().unwrap().max_timeout_seconds = 305;
    assert_eq!(evaluate(&p, &r).unwrap().overall, Status::Pass);
    p.checks
        .screen_lock
        .as_mut()
        .unwrap()
        .require_lock_on_resume = true;
    assert_eq!(evaluate(&p, &r).unwrap().overall, Status::Fail);
}

#[test]
fn immediate_password_is_optional_and_independent_of_total_timeout() {
    for enabled in [false, true] {
        for grace in [0, 5] {
            let mut p = Policy::linux_baseline();
            p.checks
                .screen_lock
                .as_mut()
                .unwrap()
                .require_immediate_password = enabled;
            let mut r = raw();
            let Some(Observation::ScreenLock(f)) = &mut r.results[3].outcome.observation else {
                panic!()
            };
            f.idle_timeout_seconds = Some(240);
            f.grace_seconds = Some(grace);
            let before = serde_json::to_value(&r).unwrap();
            let e = evaluate(&p, &r).unwrap();
            assert_eq!(
                e.checks[2].status,
                Some(if enabled && grace != 0 {
                    Status::Fail
                } else {
                    Status::Pass
                })
            );
            assert_eq!(
                e.checks[2]
                    .reasons
                    .contains(&"IMMEDIATE_PASSWORD_REQUIRED".into()),
                enabled && grace != 0
            );
            assert_eq!(serde_json::to_value(&r).unwrap(), before);
        }
    }
}

#[test]
fn immediate_password_does_not_override_inconclusive_or_missing_evidence() {
    let mut p = Policy::linux_baseline();
    p.checks
        .screen_lock
        .as_mut()
        .unwrap()
        .require_immediate_password = true;
    for q in [
        Quality::Missing,
        Quality::Inconclusive,
        Quality::Restricted,
        Quality::Unsupported,
    ] {
        let mut r = raw();
        quality(r.results[3].outcome.observation.as_mut().unwrap(), q);
        assert_eq!(
            evaluate(&p, &r).unwrap().checks[2].status,
            Some(Status::Warn)
        );
    }
    let mut r = raw();
    let Some(Observation::ScreenLock(f)) = &mut r.results[3].outcome.observation else {
        panic!()
    };
    f.grace_seconds = None;
    assert_eq!(
        evaluate(&p, &r).unwrap().checks[2].status,
        Some(Status::Error)
    );
}

#[test]
fn v2_optional_immediate_field_preserves_existing_v1_v2_and_serialization() {
    let original =
        Policy::from_json(include_str!("../../../policies/linux-baseline.json")).unwrap();
    assert!(
        !original
            .checks
            .screen_lock
            .as_ref()
            .unwrap()
            .require_immediate_password
    );
    assert!(!serde_json::to_string(&original)
        .unwrap()
        .contains("requireImmediatePassword"));
    for value in [false, true] {
        let mut j = serde_json::to_value(&original).unwrap();
        j["checks"]["SEC-007"]["requireImmediatePassword"] = serde_json::json!(value);
        let p = Policy::from_json(&j.to_string()).unwrap();
        assert_eq!(
            p.checks
                .screen_lock
                .as_ref()
                .unwrap()
                .require_immediate_password,
            value
        );
        let serialized = serde_json::to_string(&p).unwrap();
        assert_eq!(serialized.contains("requireImmediatePassword"), value);
        assert_eq!(Policy::from_json(&serialized).unwrap(), p);
    }
    assert_eq!(
        Policy::from_json(include_str!("../../../policies/default.json")).unwrap(),
        Policy::default()
    );
}

#[test]
fn invalid_or_contradictory_immediate_password_policies_are_rejected() {
    for value in [
        serde_json::Value::Null,
        serde_json::json!("true"),
        serde_json::json!(1),
    ] {
        let mut j = serde_json::to_value(Policy::linux_baseline()).unwrap();
        j["checks"]["SEC-007"]["requireImmediatePassword"] = value;
        assert!(Policy::from_json(&j.to_string()).is_err());
    }
    let mut p = Policy::linux_baseline();
    p.checks.screen_lock.as_mut().unwrap().required = false;
    p.checks
        .screen_lock
        .as_mut()
        .unwrap()
        .require_immediate_password = true;
    assert!(p.validate().is_err());
}

#[test]
fn immediate_password_informational_failure_remains_visible_without_gating() {
    let mut p = Policy::linux_baseline();
    let screen = p.checks.screen_lock.as_mut().unwrap();
    screen.require_immediate_password = true;
    screen.mandatory = false;
    let e = evaluate(&p, &raw()).unwrap();
    assert_eq!(e.overall, Status::Pass);
    assert_eq!(e.checks[2].status, Some(Status::Fail));
}
#[test]
fn verified_but_inconsistent_typed_facts_are_rejected() {
    for i in 3..7 {
        let mut r = raw();
        match r.results[i].outcome.observation.as_mut().unwrap() {
            Observation::ScreenLock(f) => f.idle_timeout_seconds = Some(0),
            Observation::Tpm(f) => f.devices[0].read_permission = None,
            Observation::SecureBoot(f) => f.setup_mode = Some(true),
            Observation::Firewall(f) => f.ipv6_verified = false,
            _ => panic!(),
        }
        assert_eq!(
            evaluate(&Policy::linux_baseline(), &r).unwrap().checks[i - 1].status,
            Some(Status::Error)
        );
    }
}
#[test]
fn headless_is_na_and_not_a_successful_mandatory_security_certification() {
    let mut r = raw();
    quality(
        r.results[3].outcome.observation.as_mut().unwrap(),
        Quality::NotApplicable,
    );
    r.results[3].outcome.status = Status::NotApplicable;
    let e = evaluate(&Policy::linux_baseline(), &r).unwrap();
    assert_eq!(e.checks[2].status, Some(Status::NotApplicable));
    assert_eq!(e.overall, Status::NotApplicable);
    r.policy_evaluation = Some(e);
    assert_eq!(r.exit_code(), 4);
}
#[test]
fn all_new_kinds_roundtrip_without_changing_report_schema_or_exit_codes() {
    let mut r = raw();
    let json = serde_json::to_value(&r).unwrap();
    assert_eq!(json["schemaVersion"], "baradwatchu.audit-report.v1");
    assert_eq!(
        json["policyEvaluation"]["schemaVersion"],
        "baradwatchu.policy-evaluation.v1"
    );
    for (i, kind) in [
        (3, "SCREEN_LOCK"),
        (4, "TPM"),
        (5, "SECURE_BOOT"),
        (6, "FIREWALL"),
    ] {
        assert_eq!(json["results"][i]["observation"]["kind"], kind);
    }
    assert_eq!(serde_json::from_value::<AuditReport>(json).unwrap(), r);
    for (status, code) in [
        (Status::Pass, 0),
        (Status::Error, 1),
        (Status::Fail, 3),
        (Status::Warn, 4),
        (Status::NotApplicable, 4),
    ] {
        r.policy_evaluation.as_mut().unwrap().overall = status;
        assert_eq!(r.exit_code(), code);
    }
}
