#![cfg(target_os = "linux")]
mod baseline_common;
mod common;
use baradwatchu_agent::{
    audit::{AuditReport, OperatingSystem, Outcome, Status},
    checks::builtin,
    observation::*,
    platform::{
        command::ProbeError,
        linux::baseline::{
            files::{Files, Node},
            password_aging, password_pam,
        },
        AuditPlatform,
    },
    policy::{evaluate, Policy},
};
use baseline_common::{host, out, Fs, Runner};
use std::{cell::Cell, collections::BTreeMap};

const SAMPLE: &str = include_str!("../../../policies/password-baseline.example.json");
const QUALITY: &str = "minlen = 14\nminclass = 4\nucredit = -1\nlcredit = -1\ndcredit = -1\nocredit = -1\nenforcing = 1\nenforce_for_root\n";
const STACK: &str = "password requisite pam_pwquality.so retry=3\npassword sufficient pam_unix.so use_authtok yescrypt shadow\npassword required pam_deny.so\n";
fn listing(min: i64, max: i64, warn: i64, expires: &str) -> String {
    format!("Last password change : 2026-10-01\nPassword expires : {expires}\nPassword inactive : never\nAccount expires : never\nMinimum number of days between password change : {min}\nMaximum number of days between password change : {max}\nNumber of days of warning before password expires : {warn}\n")
}
fn accounts() -> Fs {
    let mut fs = Fs::default();
    fs.text(
        "/etc/login.defs",
        "UID_MIN 1000\nUID_MAX 60000\nPASS_MAX_DAYS 99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n",
    );
    fs.text("/etc/shells", "/bin/bash\n/bin/zsh\n/usr/bin/nologin\n");
    fs.text("/etc/nsswitch.conf", "passwd: files systemd sss\n");
    fs.text("/etc/passwd", "root:x:0:0:private root:/root:/bin/bash\nprivate-person:x:1000:1000:personal detail:/home/private:/bin/bash\nservice:x:999:999::/srv:/bin/bash\ndaemon:x:1001:1001::/srv:/usr/bin/nologin\n");
    fs
}
fn pam(stack: &str) -> Fs {
    let mut fs = Fs::default();
    fs.directories.insert(
        "/etc/pam.d".into(),
        Ok(Some(vec!["passwd".into(), "system-auth".into()])),
    );
    fs.text("/etc/pam.d/passwd", "password include system-auth\n");
    fs.text("/etc/pam.d/system-auth", stack);
    fs.text("/etc/security/pwquality.conf", QUALITY);
    fs
}
fn aging(fs: &Fs, output: &str) -> Outcome {
    password_aging::observe(fs, &Runner::new(vec![out(output)]), &host())
}
fn complexity(fs: &dyn Files) -> Outcome {
    password_pam::observe(fs, &host())
}
fn a_facts(o: &Outcome) -> &PasswordAging {
    let Some(Observation::PasswordAging(f)) = &o.observation else {
        panic!()
    };
    f
}
fn p_facts(o: &Outcome) -> &PasswordComplexity {
    let Some(Observation::PasswordComplexity(f)) = &o.observation else {
        panic!()
    };
    f
}
struct Fixture {
    aging: Outcome,
    pam: Outcome,
    calls: Cell<usize>,
    os: OperatingSystem,
}
impl AuditPlatform for Fixture {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        Ok(self.os.clone())
    }
    fn pending_updates(&self) -> Outcome {
        common::platform().updates
    }
    fn root_encryption(&self) -> Outcome {
        common::platform().root
    }
    fn password_aging(&self) -> Outcome {
        self.calls.set(self.calls.get() + 1);
        self.aging.clone()
    }
    fn password_complexity(&self) -> Outcome {
        self.calls.set(self.calls.get() + 1);
        self.pam.clone()
    }
}
fn fixture(a: Outcome, p: Outcome) -> Fixture {
    Fixture {
        aging: a,
        pam: p,
        calls: Cell::new(0),
        os: common::platform().os,
    }
}
fn report(a: Outcome, p: Outcome) -> AuditReport {
    builtin::standalone_with_policy(
        &fixture(a, p),
        &common::FixedClock,
        &Policy::from_json(SAMPLE).unwrap(),
    )
    .unwrap()
}
fn statuses(r: &AuditReport) -> BTreeMap<String, Status> {
    r.policy_evaluation
        .as_ref()
        .unwrap()
        .checks
        .iter()
        .filter_map(|c| c.status.map(|s| (c.check_id.clone(), s)))
        .collect()
}
fn good_a() -> Outcome {
    aging(&accounts(), &listing(1, 60, 10, "2026-11-30"))
}
fn good_p() -> Outcome {
    complexity(&pam(STACK))
}

#[test]
fn effective_aging_is_not_creation_defaults() {
    let o = good_a();
    let f = a_facts(&o);
    assert_eq!(f.creation_defaults.maximum_days, Some(99999));
    assert_eq!(f.accounts[0].values.maximum_days, Some(60));
    assert_eq!(f.accounts[0].values.warning_days, Some(10));
    assert_eq!(f.excluded_accounts, 3);
    assert_eq!(f.external_authority_configured, Some(true));
    assert_eq!(statuses(&report(o, good_p()))["SEC-008"], Status::Pass);
}
#[test]
fn local_selection_and_guard_never_query_external_or_system_accounts() {
    let fs = accounts();
    let runner = Runner::new(vec![out(&listing(1, 60, 10, "2026-11-30"))]);
    password_aging::observe(&fs, &runner, &host());
    let calls = runner.calls.borrow();
    assert_eq!(calls.len(), 1);
    assert!(calls[0].read_only_filesystem);
    assert!(!calls[0].allow_null_device);
    assert_eq!(
        calls[0].args,
        vec!["--list", "--iso8601", "--", "private-person"]
    );
    assert!(!fs.calls.borrow().iter().any(|s| s.contains("shadow")));
}
#[test]
fn report_redacts_account_data_and_raw_output() {
    let r = report(good_a(), good_p());
    let text = serde_json::to_string(&r).unwrap();
    for secret in [
        "private-person",
        "personal detail",
        "/home/private",
        "2026-10-01",
        "Last password change",
        "system-auth",
    ] {
        assert!(!text.contains(secret), "{secret}");
    }
}
#[test]
fn full_audit_arch_and_fedora_integrate_all_three_controls() {
    for id in ["arch", "fedora"] {
        let mut f = fixture(good_a(), good_p());
        f.os.distribution_id = Some(id.into());
        let r = builtin::standalone_with_policy(
            &f,
            &common::FixedClock,
            &Policy::from_json(SAMPLE).unwrap(),
        )
        .unwrap();
        assert_eq!(f.calls.get(), 2);
        assert_eq!(r.schema_version, "baradwatchu.audit-report.v2");
        for id in ["SEC-008", "SEC-009", "SEC-010"] {
            assert_eq!(statuses(&r)[id], Status::Pass);
            assert!(r.results.iter().any(|r| r.check.id == id));
        }
    }
}
#[test]
fn never_expiring_password_fails_both_account_criteria() {
    for max in [-1, 99999] {
        let r = report(aging(&accounts(), &listing(0, max, 10, "never")), good_p());
        assert_eq!(statuses(&r)["SEC-008"], Status::Fail);
        assert_eq!(statuses(&r)["SEC-009"], Status::Fail);
    }
}
#[test]
fn warning_default_is_ten_days_and_policy_is_configurable() {
    let r = report(
        aging(&accounts(), &listing(1, 60, 7, "2026-11-30")),
        good_p(),
    );
    assert_eq!(statuses(&r)["SEC-009"], Status::Fail);
    let mut p = Policy::from_json(SAMPLE).unwrap();
    p.checks.password_warning.as_mut().unwrap().minimum_days = 7;
    let e = evaluate(&p, &r).unwrap();
    assert_eq!(
        e.checks
            .iter()
            .find(|c| c.check_id == "SEC-009")
            .unwrap()
            .status,
        Some(Status::Pass)
    );
}
#[test]
fn minimum_and_maximum_aging_independently_enforced() {
    for (min, max) in [(0, 60), (1, 61)] {
        assert_eq!(
            statuses(&report(
                aging(&accounts(), &listing(min, max, 10, "2026-11-30")),
                good_p()
            ))["SEC-008"],
            Status::Fail
        );
    }
}
#[test]
fn insufficient_privileges_warn_without_retry_or_raw_diagnostics() {
    let runner = Runner::new(vec![Err(ProbeError::new(
        baradwatchu_agent::audit::Reason::PermissionDenied,
        "private raw error",
    ))]);
    let o = password_aging::observe(&accounts(), &runner, &host());
    assert_eq!(runner.calls.borrow().len(), 1);
    assert_eq!(
        statuses(&report(o.clone(), good_p()))["SEC-008"],
        Status::Warn
    );
    assert!(!serde_json::to_string(&o)
        .unwrap()
        .contains("private raw error"));
}
#[test]
fn incomplete_duplicate_and_unexpected_chage_formats_warn() {
    let valid = listing(1, 60, 10, "2026-11-30");
    for s in [
        "garbage".to_string(),
        valid.replace("Maximum number of days between password change : 60\n", ""),
        format!("{valid}Last password change : never\n"),
        valid.replace("2026-11-30", "2026-02-31"),
        valid.replace("2026-10-01", "Oct 01, 2026"),
    ] {
        assert_eq!(
            statuses(&report(aging(&accounts(), &s), good_p()))["SEC-008"],
            Status::Warn
        );
    }
}
#[test]
fn empty_scope_is_not_pass() {
    let mut fs = accounts();
    fs.text("/etc/passwd", "root:x:0:0::/root:/bin/bash\n");
    let o = password_aging::observe(&fs, &Runner::new(vec![]), &host());
    assert_eq!(statuses(&report(o, good_p()))["SEC-009"], Status::Warn);
}
#[test]
fn missing_selection_metadata_never_queries_accounts() {
    let mut fs = accounts();
    fs.reads.remove("/etc/shells");
    let o = password_aging::observe(&fs, &Runner::new(vec![]), &host());
    assert_eq!(a_facts(&o).quality, Quality::Inconclusive);
}
#[test]
fn all_selected_accounts_are_evaluated() {
    let mut fs = accounts();
    fs.text(
        "/etc/passwd",
        "one:x:1000:1000::/home/one:/bin/bash\ntwo:x:1001:1001::/home/two:/bin/bash\n",
    );
    let runner = Runner::new(vec![
        out(&listing(1, 60, 10, "2026-11-30")),
        out(&listing(1, 90, 10, "2026-12-30")),
    ]);
    let r = report(password_aging::observe(&fs, &runner, &host()), good_p());
    assert_eq!(statuses(&r)["SEC-008"], Status::Fail);
}
#[test]
fn container_gate_skips_all_credential_sources() {
    let fs = Fs::default();
    let mut env = host();
    env.kind = baradwatchu_agent::platform::linux::environment::Kind::Container;
    let a = password_aging::observe(&fs, &Runner::new(vec![]), &env);
    let p = password_pam::observe(&fs, &env);
    assert!(fs.calls.borrow().is_empty());
    assert_eq!(a_facts(&a).quality, Quality::Restricted);
    assert_eq!(p_facts(&p).quality, Quality::Restricted);
}
#[test]
fn arch_include_and_fedora_substack_wrapper_prove_gate() {
    let mut fs = pam(STACK);
    assert!(p_facts(&complexity(&fs))
        .stacks
        .iter()
        .all(|s| s.enforcement_proven));
    fs.text("/etc/pam.d/passwd", "password substack system-auth\n");
    assert!(p_facts(&complexity(&fs))
        .stacks
        .iter()
        .all(|s| s.enforcement_proven));
}
#[test]
fn substack_continuation_cannot_hide_writer_bypass() {
    let mut fs = pam(STACK);
    fs.text(
        "/etc/pam.d/passwd",
        "password substack system-auth\npassword required pam_unix.so\n",
    );
    assert_eq!(
        statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
        Status::Warn
    );
}
#[test]
fn include_cycles_and_missing_sources_warn() {
    for line in ["password include passwd\n", "password include absent\n"] {
        let fs = pam(line);
        assert_eq!(
            statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
            Status::Warn
        );
    }
}
#[test]
fn pam_arguments_override_main_and_sorted_dropins() {
    let mut fs = pam(&STACK.replace("retry=3", "retry=3 minlen=14"));
    fs.directories.insert(
        "/etc/security/pwquality.conf.d".into(),
        Ok(Some(vec!["20-last.conf".into(), "10-first.conf".into()])),
    );
    fs.text("/etc/security/pwquality.conf.d/10-first.conf", "minlen=8\n");
    fs.text("/etc/security/pwquality.conf.d/20-last.conf", "minlen=20\n");
    fs.text(
        "/etc/security/pwquality.conf",
        &QUALITY.replace("minlen = 14", "minlen = 18"),
    );
    assert!(p_facts(&complexity(&fs)).stacks.iter().all(|s| s
        .requirements
        .as_ref()
        .unwrap()
        .minimum_length
        == Some(14)));
}
#[test]
fn module_presence_and_required_control_do_not_prove_enforcement() {
    for control in ["optional", "sufficient", "required"] {
        let fs = pam(&STACK.replace(
            "requisite pam_pwquality",
            &format!("{control} pam_pwquality"),
        ));
        assert_eq!(
            statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
            Status::Warn
        );
    }
}
#[test]
fn early_success_jumps_reset_and_unknown_modules_warn() {
    for prefix in [
        "password sufficient pam_permit.so\n",
        "password [success=1 default=ignore] pam_succeed_if.so uid > 1000\n",
        "password [default=reset] pam_permit.so\n",
        "password optional custom.so\n",
    ] {
        assert_eq!(
            statuses(&report(
                good_a(),
                complexity(&pam(&format!("{prefix}{STACK}")))
            ))["SEC-010"],
            Status::Warn
        );
    }
}
#[test]
fn writer_order_and_token_reuse_are_required() {
    for stack in [
        STACK.replace("use_authtok", ""),
        format!("password required pam_unix.so\n{STACK}"),
    ] {
        assert_eq!(
            statuses(&report(good_a(), complexity(&pam(&stack))))["SEC-010"],
            Status::Warn
        );
    }
}
#[test]
fn warning_only_root_exception_and_unknown_enforcing_warn() {
    for config in [
        QUALITY.replace("enforcing = 1", "enforcing = 0"),
        QUALITY.replace("enforce_for_root\n", ""),
        QUALITY.replace("enforcing = 1\n", ""),
    ] {
        let mut fs = pam(STACK);
        fs.text("/etc/security/pwquality.conf", &config);
        assert_eq!(
            statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
            Status::Warn
        );
    }
}
#[test]
fn minclass_does_not_replace_explicit_individual_policy_requirements() {
    let mut fs = pam(STACK);
    fs.text(
        "/etc/security/pwquality.conf",
        &QUALITY.replace("ucredit = -1", "ucredit = 0"),
    );
    assert_eq!(
        statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
        Status::Fail
    );
}
#[test]
fn positive_credits_do_not_certify_true_length() {
    let mut fs = pam(STACK);
    fs.text(
        "/etc/security/pwquality.conf",
        &QUALITY.replace("ucredit = -1", "ucredit = 2"),
    );
    let r = report(good_a(), complexity(&fs));
    let mut p = Policy::from_json(SAMPLE).unwrap();
    p.checks
        .password_complexity
        .as_mut()
        .unwrap()
        .minimum_uppercase = 0;
    assert_eq!(
        evaluate(&p, &r)
            .unwrap()
            .checks
            .iter()
            .find(|c| c.check_id == "SEC-010")
            .unwrap()
            .status,
        Some(Status::Fail)
    );
}
#[test]
fn weak_known_requirements_fail_but_missing_fields_warn() {
    for (config, status) in [
        (QUALITY.replace("minlen = 14", "minlen = 8"), Status::Fail),
        (QUALITY.replace("minlen = 14\n", ""), Status::Warn),
    ] {
        let mut fs = pam(STACK);
        fs.text("/etc/security/pwquality.conf", &config);
        assert_eq!(
            statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
            status
        );
    }
}
#[test]
fn alternate_password_service_prevents_global_pass() {
    let mut fs = pam(STACK);
    fs.directories
        .get_mut("/etc/pam.d")
        .unwrap()
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .push("alternate".into());
    fs.text("/etc/pam.d/alternate", "password required pam_unix.so\n");
    assert_eq!(
        statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
        Status::Warn
    );
}
#[test]
fn vendor_pam_fallback_and_local_override() {
    let mut fs = pam(STACK);
    fs.reads.remove("/etc/pam.d/system-auth");
    fs.nodes.remove("/etc/pam.d/system-auth");
    fs.text("/usr/lib/pam.d/system-auth", STACK);
    assert_eq!(
        statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
        Status::Pass
    );
    fs.text("/etc/pam.d/system-auth", "password required pam_unix.so\n");
    assert_eq!(
        statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
        Status::Warn
    );
}
#[test]
fn unknown_custom_config_and_vendor_quality_layout_warn() {
    let fs = pam(&STACK.replace("retry=3", "conf=/custom"));
    assert_eq!(
        statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
        Status::Warn
    );
    let mut fs = pam(STACK);
    fs.text("/usr/lib/security/pwquality.conf", QUALITY);
    assert_eq!(p_facts(&complexity(&fs)).quality, Quality::Inconclusive);
}
struct Racing {
    fs: Fs,
    reads: Cell<usize>,
}
impl Files for Racing {
    fn info(&self, p: &str) -> Result<Option<Node>, ProbeError> {
        self.fs.info(p)
    }
    fn entries(&self, p: &str) -> Result<Option<Vec<String>>, ProbeError> {
        self.fs.entries(p)
    }
    fn read(&self, p: &str, n: usize) -> Result<Option<Vec<u8>>, ProbeError> {
        if p == "/etc/security/pwquality.conf" {
            self.reads.set(self.reads.get() + 1);
            if self.reads.get() > 1 {
                return Ok(Some(b"minlen=6\n".to_vec()));
            }
        }
        self.fs.read(p, n)
    }
}
#[test]
fn source_changes_discard_partial_proof() {
    let fs = Racing {
        fs: pam(STACK),
        reads: Cell::new(0),
    };
    assert_eq!(p_facts(&complexity(&fs)).quality, Quality::Inconclusive);
}
#[test]
fn old_profiles_do_not_run_or_require_credentials() {
    for text in [
        include_str!("../../../policies/default.json"),
        include_str!("../../../policies/linux-baseline.json"),
        include_str!("../../../policies/encryption-coverage.example.json"),
    ] {
        let p = Policy::from_json(text).unwrap();
        let f = fixture(good_a(), good_p());
        let r = builtin::standalone_with_policy(&f, &common::FixedClock, &p).unwrap();
        assert_eq!(f.calls.get(), 0);
        assert!(!r
            .policy_evaluation
            .unwrap()
            .checks
            .iter()
            .any(|c| matches!(c.check_id.as_str(), "SEC-008" | "SEC-009" | "SEC-010")));
    }
}
#[test]
fn credential_policy_rejects_null_invalid_and_legacy_schema_extensions() {
    for text in [
        SAMPLE.replace("policy.v3", "policy.v2"),
        SAMPLE.replace("policy.v3", "policy.v1"),
        SAMPLE.replace("\"maximumDays\": 60", "\"maximumDays\": 0"),
        SAMPLE.replace("\"minimumClasses\": 4", "\"minimumClasses\": 5"),
        SAMPLE.replace("{ \"minimumDays\": 10 }", "null"),
        SAMPLE.replace("\"minimumLength\": 14", "\"unknown\": 14"),
    ] {
        assert!(Policy::from_json(&text).is_err(), "{text}");
    }
}
#[test]
fn informational_credentials_do_not_gate_and_observations_are_immutable() {
    let r = report(
        aging(&accounts(), &listing(0, 90, 7, "2026-12-30")),
        good_p(),
    );
    let before = serde_json::to_string(&r).unwrap();
    let mut p = Policy::from_json(SAMPLE).unwrap();
    p.checks.password_aging.as_mut().unwrap().mandatory = false;
    p.checks.password_warning.as_mut().unwrap().mandatory = false;
    assert_eq!(evaluate(&p, &r).unwrap().overall, Status::Pass);
    assert_eq!(serde_json::to_string(&r).unwrap(), before);
}
#[test]
fn new_report_roundtrips_and_unsupported_os_skips_credentials() {
    let r = report(good_a(), good_p());
    let text = serde_json::to_string(&r).unwrap();
    let decoded: AuditReport = serde_json::from_str(&text).unwrap();
    assert_eq!(statuses(&r), statuses(&decoded));
    let mut f = fixture(good_a(), good_p());
    f.os.supported = false;
    f.os.distribution_id = Some("ubuntu".into());
    let r = builtin::standalone_with_policy(
        &f,
        &common::FixedClock,
        &Policy::from_json(SAMPLE).unwrap(),
    )
    .unwrap();
    assert_eq!(f.calls.get(), 0);
    assert_eq!(statuses(&r)["SEC-010"], Status::Warn);
}

#[test]
fn deny_only_fallback_does_not_invent_quality_or_hide_good_stack() {
    let mut fs = pam(STACK);
    fs.directories
        .get_mut("/etc/pam.d")
        .unwrap()
        .as_mut()
        .unwrap()
        .as_mut()
        .unwrap()
        .push("other".into());
    fs.text(
        "/etc/pam.d/other",
        "password optional pam_warn.so\npassword required pam_deny.so\n",
    );
    let o = complexity(&fs);
    assert!(p_facts(&o)
        .stacks
        .iter()
        .any(|s| s.password_changes_denied && s.requirements.is_none()));
    assert_eq!(statuses(&report(good_a(), o))["SEC-010"], Status::Pass);
    assert_eq!(
        statuses(&report(
            good_a(),
            complexity(&pam("password requisite pam_deny.so\n"))
        ))["SEC-010"],
        Status::Warn
    );
}

#[test]
fn fedora_sssd_branch_is_reported_as_unproven_not_silently_skipped() {
    let fs=pam("password requisite pam_pwquality.so local_users_only\npassword sufficient pam_unix.so use_authtok sha512 shadow\npassword sufficient pam_sss.so use_authtok\npassword required pam_deny.so\n");
    let o = complexity(&fs);
    assert!(p_facts(&o).stacks.iter().all(|s| !s.enforcement_proven));
    assert_eq!(statuses(&report(good_a(), o))["SEC-010"], Status::Warn);
}

#[test]
fn disabled_credentials_do_not_collect_and_stale_credentials_do_not_pass() {
    let mut p = Policy::from_json(SAMPLE).unwrap();
    p.checks.password_aging.as_mut().unwrap().enabled = false;
    p.checks.password_warning.as_mut().unwrap().enabled = false;
    p.checks.password_complexity.as_mut().unwrap().enabled = false;
    let f = fixture(good_a(), good_p());
    builtin::standalone_with_policy(&f, &common::FixedClock, &p).unwrap();
    assert_eq!(f.calls.get(), 0);
    let mut r = report(good_a(), good_p());
    r.completed_at_unix_ms += 301000;
    let e = evaluate(&Policy::from_json(SAMPLE).unwrap(), &r).unwrap();
    assert!(e
        .checks
        .iter()
        .filter(|c| c.enabled)
        .all(|c| c.status == Some(Status::Warn)));
}

#[test]
fn known_library_parse_failures_cannot_create_a_false_pass() {
    for config in [
        format!("{}minlen=14\n", " ".repeat(1024)),
        QUALITY.replace("ucredit = -1", "ucredit = -2147483648"),
        format!("retry=2147483647\n{QUALITY}"),
    ] {
        let mut fs = pam(STACK);
        fs.text("/etc/security/pwquality.conf", &config);
        assert_eq!(
            statuses(&report(good_a(), complexity(&fs)))["SEC-010"],
            Status::Warn
        );
    }
}

#[test]
fn duplicate_accounts_and_ambiguous_uid_selection_warn_without_queries() {
    for content in [
        "one:x:1000:1000::/home/one:/bin/bash\ntwo:x:1000:1000::/home/two:/bin/bash\n",
        "one:x:1000:1000::/home/one:/bin/bash\none:x:1001:1001::/home/other:/bin/bash\n",
    ] {
        let mut fs = accounts();
        fs.text("/etc/passwd", content);
        // The first valid account may be inspected; partial data must be discarded.
        let o = password_aging::observe(
            &fs,
            &Runner::new(vec![out(&listing(1, 60, 10, "2026-11-30"))]),
            &host(),
        );
        assert_eq!(a_facts(&o).quality, Quality::Inconclusive);
        assert!(a_facts(&o).accounts.is_empty());
    }
}

#[test]
fn unexpected_chage_stderr_discards_even_successful_stdout() {
    let runner = Runner::new(vec![Ok(
        baradwatchu_agent::platform::command::CommandOutput {
            code: Some(0),
            stdout: listing(1, 60, 10, "2026-11-30"),
            stderr: "unrecognized diagnostic".into(),
        },
    )]);
    let o = password_aging::observe(&accounts(), &runner, &host());
    assert_eq!(a_facts(&o).accounts[0].quality, Quality::Inconclusive);
    assert_eq!(statuses(&report(o, good_p()))["SEC-009"], Status::Warn);
}

#[test]
fn explicit_local_users_only_is_valid_for_local_scope() {
    let o = complexity(&pam(&STACK.replace("retry=3", "retry=3 local_users_only")));
    assert_eq!(statuses(&report(good_a(), o))["SEC-010"], Status::Pass);
}

#[test]
fn unreadable_pam_file_is_unknown_not_absent_or_pass() {
    let mut fs = pam(STACK);
    fs.reads.insert(
        "/etc/pam.d/system-auth".into(),
        Err(ProbeError::new(
            baradwatchu_agent::audit::Reason::PermissionDenied,
            "private source",
        )),
    );
    let o = complexity(&fs);
    assert_eq!(p_facts(&o).quality, Quality::Inconclusive);
    assert!(!serde_json::to_string(&o)
        .unwrap()
        .contains("private source"));
}

#[test]
fn forced_change_is_not_recurring_expiry_and_zero_age_remains_strict() {
    let forced = listing(1, -1, 10, "password must be changed")
        .replace("2026-10-01", "password must be changed");
    let r = report(aging(&accounts(), &forced), good_p());
    assert_eq!(statuses(&r)["SEC-008"], Status::Fail);
    assert_eq!(statuses(&r)["SEC-009"], Status::Fail);
    let r = report(
        aging(&accounts(), &listing(0, 0, 0, "password must be changed")),
        good_p(),
    );
    let mut p = Policy::from_json(SAMPLE).unwrap();
    p.checks.password_aging.as_mut().unwrap().minimum_days = 0;
    assert_eq!(
        evaluate(&p, &r)
            .unwrap()
            .checks
            .iter()
            .find(|c| c.check_id == "SEC-008")
            .unwrap()
            .status,
        Some(Status::Pass)
    );
}
