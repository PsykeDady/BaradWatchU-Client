use baradwatchu_agent::{
    audit::{Clock, OperatingSystem, Outcome, Reason, Status},
    cli,
    platform::{
        command::{CommandOutput, CommandRunner, CommandSpec, ProbeError},
        AuditPlatform,
    },
    workstation::{self, LocalSelection, PackPolicy},
};
use serde_json::json;
use std::{cell::Cell, ffi::OsString};

const SAMPLE: &str = include_str!("../../../policies/workstation.example.json");
struct Fixture {
    calls: Cell<usize>,
}
impl AuditPlatform for Fixture {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        let mut os = OperatingSystem::unidentified("linux");
        os.supported = true;
        os.distribution_id = Some("arch".into());
        Ok(os)
    }
    fn pending_updates(&self) -> Outcome {
        self.calls.set(self.calls.get() + 1);
        unknown()
    }
    fn root_encryption(&self) -> Outcome {
        self.calls.set(self.calls.get() + 1);
        unknown()
    }
    fn password_aging(&self) -> Outcome {
        self.calls.set(self.calls.get() + 1);
        unknown()
    }
}
struct Time;
impl Clock for Time {
    fn now_unix_ms(&self) -> Result<u64, String> {
        Ok(1000)
    }
}
fn unknown() -> Outcome {
    Outcome::new(Status::Warn, Reason::EvidenceInconclusive, "fixture")
}
fn fixture() -> Fixture {
    Fixture {
        calls: Cell::new(0),
    }
}
fn policy() -> PackPolicy {
    PackPolicy::from_json(SAMPLE).unwrap()
}
fn selection(ids: &[&str]) -> LocalSelection {
    LocalSelection::from_json(
        &json!({"schemaVersion":"baradwatchu.workstation-local.v1","disabled":ids}).to_string(),
    )
    .unwrap()
}

#[test]
fn samples_validate_and_vpn_is_informational() {
    let p = policy();
    assert!(!p.supplemental.vpn.mandatory);
    assert!(p.supplemental.vpn.enabled);
    LocalSelection::from_json(include_str!(
        "../../../policies/workstation-local.example.json"
    ))
    .unwrap();
}
#[test]
fn unknown_duplicate_null_and_arbitrary_commands_rejected() {
    for text in [
        r#"{"schemaVersion":"baradwatchu.workstation-local.v1","disabled":["SEC-999"]}"#,
        r#"{"schemaVersion":"baradwatchu.workstation-local.v1","disabled":["SEC-003","SEC-003"]}"#,
        r#"{"schemaVersion":"baradwatchu.workstation-local.v1","disabled":null}"#,
        r#"{"schemaVersion":"baradwatchu.workstation-local.v1","disabled":[],"command":"sh"}"#,
        r#"{"schemaVersion":"baradwatchu.workstation-local.v1","disabled":[],"disabled":[]}"#,
    ] {
        assert!(LocalSelection::from_json(text).is_err());
    }
    assert!(PackPolicy::from_json(&SAMPLE.replace("\"supplemental\":", "\"command\":")).is_err());
    assert!(
        PackPolicy::from_json(&SAMPLE.replace("\"mandatory\": true", "\"mandatory\": null"))
            .is_err()
    );
    assert!(PackPolicy::from_json(&" ".repeat(65537)).is_err());
}
#[test]
fn required_local_disable_remains_visible_and_not_executed() {
    let mut called = vec![];
    let r = workstation::audit(
        &fixture(),
        &Time,
        &policy(),
        &selection(&["SEC-003"]),
        |id| {
            called.push(id.to_owned());
            unknown()
        },
    )
    .unwrap();
    assert!(!called.iter().any(|s| s == "SEC-003"));
    let c = r.checks.iter().find(|c| c.id == "SEC-003").unwrap();
    assert!(c.desired_enabled && c.mandatory && c.required_check_interrupted);
    assert_eq!(c.execution, "DISABLED_LOCAL");
    assert!(c.outcome.is_none());
    assert_eq!(c.evaluation, Some(Status::Fail));
    assert_eq!(r.overall, Status::Fail);
    assert_eq!(r.exit_code(), 3);
    assert_eq!(r.remote_delivery, "NOT_IMPLEMENTED");
}
#[test]
fn optional_local_disable_does_not_become_required_violation() {
    let r = workstation::audit(
        &fixture(),
        &Time,
        &policy(),
        &selection(&["SEC-011"]),
        |_| unknown(),
    )
    .unwrap();
    let c = r.checks.iter().find(|c| c.id == "SEC-011").unwrap();
    assert!(!c.required_check_interrupted);
    assert_eq!(c.evaluation, None);
    assert!(c.outcome.is_none());
}
#[test]
fn native_local_disable_preserves_original_policy_and_skips_collector() {
    let f = fixture();
    let r = workstation::audit(
        &f,
        &Time,
        &policy(),
        &selection(&["SEC-001", "SEC-006", "SEC-008", "SEC-009"]),
        |_| unknown(),
    )
    .unwrap();
    assert_eq!(f.calls.get(), 0);
    assert!(r
        .native_report
        .policy_evaluation
        .as_ref()
        .unwrap()
        .policy
        .enabled("SEC-008"));
    assert!(!r
        .native_report
        .results
        .iter()
        .any(|r| r.check.id == "SEC-008"));
    assert!(
        r.checks
            .iter()
            .find(|c| c.id == "SEC-008")
            .unwrap()
            .required_check_interrupted
    );
}
#[test]
fn policy_disable_is_distinct_from_local_disable() {
    let mut p = policy();
    p.supplemental.antivirus.enabled = false;
    let r = workstation::audit(&fixture(), &Time, &p, &LocalSelection::default(), |id| {
        assert_ne!(id, "SEC-003");
        unknown()
    })
    .unwrap();
    let c = r.checks.iter().find(|c| c.id == "SEC-003").unwrap();
    assert_eq!(c.execution, "DISABLED_POLICY");
    assert!(!c.required_check_interrupted);
    assert_eq!(c.evaluation, None);
}
#[test]
fn old_native_policy_versions_can_be_wrapped_without_changes() {
    for version in ["v1", "v2", "v3"] {
        let mut p = policy();
        p.native_policy = baradwatchu_agent::policy::Policy::from_json(&format!(
            r#"{{"schemaVersion":"baradwatchu.audit-policy.{version}"}}"#
        ))
        .unwrap();
        let r = workstation::audit(&fixture(), &Time, &p, &LocalSelection::default(), |_| {
            unknown()
        })
        .unwrap();
        assert_eq!(
            r.native_report.policy_evaluation.as_ref().unwrap().policy,
            p.native_policy
        );
    }
}
struct Runner {
    text: String,
    code: Option<i32>,
    stderr: String,
}
impl CommandRunner for Runner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        assert_eq!(spec.program.to_str(), Some("/usr/bin/bash"));
        assert!(spec.read_only_filesystem);
        assert!(!spec.allow_null_device);
        assert!(spec.config_environment.is_empty());
        assert_eq!(spec.timeout.as_secs(), 10);
        assert_eq!(spec.output_limit, 8192);
        assert_eq!(&spec.args[..3], &["--noprofile", "--norc", "-c"]);
        Ok(CommandOutput {
            code: self.code,
            stdout: self.text.clone(),
            stderr: self.stderr.clone(),
        })
    }
}
fn runner(text: &str) -> Runner {
    Runner {
        text: text.into(),
        code: Some(0),
        stderr: String::new(),
    }
}
#[test]
fn script_success_remains_an_observation_not_a_pass() {
    for (id, facts) in [
        (
            "SEC-003",
            r#"{"daemon":"ACTIVE","updater":"ACTIVE","onAccess":"ACTIVE","candidatePrevention":true,"candidateSignatureMtime":123}"#,
        ),
        (
            "SEC-004",
            r#"{"hostsSinkEntries":100000,"resolver":"LOOPBACK_ONLY","nss":"FILES_PRESENT","candidateDnsmasqRules":500000,"dnsmasq":"ACTIVE"}"#,
        ),
        ("SEC-011", r#"{"state":"CONNECTED"}"#),
    ] {
        let o = workstation::collect_script(id, &runner(facts));
        assert_eq!(o.status, Status::Warn);
        assert_eq!(o.evidence.len(), 1);
        assert_eq!(o.evidence[0].values["enforcementVerified"], false);
    }
}
#[test]
fn hosts_and_dnsmasq_are_independent_candidates() {
    let facts = r#"{"hostsSinkEntries":100000,"resolver":"OTHER","nss":"FILES_PRESENT","candidateDnsmasqRules":null,"dnsmasq":"INACTIVE"}"#;
    let o = workstation::collect_script("SEC-004", &runner(facts));
    assert_eq!(o.status, Status::Warn);
    assert_eq!(o.evidence[0].values["facts"]["hostsSinkEntries"], 100000);
}
#[test]
fn invalid_output_and_private_diagnostics_are_discarded() {
    for text in [
        r#"{"state":"CONNECTED","user":"private@example.test"}"#,
        r#"{"state":"NEW_STATE"}"#,
        r#"{"state":"CONNECTED","state":"DISCONNECTED"}"#,
        "private raw data",
    ] {
        let o = workstation::collect_script("SEC-011", &runner(text));
        assert_eq!(o.status, Status::Warn);
        assert!(o.evidence.is_empty());
        assert!(!serde_json::to_string(&o).unwrap().contains("private"));
    }
    for code in [None, Some(1), Some(4)] {
        let mut r = runner(r#"{"state":"CONNECTED"}"#);
        r.code = code;
        assert!(workstation::collect_script("SEC-011", &r)
            .evidence
            .is_empty());
    }
    let mut r = runner(r#"{"state":"CONNECTED"}"#);
    r.stderr = "private diagnostic".into();
    assert!(workstation::collect_script("SEC-011", &r)
        .evidence
        .is_empty());
}
#[test]
fn unknown_script_and_oversized_output_fail_closed() {
    assert!(workstation::parse_facts("SEC-000", "{}").is_err());
    assert!(workstation::parse_facts("SEC-011", &" ".repeat(8193)).is_err());
}
#[test]
fn cli_registry_and_invalid_options_need_no_collectors() {
    let run = |args: &[&str]| cli::run(&args.iter().map(OsString::from).collect::<Vec<_>>());
    for args in [
        vec!["workstation", "list"],
        vec!["workstation", "check", "../script"],
        vec!["workstation", "audit"],
        vec!["workstation", "audit", "--policy"],
        vec!["workstation", "audit", "--command", "sh"],
    ] {
        assert_eq!(run(&args).err().unwrap().code, 2);
    }
}

#[cfg(target_os = "linux")]
fn shell_fixture(source: &str) -> serde_json::Value {
    use baradwatchu_agent::platform::command::SystemRunner;
    let mut spec = CommandSpec::new("/usr/bin/bash", &["--noprofile", "--norc", "-c", source]);
    spec.read_only_filesystem = true;
    let out = SystemRunner.run(&spec).unwrap();
    assert_eq!(out.code, Some(0), "{}", out.stderr);
    assert!(out.stderr.is_empty());
    serde_json::from_str(&out.stdout).unwrap()
}
#[cfg(target_os = "linux")]
#[test]
fn real_guarded_cato_script_normalizes_and_redacts_fixtures() {
    let source = include_str!("../../../scripts/audit/SEC-011.sh");
    for (raw, expected) in [
        ("STATE_CONNECTED user=private@example.test", "CONNECTED"),
        ("STATE_UNAUTHENTICATED", "AUTH_REQUIRED"),
        ("STATE_STOPPED", "DISCONNECTED"),
        ("STATE_CONNECTED STATE_FAILED", "UNKNOWN"),
        ("new format private@example.test", "UNKNOWN"),
    ] {
        let code = source
            .replace(
                "/usr/bin/cato-sdp status",
                &format!("printf '%s\\n' '{raw}'"),
            )
            .replace("-x /usr/bin/cato-sdp", "-x /usr/bin/printf");
        let result = shell_fixture(&code);
        assert_eq!(result, json!({"state":expected}));
    }
    let code = source
        .replace(
            "/usr/bin/cato-sdp status",
            "printf 'STATE_CONNECTED'; false",
        )
        .replace("-x /usr/bin/cato-sdp", "-x /usr/bin/printf");
    // Nonzero status must not become CONNECTED even if the tool printed that token.
    assert_eq!(shell_fixture(&code)["state"], "UNKNOWN");
}
#[cfg(target_os = "linux")]
#[test]
fn real_guarded_dns_script_supports_hosts_and_candidate_rules_without_exposing_names() {
    use std::fs;
    let root = std::env::temp_dir().join(format!("baradwatchu-dns-fixture-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("hosts"),
        "127.0.0.1 localhost\n0.0.0.0 private.example other.example # comment\n:: third.example\n",
    )
    .unwrap();
    fs::write(
        root.join("resolv"),
        "nameserver 127.0.0.1\nnameserver 192.0.2.3\n",
    )
    .unwrap();
    fs::write(root.join("nss"), "hosts: resolve dns # files\n").unwrap();
    fs::write(
        root.join("rules"),
        "server=/private.example/\nserver=/another.example/\n#ignored\n",
    )
    .unwrap();
    let mut source = include_str!("../../../scripts/audit/SEC-004.sh").to_owned();
    for (from, to) in [
        ("/etc/hosts", "hosts"),
        ("/etc/resolv.conf", "resolv"),
        ("/etc/nsswitch.conf", "nss"),
        ("/etc/dnsmasq.d/.hagezi-ultimate.servers", "rules"),
        ("/etc/dnsmasq.d/hagezi/hagezi-ultimate.servers", "absent"),
        ("/var/lib/dnsmasq-hagezi/hagezi-ultimate.servers", "absent"),
    ] {
        source = source.replace(from, root.join(to).to_str().unwrap());
    }
    source = source.replace(
        "/usr/bin/systemctl is-active dnsmasq.service",
        "printf 'active'",
    );
    let facts = shell_fixture(&source);
    assert_eq!(
        facts,
        json!({"hostsSinkEntries":3,"resolver":"MIXED","nss":"FILES_ABSENT","candidateDnsmasqRules":2,"dnsmasq":"ACTIVE"})
    );
    fs::remove_dir_all(root).unwrap();
}
#[cfg(target_os = "linux")]
#[test]
fn real_guarded_av_script_keeps_conflicting_configuration_unknown() {
    use std::fs;
    let root = std::env::temp_dir().join(format!("baradwatchu-av-fixture-{}", std::process::id()));
    fs::create_dir(&root).unwrap();
    fs::write(
        root.join("clamd.conf"),
        "OnAccessPrevention yes\nOnAccessPrevention no\n",
    )
    .unwrap();
    let source = include_str!("../../../scripts/audit/SEC-003.sh")
        .replace(
            "/etc/clamav/clamd.conf",
            root.join("clamd.conf").to_str().unwrap(),
        )
        .replace("/var/lib/clamav/", &format!("{}/", root.display()))
        .replace("/usr/bin/systemctl is-active \"$1\"", "printf 'active'");
    let facts = shell_fixture(&source);
    assert_eq!(
        facts,
        json!({"candidatePrevention":null,"candidateSignatureMtime":null,"daemon":"ACTIVE","updater":"ACTIVE","onAccess":"ACTIVE"})
    );
    fs::remove_dir_all(root).unwrap();
}
