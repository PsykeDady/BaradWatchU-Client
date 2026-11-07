#![cfg(target_os = "linux")]
mod common;
use baradwatchu_agent::{
    adapters::{
        self,
        external::{self, ExternalSpec},
        Implementation, LocalExecutor,
    },
    audit::{Reason, Status},
    check_port::{Availability, CheckEvidence, CheckExecutor, ExecutionState},
    platform::command::{CommandOutput, CommandRunner, CommandSpec, ProbeError, SystemRunner},
    workstation::{self, LocalSelection, PackPolicy},
};
use std::{cell::RefCell, path::PathBuf, sync::OnceLock, time::Duration};
const GOOD: &str = r#"{"schemaVersion":"baradwatchu.check-evidence.v1","checkId":"SEC-013","availability":"AVAILABLE","data":{"kind":"SECURE_BOOT","values":{"state":"ENABLED","secureBoot":true,"setupMode":false}}}"#;

#[test]
fn migrated_cato_file_emits_new_contract_for_known_unknown_and_absent_tool() {
    let root = binary().parent().unwrap().to_owned();
    for (index, raw) in ["STATE_CONNECTED", "new unknown format", "ABSENT"]
        .iter()
        .enumerate()
    {
        let mut source = include_str!("../../../scripts/adapters/SEC-011.sh")
            .replace(
                "/usr/bin/cato-sdp status",
                &format!("printf '%s\\n' '{raw}'"),
            )
            .replace("-x /usr/bin/cato-sdp", "-x /usr/bin/printf");
        if *raw == "ABSENT" {
            source = source.replace("-x /usr/bin/printf", "-x /nonexistent/baradwatchu/cato");
        }
        let path = root.join(format!("cato-{index}.sh"));
        std::fs::write(&path, source).unwrap();
        let spec = ExternalSpec {
            program: "/usr/bin/bash".into(),
            args: vec![
                "--noprofile".into(),
                "--norc".into(),
                path.to_string_lossy().into_owned(),
            ],
            timeout: Duration::from_secs(2),
            output_limit: 8192,
        };
        let e = external::execute("SEC-011", &spec, &SystemRunner);
        assert_eq!(e.execution, ExecutionState::Completed);
        assert_eq!(
            e.availability,
            if *raw == "ABSENT" {
                Availability::Unknown
            } else {
                Availability::Available
            }
        );
    }
}

#[test]
fn warning_only_selection_executes_enabled_id_not_disabled_aging_id() {
    let mut p = policy();
    p.native_policy.checks.secure_boot.as_mut().unwrap().enabled = false;
    p.native_policy
        .checks
        .password_warning
        .as_mut()
        .unwrap()
        .enabled = true;
    let local = LocalSelection::from_json(
        r#"{"schemaVersion":"baradwatchu.workstation-local.v1","disabled":["SEC-008"]}"#,
    )
    .unwrap();
    let e = FixtureExecutor {
        calls: RefCell::new(vec![]),
        mode: "available",
    };
    workstation::audit_with_executor(&common::platform(), &common::FixedClock, &p, &local, &e)
        .unwrap();
    assert_eq!(&*e.calls.borrow(), &["SEC-009"]);
}
fn binary() -> PathBuf {
    static BIN: OnceLock<PathBuf> = OnceLock::new();
    BIN.get_or_init(|| {
        let root =
            std::env::temp_dir().join(format!("baradwatchu-adapter-bin-{}", std::process::id()));
        std::fs::create_dir(&root).unwrap();
        let bin = root.join("fixture");
        let status = std::process::Command::new("rustc")
            .args([
                "--edition=2021",
                concat!(
                    env!("CARGO_MANIFEST_DIR"),
                    "/examples/check_evidence_fixture.rs"
                ),
                "-o",
            ])
            .arg(&bin)
            .status()
            .unwrap();
        assert!(status.success());
        bin
    })
    .clone()
}
fn spec(mode: &str) -> ExternalSpec {
    ExternalSpec {
        program: binary(),
        args: vec![mode.into()],
        timeout: Duration::from_millis(200),
        output_limit: 8192,
    }
}
#[test]
fn native_and_external_registry_selection() {
    let r = adapters::registry();
    assert_eq!(r.len(), 15);
    assert!(matches!(
        r.iter().find(|r| r.id == "SEC-008").unwrap().implementation,
        Implementation::Native
    ));
    assert!(matches!(
        r.iter().find(|r| r.id == "SEC-011").unwrap().implementation,
        Implementation::External(_)
    ));
    let p = common::platform();
    let exec = LocalExecutor::new(&p, &[]);
    exec.execute("SEC-001");
    assert!(p.calls.borrow().contains(&"updates"));
    assert_eq!(
        exec.execute("UNKNOWN").execution,
        ExecutionState::NotStarted
    );
}
#[test]
fn real_external_script_file() {
    let s = ExternalSpec {
        program: "/usr/bin/bash".into(),
        args: vec![
            "--noprofile".into(),
            "--norc".into(),
            concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/tests/fixtures/check-evidence.sh"
            )
            .into(),
        ],
        timeout: Duration::from_secs(2),
        output_limit: 8192,
    };
    let e = external::execute("SEC-013", &s, &SystemRunner);
    assert_eq!(e.execution, ExecutionState::Completed);
    assert_eq!(e.availability, Availability::Available);
    assert!(e.outcome.observation.is_some());
}
#[test]
fn real_local_binary_without_interpreter() {
    let e = external::execute("SEC-013", &spec("available"), &SystemRunner);
    assert_eq!(e.execution, ExecutionState::Completed);
    assert_eq!(e.outcome.status, Status::Warn);
}

#[test]
fn non_executable_registered_program_is_an_execution_error() {
    use std::os::unix::fs::PermissionsExt;
    let path = binary().parent().unwrap().join("not-executable");
    std::fs::write(&path, b"fixture, not executable").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let mut s = spec("available");
    s.program = path;
    let e = external::execute("SEC-013", &s, &SystemRunner);
    assert_eq!(e.execution, ExecutionState::Failed);
    assert_eq!(e.outcome.reason_code, Reason::PermissionDenied);
    assert_eq!(e.outcome.status, Status::Warn);
}
#[test]
fn real_timeout() {
    assert_eq!(
        external::execute("SEC-013", &spec("timeout"), &SystemRunner).execution,
        ExecutionState::Timeout
    );
}
#[test]
fn real_malformed_output() {
    assert_eq!(
        external::execute("SEC-013", &spec("malformed"), &SystemRunner).execution,
        ExecutionState::InvalidEvidence
    );
}
#[test]
fn real_unexpected_exit() {
    assert_eq!(
        external::execute("SEC-013", &spec("exit"), &SystemRunner).execution,
        ExecutionState::UnexpectedExit
    );
}
#[test]
fn real_stdout_and_stderr_limits() {
    for mode in ["large", "stderr"] {
        assert_eq!(
            external::execute("SEC-013", &spec(mode), &SystemRunner).execution,
            ExecutionState::OutputLimit
        );
    }
}
#[test]
fn missing_executable_and_relative_command_rejected() {
    let mut s = spec("available");
    s.program = "/nonexistent/baradwatchu/fixture".into();
    assert_eq!(
        external::execute("SEC-013", &s, &SystemRunner).execution,
        ExecutionState::MissingExecutable
    );
    s.program = "sh".into();
    assert_eq!(
        external::execute("SEC-013", &s, &SystemRunner).execution,
        ExecutionState::NotStarted
    );
}
#[test]
fn strict_contract_identity_fields_duplicates_and_no_policy_verdict() {
    for text in [
        GOOD.replace("SEC-013", "SEC-011"),
        GOOD.replace("ENABLED", "FUTURE"),
        GOOD.replace("\"setupMode\":false", "\"setupMode\":false,\"PASS\":true"),
        GOOD.replace("\"checkId\":", "\"pass\":true,\"checkId\":"),
        GOOD.replace(
            "\"secureBoot\":true",
            "\"secureBoot\":true,\"secureBoot\":false",
        ),
        format!("{GOOD}{GOOD}"),
        GOOD.replace("AVAILABLE", "UNKNOWN"),
    ] {
        assert!(external::parse("SEC-013", &text).is_err(), "{text}");
    }
}
#[test]
fn availability_is_distinct_from_successful_execution() {
    for (wire, state) in [
        ("UNKNOWN", Availability::Unknown),
        ("NOT_APPLICABLE", Availability::NotApplicable),
        ("ERROR", Availability::Error),
    ] {
        let e=external::parse("SEC-013",&format!(r#"{{"schemaVersion":"baradwatchu.check-evidence.v1","checkId":"SEC-013","availability":"{wire}","data":null}}"#)).unwrap();
        assert_eq!(e.availability, state);
        assert_eq!(e.execution, ExecutionState::Completed);
    }
}
struct Mock;
impl CommandRunner for Mock {
    fn run(&self, s: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        assert!(s.read_only_filesystem);
        assert!(!s.allow_null_device);
        assert!(s.config_environment.is_empty());
        assert_eq!(
            &s.args[s.args.len() - 4..],
            &[
                "--check-id",
                "SEC-013",
                "--schema",
                "baradwatchu.check-evidence.v1"
            ]
        );
        Ok(CommandOutput {
            code: Some(0),
            stdout: GOOD.into(),
            stderr: "diagnostic intentionally discarded".into(),
        })
    }
}
#[test]
fn explicit_arguments_and_diagnostics_not_logged() {
    let e = external::execute("SEC-013", &spec("available"), &Mock);
    assert_eq!(e.execution, ExecutionState::Completed);
    assert!(!serde_json::to_string(&e.outcome)
        .unwrap()
        .contains("discarded"));
}
struct FixtureExecutor {
    calls: RefCell<Vec<String>>,
    mode: &'static str,
}
impl CheckExecutor for FixtureExecutor {
    fn execute(&self, id: &str) -> CheckEvidence {
        self.calls.borrow_mut().push(id.into());
        external::execute(id, &spec(self.mode), &SystemRunner)
    }
}
fn policy() -> PackPolicy {
    let mut p =
        PackPolicy::from_json(include_str!("../../../policies/workstation.example.json")).unwrap();
    let mut v = serde_json::to_value(&p.native_policy).unwrap();
    for (_, value) in v["checks"].as_object_mut().unwrap() {
        value["enabled"] = false.into();
    }
    v["checks"]["SEC-013"]["enabled"] = true.into();
    v["checks"]["SEC-013"]["mandatory"] = true.into();
    p.native_policy = baradwatchu_agent::policy::Policy::from_json(&v.to_string()).unwrap();
    p.supplemental.antivirus.enabled = false;
    p.supplemental.filtering.enabled = false;
    p.supplemental.vpn.enabled = false;
    p
}
#[test]
fn same_policy_evaluates_external_binary_evidence_not_adapter_verdict() {
    let e = FixtureExecutor {
        calls: RefCell::new(vec![]),
        mode: "available",
    };
    let report = workstation::audit_with_executor(
        &common::platform(),
        &common::FixedClock,
        &policy(),
        &LocalSelection::default(),
        &e,
    )
    .unwrap();
    let check = report.checks.iter().find(|c| c.id == "SEC-013").unwrap();
    assert_eq!(check.outcome.as_ref().unwrap().status, Status::Warn);
    assert_eq!(check.evaluation, Some(Status::Pass));
    assert_eq!(report.overall, Status::Pass);
    assert_eq!(&*e.calls.borrow(), &["SEC-013"]);
}
#[test]
fn required_disabled_never_calls_executor_and_stays_visible() {
    let e = FixtureExecutor {
        calls: RefCell::new(vec![]),
        mode: "available",
    };
    let local = LocalSelection::from_json(
        r#"{"schemaVersion":"baradwatchu.workstation-local.v1","disabled":["SEC-013"]}"#,
    )
    .unwrap();
    let report = workstation::audit_with_executor(
        &common::platform(),
        &common::FixedClock,
        &policy(),
        &local,
        &e,
    )
    .unwrap();
    assert!(e.calls.borrow().is_empty());
    let check = report.checks.iter().find(|c| c.id == "SEC-013").unwrap();
    assert!(check.required_check_interrupted);
    assert_eq!(check.evaluation, Some(Status::Fail));
    assert!(check.execution_state.is_none());
}
#[test]
fn executor_errors_survive_in_report_without_becoming_pass() {
    let e = FixtureExecutor {
        calls: RefCell::new(vec![]),
        mode: "malformed",
    };
    let r = workstation::audit_with_executor(
        &common::platform(),
        &common::FixedClock,
        &policy(),
        &LocalSelection::default(),
        &e,
    )
    .unwrap();
    let c = r.checks.iter().find(|c| c.id == "SEC-013").unwrap();
    assert_eq!(c.execution_state, Some(ExecutionState::InvalidEvidence));
    assert_ne!(c.evaluation, Some(Status::Pass));
}
#[test]
fn untrusted_config_cannot_register_commands() {
    let sample = include_str!("../../../policies/workstation.example.json");
    assert!(PackPolicy::from_json(&sample.replacen("{", "{\"command\":\"/bin/sh\",", 1)).is_err());
    assert!(LocalSelection::from_json(r#"{"schemaVersion":"baradwatchu.workstation-local.v1","disabled":[],"implementations":[{"command":"/bin/sh"}]}"#).is_err());
}
#[test]
fn unavailable_guard_never_retries() {
    struct Denied(RefCell<usize>);
    impl CommandRunner for Denied {
        fn run(&self, _: &CommandSpec) -> Result<CommandOutput, ProbeError> {
            *self.0.borrow_mut() += 1;
            Err(ProbeError::new(Reason::ReadOnlyGuardUnavailable, "fixture"))
        }
    }
    let runner = Denied(RefCell::new(0));
    assert_eq!(
        external::execute("SEC-013", &spec("available"), &runner).execution,
        ExecutionState::NotStarted
    );
    assert_eq!(*runner.0.borrow(), 1);
}
