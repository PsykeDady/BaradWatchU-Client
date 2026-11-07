#![cfg(target_os = "linux")]
mod common;
use baradwatchu_agent::{
    audit::{AuditReport, Outcome, Reason, Status},
    checks::builtin,
    observation::{MetadataState, Observation, UpdateClass},
    platform::{
        arch::{self, Metadata, Snapshot, Stamp, SystemMetadata},
        command::{CommandOutput, CommandRunner, CommandSpec, ProbeError},
        linux::{
            self,
            environment::{Environment, Kind},
            storage,
        },
    },
    policy::{PendingAction, Policy, Uncertain},
};
use common::*;
use std::{
    cell::RefCell,
    collections::VecDeque,
    path::{Path, PathBuf},
};
const ARCH: &str = include_str!("fixtures/arch.os-release");
const UPDATES: &str = include_str!("fixtures/pacman-upgrades.txt");
const ROOT: &str = include_str!("fixtures/root-ext4.json");
const ENCRYPTED: &str = include_str!("fixtures/blocks-encrypted.json");
fn stamp(time: u64) -> Stamp {
    Stamp {
        size: 128,
        modified_unix_ns: Some(u128::from(time) * 1_000_000_000),
        changed_unix_ns: 1,
        inode: 2,
        device: 3,
    }
}
fn snapshot(time: u64) -> Snapshot {
    Snapshot {
        repositories: vec![("core".into(), Some(stamp(time)))],
        local: Some(stamp(time)),
    }
}
struct Cache {
    values: RefCell<VecDeque<Result<Snapshot, ProbeError>>>,
}
impl Cache {
    fn new(s: Snapshot) -> Self {
        Self {
            values: RefCell::new(vec![Ok(s.clone()), Ok(s)].into()),
        }
    }
}
impl Metadata for Cache {
    fn snapshot(&self, database: &Path, repositories: &[String]) -> Result<Snapshot, ProbeError> {
        assert_eq!(database, Path::new("/tmp/Arch Metadata"));
        assert_eq!(repositories, ["core"]);
        self.values
            .borrow_mut()
            .pop_front()
            .expect("unexpected metadata access")
    }
}
struct Commands {
    outputs: RefCell<VecDeque<Result<CommandOutput, ProbeError>>>,
    calls: RefCell<Vec<CommandSpec>>,
}
impl Commands {
    fn new(outputs: Vec<Result<CommandOutput, ProbeError>>) -> Self {
        Self {
            outputs: RefCell::new(outputs.into()),
            calls: RefCell::new(vec![]),
        }
    }
}
impl CommandRunner for Commands {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        self.calls.borrow_mut().push(spec.clone());
        self.outputs
            .borrow_mut()
            .pop_front()
            .expect("unexpected command")
    }
}
fn config() -> Vec<Result<CommandOutput, ProbeError>> {
    vec![
        Ok(out(0, "/tmp/Arch Metadata\n", "")),
        Ok(out(0, "/\n", "")),
        Ok(out(0, "core\n", "")),
    ]
}
fn run(query: CommandOutput, cache: &dyn Metadata) -> (Outcome, Commands) {
    let mut outputs = config();
    outputs.push(Ok(query));
    let runner = Commands::new(outputs);
    let result = arch::updates(&runner, cache);
    (result, runner)
}
fn facts(result: &Outcome) -> &baradwatchu_agent::observation::Updates {
    match result.observation.as_ref().unwrap() {
        Observation::Updates(f) => f,
        _ => panic!(),
    }
}
fn host() -> Environment {
    Environment {
        kind: Kind::NativeHost,
        reason: "fixture",
        probe_error: None,
    }
}
fn assessment(result: Outcome, policy: &Policy) -> baradwatchu_agent::policy::PolicyEvaluation {
    let mut p = platform();
    p.os = linux::parse_os_release(ARCH, "fixture", false).unwrap();
    p.updates = result;
    builtin::standalone_with_policy(&p, &FixedClock, policy)
        .unwrap()
        .policy_evaluation
        .unwrap()
}
#[test]
fn native_arch_is_supported_without_version_id() {
    let os = linux::parse_os_release(ARCH, "fixture", false).unwrap();
    assert!(os.supported);
    assert!(os.version_id.is_none());
    assert_eq!(os.distribution_id.as_deref(), Some("arch"));
}
#[test]
fn arch_derivatives_do_not_inherit_support() {
    for id in ["manjaro", "endeavouros", "arcolinux", "garuda"] {
        let os =
            linux::parse_os_release(&format!("ID={id}\nID_LIKE=arch\n"), "fixture", false).unwrap();
        assert!(!os.supported);
        let runner = Commands::new(vec![]);
        let result = linux::pending_updates_for(&os, &runner, &Cache::new(snapshot(NOW)));
        assert_eq!(result.status, Status::NotApplicable);
        assert!(runner.calls.borrow().is_empty());
    }
}
#[test]
fn rolling_metadata_with_optional_version_does_not_require_fedora_number() {
    for extra in ["", "VERSION_ID=rolling\n", "VERSION_ID=2026.10.01\n"] {
        assert!(
            linux::parse_os_release(&(ARCH.to_owned() + extra), "fixture", false)
                .unwrap()
                .supported
        );
    }
}
#[test]
fn parses_versions_epochs_and_keeps_ignored_pending_packages() {
    assert_eq!(arch::parse_upgrades(UPDATES).unwrap(), (3, 1));
    assert_eq!(arch::parse_upgrades("").unwrap(), (0, 0));
}
#[test]
fn malformed_or_duplicate_upgrade_records_are_not_accepted() {
    for output in [
        "\n",
        "pkg 1 -> 1",
        "pkg 1 => 2",
        "pkg 1 -> 2 other",
        "../bad 1 -> 2",
        "pkg 1 -> 2\npkg 1 -> 3",
        "pkg 1 -> 2 [ignored] trailing",
        "pkg \u{1b} -> 2",
    ] {
        assert!(arch::parse_upgrades(output).is_err(), "{output:?}");
    }
}
#[test]
fn pending_updates_have_unknown_security_classification() {
    let (result, _) = run(out(0, UPDATES, ""), &Cache::new(snapshot(NOW - 10)));
    assert_eq!(result.status, Status::Fail);
    assert_eq!(result.reason_code, Reason::UpdatesAvailable);
    let f = facts(&result);
    assert_eq!(f.classification, UpdateClass::UnknownSecurity);
    assert_eq!(f.pending_packages, Some(3));
    assert_eq!(f.security_advisories, None);
    assert_eq!(f.ordinary_pending, None);
    assert!(!f.classification_complete);
    assert!(!f.coverage_complete);
}
#[test]
fn no_updates_with_fresh_metadata_is_still_not_current_security_pass() {
    for code in [0, 1] {
        let (result, _) = run(out(code, "", ""), &Cache::new(snapshot(NOW - 10)));
        assert_eq!(result.reason_code, Reason::NoCachedUpdates);
        assert_eq!(facts(&result).classification, UpdateClass::NoPending);
        let evaluation = assessment(result, &Policy::default());
        assert_eq!(evaluation.overall, Status::Warn);
        assert!(!evaluation.checks[0]
            .reasons
            .contains(&"STALE_METADATA".into()));
        assert!(evaluation.checks[0]
            .reasons
            .contains(&"UNKNOWN_METADATA_COVERAGE".into()));
    }
}
#[test]
fn stale_metadata_is_evaluated_by_the_existing_policy_limit() {
    let (result, _) = run(out(1, "", ""), &Cache::new(snapshot(NOW - 90000)));
    let mut policy = Policy::default();
    policy.checks.updates.evidence.stale = Uncertain::Error;
    let evaluation = assessment(result, &policy);
    assert_eq!(evaluation.overall, Status::Error);
    assert!(evaluation.checks[0]
        .reasons
        .contains(&"STALE_METADATA".into()));
}
#[test]
fn future_or_unknown_file_mtime_cannot_establish_freshness() {
    for time in [None, Some(u128::from(NOW + 10) * 1_000_000_000)] {
        let mut s = snapshot(NOW);
        s.repositories[0].1.as_mut().unwrap().modified_unix_ns = time;
        let (result, _) = run(out(1, "", ""), &Cache::new(s));
        let evaluation = assessment(result, &Policy::default());
        assert_eq!(evaluation.overall, Status::Warn);
        assert!(evaluation.checks[0]
            .reasons
            .contains(&"UNKNOWN_METADATA_TIMESTAMP".into()));
    }
}
#[test]
fn missing_sync_or_local_metadata_is_inconclusive_without_package_query() {
    for local_missing in [true, false] {
        let mut s = snapshot(NOW);
        if local_missing {
            s.local = None
        } else {
            s.repositories[0].1 = None
        };
        let runner = Commands::new(config());
        let result = arch::updates(&runner, &Cache::new(s));
        assert_eq!(result.reason_code, Reason::CacheUnavailable);
        assert_eq!(facts(&result).metadata_state, MetadataState::Missing);
        assert_eq!(facts(&result).pending_packages, None);
        let mut policy = Policy::default();
        policy.checks.updates.evidence.missing = Uncertain::Fail;
        assert_eq!(assessment(result, &policy).overall, Status::Fail);
        assert_eq!(runner.calls.borrow().len(), 3);
    }
}
#[test]
fn changed_metadata_during_query_discards_stable_classification() {
    let cache = Cache {
        values: RefCell::new(vec![Ok(snapshot(NOW - 10)), Ok(snapshot(NOW))].into()),
    };
    let (result, _) = run(out(0, UPDATES, ""), &cache);
    assert_eq!(result.reason_code, Reason::UpdateScopeInconclusive);
    assert_eq!(facts(&result).classification, UpdateClass::Unknown);
    assert_eq!(result.evidence[0].values["snapshotChanged"], true);
}
#[test]
fn unknown_security_never_bypasses_ordinary_and_security_policy_actions() {
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
            let (result, _) = run(out(0, UPDATES, ""), &Cache::new(snapshot(NOW)));
            let mut p = Policy::default();
            p.checks.updates.ordinary_updates = ordinary;
            p.checks.updates.security_updates = security;
            let e = assessment(result, &p);
            assert_ne!(e.checks[0].status, Some(Status::Pass));
            if ordinary == PendingAction::Fail && security == PendingAction::Fail {
                assert_eq!(e.overall, Status::Fail)
            } else {
                assert_eq!(e.overall, Status::Warn)
            }
        }
    }
}
#[test]
fn only_guarded_config_and_local_query_commands_execute() {
    let (_, runner) = run(out(0, UPDATES, ""), &Cache::new(snapshot(NOW)));
    let commands = runner.calls.borrow();
    assert_eq!(commands.len(), 4);
    for c in commands.iter() {
        assert!(c.read_only_filesystem);
        assert!(c.timeout.as_secs() <= 30);
        assert!(c.output_limit <= 256 * 1024);
        assert!(matches!(
            c.program.to_str(),
            Some("/usr/bin/pacman-conf" | "/usr/bin/pacman")
        ));
        assert!(!c.args.iter().any(|a| matches!(
            a.as_str(),
            "-S" | "-Sy" | "--sync" | "--refresh" | "--downloadonly" | "--remove"
        )));
    }
    let c = &commands[3];
    assert!(commands[..3].iter().all(|c| !c.allow_null_device));
    assert!(c.allow_null_device);
    assert_eq!(
        c.args,
        [
            "--query",
            "--upgrades",
            "--color",
            "never",
            "--config",
            "/etc/pacman.conf",
            "--dbpath",
            "/tmp/Arch Metadata",
            "--logfile",
            "/dev/null"
        ]
    );
}
#[test]
fn missing_tools_permissions_guard_and_timeout_are_errors_without_retry() {
    for reason in [
        Reason::MissingTool,
        Reason::PermissionDenied,
        Reason::ReadOnlyGuardUnavailable,
        Reason::Timeout,
    ] {
        for query_stage in [false, true] {
            let mut outputs = if query_stage { config() } else { vec![] };
            outputs.push(Err(ProbeError::new(reason, "fixture")));
            let runner = Commands::new(outputs);
            let result = arch::updates(&runner, &Cache::new(snapshot(NOW)));
            assert_eq!(result.status, Status::Error);
            assert_eq!(result.reason_code, reason);
            assert_eq!(runner.calls.borrow().len(), if query_stage { 4 } else { 1 });
        }
    }
}
#[test]
fn metadata_permission_errors_are_not_missing_cache() {
    let cache = Cache {
        values: RefCell::new(
            vec![Err(ProbeError::new(Reason::PermissionDenied, "fixture"))].into(),
        ),
    };
    let runner = Commands::new(config());
    let result = arch::updates(&runner, &cache);
    assert_eq!(result.reason_code, Reason::PermissionDenied);
    assert_eq!(result.status, Status::Error);
    assert_eq!(runner.calls.borrow().len(), 3);
}
#[test]
fn command_diagnostics_and_failures_cannot_be_empty_successes() {
    for (code, text, stderr, reason) in [
        (1, "", "Permission denied", Reason::PermissionDenied),
        (2, "", "", Reason::ExecutionFailed),
        (1, UPDATES, "", Reason::ExecutionFailed),
        (0, "", "warning: database unusable", Reason::ExecutionFailed),
        (0, "garbage", "", Reason::InvalidOutput),
    ] {
        let (result, _) = run(out(code, text, stderr), &Cache::new(snapshot(NOW)));
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.reason_code, reason);
    }
}
#[test]
fn invalid_or_foreign_config_scope_never_executes_a_package_query() {
    for db in ["relative\n", "/tmp/../etc\n", "/tmp\nother\n", ""] {
        let runner = Commands::new(vec![Ok(out(0, db, ""))]);
        assert_eq!(
            arch::updates(&runner, &Cache::new(snapshot(NOW))).reason_code,
            Reason::InvalidOutput
        );
        assert_eq!(runner.calls.borrow().len(), 1);
    }
    let runner = Commands::new(vec![
        Ok(out(0, "/tmp/Arch Metadata", "")),
        Ok(out(0, "/foreign", "")),
    ]);
    let result = arch::updates(&runner, &Cache::new(snapshot(NOW)));
    assert_eq!(result.reason_code, Reason::UpdateScopeInconclusive);
    assert_eq!(runner.calls.borrow().len(), 2);
}
#[test]
fn no_repositories_or_unsafe_repository_names_are_explicit() {
    for (repos, reason) in [
        ("", Reason::NoEnabledRepositories),
        ("../secret\n", Reason::InvalidOutput),
        ("core\ncore\n", Reason::InvalidOutput),
    ] {
        let mut outputs = config();
        outputs[2] = Ok(out(0, repos, ""));
        let runner = Commands::new(outputs);
        assert_eq!(
            arch::updates(&runner, &Cache::new(snapshot(NOW))).reason_code,
            reason
        );
        assert_eq!(runner.calls.borrow().len(), 3);
    }
}
#[test]
fn linux_dispatch_chooses_pacman_for_arch_and_dnf_for_fedora() {
    let mut outputs = config();
    outputs.push(Ok(out(0, UPDATES, "")));
    let runner = Commands::new(outputs);
    let os = linux::parse_os_release(ARCH, "fixture", false).unwrap();
    assert_eq!(
        linux::pending_updates_for(&os, &runner, &Cache::new(snapshot(NOW))).status,
        Status::Fail
    );
    assert!(runner
        .calls
        .borrow()
        .iter()
        .all(|c| !c.program.to_string_lossy().contains("dnf")));
    let os = linux::parse_os_release(include_str!("fixtures/fedora.os-release"), "fixture", false)
        .unwrap();
    let runner = Runner::new(vec![
        out(0, "", ""),
        out(0, include_str!("fixtures/dnf-repos.json"), ""),
    ]);
    linux::pending_updates_for(&os, &runner, &Cache::new(snapshot(NOW)));
    assert!(runner
        .commands
        .borrow()
        .iter()
        .all(|c| c.program.to_str() == Some("/usr/bin/dnf5")));
}
#[test]
fn shared_linux_storage_handles_encrypted_plain_and_lvm_roots_for_arch() {
    for (blocks, expected) in [
        (ENCRYPTED, Status::Pass),
        (
            include_str!("fixtures/blocks-plain-unrelated-luks.json"),
            Status::Fail,
        ),
        (
            include_str!("fixtures/blocks-lvm-encrypted.json"),
            Status::Pass,
        ),
        (
            include_str!("fixtures/blocks-luks-on-lvm.json"),
            Status::Pass,
        ),
    ] {
        let result = storage::encryption_in_environment(
            &Runner::new(vec![out(0, ROOT, ""), out(0, blocks, "")]),
            &Kernel::fixture(blocks),
            &host(),
        );
        assert_eq!(result.status, expected);
    }
}
#[test]
fn unknown_or_container_environment_blocks_host_storage_pass_and_fail() {
    for kind in [Kind::Container, Kind::Unknown] {
        for blocks in [
            ENCRYPTED,
            include_str!("fixtures/blocks-plain-unrelated-luks.json"),
        ] {
            let env = Environment {
                kind,
                reason: "fixture",
                probe_error: None,
            };
            let result = storage::encryption_in_environment(
                &Runner::new(vec![out(0, ROOT, ""), out(0, blocks, "")]),
                &Kernel::fixture(blocks),
                &env,
            );
            assert_eq!(result.status, Status::Warn);
            assert_eq!(result.reason_code, Reason::EncryptionInconclusive);
            let mut p = platform();
            p.os = linux::parse_os_release(ARCH, "fixture", false).unwrap();
            p.root = result;
            let mut policy = Policy::default();
            policy.checks.updates.enabled = false;
            assert_eq!(
                builtin::standalone_with_policy(&p, &FixedClock, &policy)
                    .unwrap()
                    .exit_code(),
                4
            );
        }
    }
}
#[test]
fn btrfs_and_unknown_backing_chains_remain_inconclusive_on_arch() {
    for (root, blocks) in [
        (include_str!("fixtures/root-btrfs.json"), ENCRYPTED),
        (ROOT, r#"{"blockdevices":[]}"#),
    ] {
        assert_eq!(
            storage::encryption_in_environment(
                &Runner::new(vec![out(0, root, ""), out(0, blocks, "")]),
                &Kernel::fixture(blocks),
                &host()
            )
            .status,
            Status::Warn
        );
    }
}
#[test]
fn arch_report_roundtrip_and_evaluation_preserve_observations_and_schema() {
    let (updates, _) = run(out(0, UPDATES, ""), &Cache::new(snapshot(NOW)));
    let mut p = platform();
    p.os = linux::parse_os_release(ARCH, "fixture", false).unwrap();
    p.updates = updates;
    let mut report = builtin::standalone(&p, &FixedClock).unwrap();
    let before = serde_json::to_string(&report).unwrap();
    let evaluation = baradwatchu_agent::policy::evaluate(&Policy::default(), &report).unwrap();
    assert_eq!(serde_json::to_string(&report).unwrap(), before);
    report.policy_evaluation = Some(evaluation);
    let text = serde_json::to_string(&report).unwrap();
    let restored: AuditReport = serde_json::from_str(&text).unwrap();
    assert_eq!(restored, report);
    assert_eq!(report.schema_version, "baradwatchu.audit-report.v1");
    assert_eq!(
        report
            .results
            .iter()
            .map(|r| r.check.id.as_str())
            .collect::<Vec<_>>(),
        ["SYS-OS-001", "SEC-001", "SEC-006"]
    );
    assert!(!text.contains("fixture-pkg"));
    assert!(!text.contains("6.18.1"));
    assert_eq!(report.exit_code(), 3);
    assert_eq!(
        report.results[0].outcome.evidence[0].values["fedoraChecksApplicable"],
        false
    );
    assert_eq!(
        report.results[0].outcome.evidence[0].values["archChecksApplicable"],
        true
    );
}
#[test]
fn metadata_reader_uses_only_existing_files_and_reports_missing_empty_or_wrong_type() {
    let root =
        std::env::temp_dir().join(format!("baradwatchu-arch-metadata-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let cleanup = Owned(root.clone());
    std::fs::create_dir(root.join("sync")).unwrap();
    std::fs::create_dir(root.join("local")).unwrap();
    assert!(SystemMetadata
        .snapshot(&root, &["core".into()])
        .unwrap()
        .repositories[0]
        .1
        .is_none());
    std::fs::write(root.join("sync/core.db"), "").unwrap();
    assert!(SystemMetadata
        .snapshot(&root, &["core".into()])
        .unwrap()
        .repositories[0]
        .1
        .is_none());
    std::fs::write(root.join("sync/core.db"), "owned fixture").unwrap();
    let before = std::fs::read(root.join("sync/core.db")).unwrap();
    let s = SystemMetadata.snapshot(&root, &["core".into()]).unwrap();
    assert!(s.repositories[0].1.is_some());
    assert!(s.local.is_some());
    assert_eq!(std::fs::read(root.join("sync/core.db")).unwrap(), before);
    assert!(SystemMetadata.snapshot(&root, &["../bad".into()]).is_err());
    std::fs::create_dir(root.join("sync/wrong.db")).unwrap();
    assert_eq!(
        SystemMetadata
            .snapshot(&root, &["wrong".into()])
            .unwrap_err()
            .reason,
        Reason::InvalidOutput
    );
    drop(cleanup);
}
struct Owned(PathBuf);
impl Drop for Owned {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.0).unwrap();
    }
}

#[test]
fn signature_and_crypto_engine_failures_preserve_partial_metadata_without_leaking_stderr() {
    let (result,_)=run(out(1,"","error: GPGME error: Invalid crypto engine\nerror: private-repo: missing required signature\n"),&Cache::new(snapshot(NOW-10)));
    assert_eq!(result.status, Status::Error);
    assert_eq!(facts(&result).metadata_state, MetadataState::Available);
    assert_eq!(facts(&result).classification, UpdateClass::Unknown);
    assert!(result
        .evidence
        .iter()
        .any(|e| e.values.get("cryptoEngineUnavailable") == Some(&serde_json::json!(true))));
    assert!(result.evidence.iter().any(
        |e| e.values.get("requiredDatabaseSignatureMissing") == Some(&serde_json::json!(true))
    ));
    assert!(!serde_json::to_string(&result)
        .unwrap()
        .contains("private-repo"));
}
