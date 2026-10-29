#![cfg(target_os = "linux")]
use baradwatchu_agent::{
    audit::{Clock, OperatingSystem, Outcome, Reason, Status},
    checks::builtin,
    platform::{
        command::{CommandOutput, CommandRunner, CommandSpec, ProbeError},
        fedora, linux, AuditPlatform,
    },
};
use std::{cell::RefCell, collections::VecDeque};

const FEDORA: &str = include_str!("fixtures/fedora.os-release");
const ROOT: &str = include_str!("fixtures/root-ext4.json");
const ENCRYPTED: &str = include_str!("fixtures/blocks-encrypted.json");
struct Runner {
    outputs: RefCell<VecDeque<Result<CommandOutput, ProbeError>>>,
    commands: RefCell<Vec<CommandSpec>>,
}
impl Runner {
    fn new(outputs: Vec<Result<CommandOutput, ProbeError>>) -> Self {
        Self {
            outputs: RefCell::new(outputs.into()),
            commands: RefCell::new(vec![]),
        }
    }
}
impl CommandRunner for Runner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        self.commands.borrow_mut().push(spec.clone());
        self.outputs
            .borrow_mut()
            .pop_front()
            .expect("Unexpected probe execution")
    }
}
fn output(code: i32, stdout: &str, stderr: &str) -> Result<CommandOutput, ProbeError> {
    Ok(CommandOutput {
        code: Some(code),
        stdout: stdout.into(),
        stderr: stderr.into(),
    })
}

#[test]
fn os_identity_uses_id_not_id_like_and_handles_quotes() {
    let os = linux::parse_os_release(FEDORA, "fixture", false).unwrap();
    assert!(os.supported);
    assert_eq!(os.version_id.as_deref(), Some("43"));
    assert_eq!(os.variant_id.as_deref(), Some("workstation"));
    for id in ["arch", "ubuntu", "debian", "rhel", "derivative"] {
        let text = format!("ID={id}\nNAME='Fixture Linux'\nID_LIKE=\"fedora rhel\"\n");
        let os = linux::parse_os_release(&text, "fixture", false).unwrap();
        assert!(!os.supported);
        assert_eq!(os.name.as_deref(), Some("Fixture Linux"));
    }
    let os = linux::parse_os_release(
        r#"ID=fedora
VERSION_ID=43
NAME="Fedora \"test\"""#,
        "fixture",
        false,
    )
    .unwrap();
    assert_eq!(os.name.as_deref(), Some("Fedora \"test\""));
}
#[test]
fn atomic_fedora_is_explicitly_outside_rpm_baseline() {
    assert!(
        !linux::parse_os_release(FEDORA, "fixture", true)
            .unwrap()
            .supported
    );
    for variant in ["silverblue", "coreos", "kinoite", "sway-atomic", "bootc"] {
        let text = format!("ID=fedora\nVERSION_ID=43\nVARIANT_ID={variant}");
        assert!(
            !linux::parse_os_release(&text, "fixture", false)
                .unwrap()
                .supported
        );
    }
}
#[test]
fn malformed_identity_is_rejected_without_shell_evaluation() {
    for text in [
        "ID=fedora\nVERSION_ID=",
        "ID=fedora\nVERSION_ID=rawhide",
        "ID=fedora\nVERSION_ID=43\nID=arch",
        "ID=\"$(touch bad)\"",
        "ID='fedora",
        "ID=Fedora",
        "NAME=example",
        "invalid",
    ] {
        assert!(
            linux::parse_os_release(text, "fixture", false).is_err(),
            "{text}"
        );
    }
}
#[test]
fn os_release_fallback_and_precedence() {
    let root = std::env::temp_dir().join(format!("baradwatchu-os-release-{}", std::process::id()));
    std::fs::create_dir(&root).unwrap();
    let primary = root.join("etc");
    let fallback = root.join("usr");
    std::fs::write(&fallback, FEDORA).unwrap();
    assert!(
        linux::read_identity(&primary, &fallback, false)
            .unwrap()
            .supported
    );
    std::fs::write(&primary, "ID=arch\nNAME=Arch").unwrap();
    assert!(
        !linux::read_identity(&primary, &fallback, false)
            .unwrap()
            .supported
    );
    std::fs::write(&primary, "ID=fedora\nVERSION_ID=invalid").unwrap();
    assert!(linux::read_identity(&primary, &fallback, false).is_err());
    std::fs::remove_file(&primary).unwrap();
    std::fs::remove_file(&fallback).unwrap();
    assert_eq!(
        linux::read_identity(&primary, &fallback, false)
            .unwrap_err()
            .reason,
        Reason::MissingOsRelease
    );
    std::fs::remove_dir(&root).unwrap();
}

#[test]
fn dnf_available_updates_are_fail_and_command_is_cache_only() {
    let runner = Runner::new(vec![output(
        100,
        include_str!("fixtures/dnf-updates.txt"),
        "",
    )]);
    let result = fedora::updates(&runner);
    assert_eq!(result.status, Status::Fail);
    assert_eq!(result.reason_code, Reason::UpdatesAvailable);
    let commands = runner.commands.borrow();
    assert_eq!(commands[0].program.to_str().unwrap(), "/usr/bin/dnf5");
    assert!(commands[0].read_only_filesystem);
    for arg in [
        "--cacheonly",
        "--no-plugins",
        "--skip-file-locks",
        "--setopt=logdir=/dev/null",
        "--setopt=build_cache=False",
        "--setopt=*.build_cache=False",
        "--setopt=*.skip_if_unavailable=False",
        "check-upgrade",
    ] {
        assert!(commands[0].args.iter().any(|s| s == arg));
    }
    assert!(!commands[0]
        .args
        .iter()
        .any(|s| s == "--refresh" || s == "upgrade" || s == "install"));
}
#[test]
fn no_updates_in_cache_is_not_certified_current_compliance() {
    let runner = Runner::new(vec![output(
        0,
        "",
        "Dropping all logs. To redirect the log file location use logdir.",
    )]);
    let result = fedora::updates(&runner);
    assert_eq!(result.status, Status::Warn);
    assert_eq!(result.reason_code, Reason::NoCachedUpdates);
    assert_eq!(result.evidence[0].values["cacheFreshnessVerified"], false);
}
#[test]
fn absent_cache_and_repositories_remain_inconclusive() {
    for (code, stderr, reason) in [
        (
            1,
            include_str!("fixtures/dnf-cache-missing.txt"),
            Reason::CacheUnavailable,
        ),
        (0, "No enabled repositories", Reason::NoEnabledRepositories),
    ] {
        let result = fedora::updates(&Runner::new(vec![output(code, "", stderr)]));
        assert_eq!(result.status, Status::Warn);
        assert_eq!(result.reason_code, reason);
    }
}
#[test]
fn missing_dnf_tool_is_error_without_other_command_fallback() {
    let runner = Runner::new(vec![Err(ProbeError::new(
        Reason::MissingTool,
        "DNF5 missing",
    ))]);
    let result = fedora::updates(&runner);
    assert_eq!(result.status, Status::Error);
    assert_eq!(result.reason_code, Reason::MissingTool);
    assert_eq!(runner.commands.borrow().len(), 1);
}
#[test]
fn dnf_permission_execution_and_timeout_are_errors() {
    for (input, reason) in [
        (output(1, "", "Permission denied"), Reason::PermissionDenied),
        (output(2, "", "Unknown option"), Reason::ExecutionFailed),
        (
            Err(ProbeError::new(Reason::Timeout, "deadline")),
            Reason::Timeout,
        ),
        (
            Ok(CommandOutput {
                code: None,
                stdout: "".into(),
                stderr: "".into(),
            }),
            Reason::ExecutionFailed,
        ),
    ] {
        let result = fedora::updates(&Runner::new(vec![input]));
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.reason_code, reason);
    }
}

fn encryption(root: &str, blocks: &str) -> Outcome {
    fedora::encryption(&Runner::new(vec![
        output(0, root, ""),
        output(0, blocks, ""),
    ]))
}
#[test]
fn encrypted_root_and_lvm_on_luks_pass() {
    for blocks in [
        ENCRYPTED,
        include_str!("fixtures/blocks-lvm-encrypted.json"),
    ] {
        let result = encryption(ROOT, blocks);
        assert_eq!(result.status, Status::Pass);
        assert_eq!(result.reason_code, Reason::RootEncrypted);
        assert_eq!(result.evidence[0].values["encryptedPaths"], 1);
    }
}
#[test]
fn unrelated_luks_never_proves_root_encryption() {
    let result = encryption(
        ROOT,
        include_str!("fixtures/blocks-plain-unrelated-luks.json"),
    );
    assert_eq!(result.status, Status::Fail);
    assert_eq!(result.reason_code, Reason::RootUnencrypted);
}
#[test]
fn every_root_backing_path_must_be_encrypted() {
    let mut blocks: serde_json::Value = serde_json::from_str(ENCRYPTED).unwrap();
    let plain: serde_json::Value =
        serde_json::from_str(include_str!("fixtures/blocks-plain-unrelated-luks.json")).unwrap();
    blocks["blockdevices"]
        .as_array_mut()
        .unwrap()
        .push(plain["blockdevices"][0].clone());
    let result = encryption(ROOT, &blocks.to_string());
    assert_eq!(result.status, Status::Fail);
    assert_eq!(result.evidence[0].values["rootBackingPaths"], 2);
}
#[test]
fn btrfs_container_missing_device_and_unknown_mapping_are_inconclusive() {
    for (root, blocks) in [
        (
            include_str!("fixtures/root-btrfs.json").to_owned(),
            ENCRYPTED.to_owned(),
        ),
        (ROOT.replace("ext4", "overlay"), ENCRYPTED.to_owned()),
        (ROOT.to_owned(), r#"{"blockdevices":[]}"#.to_owned()),
        (ROOT.to_owned(), ENCRYPTED.replace("crypto_LUKS", "unknown")),
        (ROOT.to_owned(), ENCRYPTED.replace("\"disk\"", "\"loop\"")),
        (ROOT.to_owned(), ENCRYPTED.replace("\"crypt\"", "\"raid1\"")),
    ] {
        let result = encryption(&root, &blocks);
        assert_eq!(result.status, Status::Warn);
        assert_eq!(result.reason_code, Reason::EncryptionInconclusive);
    }
}
#[test]
fn malformed_or_incomplete_json_is_error() {
    for (root, blocks) in [
        ("not JSON", ENCRYPTED),
        (ROOT, "{}"),
        ("{\"filesystems\":[]}", ENCRYPTED),
        (
            "{\"filesystems\":[{\"target\":\"/home\",\"fstype\":\"ext4\",\"maj:min\":\"253:0\"}]}",
            ENCRYPTED,
        ),
    ] {
        let result = encryption(root, blocks);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.reason_code, Reason::InvalidOutput);
    }
}
#[test]
fn disk_tool_missing_or_denied_cannot_pass() {
    let missing = Runner::new(vec![Err(ProbeError::new(
        Reason::MissingTool,
        "findmnt missing",
    ))]);
    assert_eq!(
        fedora::encryption(&missing).reason_code,
        Reason::MissingTool
    );
    let denied = Runner::new(vec![
        output(0, ROOT, ""),
        output(1, "", "Permission denied"),
    ]);
    let result = fedora::encryption(&denied);
    assert_eq!(result.status, Status::Error);
    assert_eq!(result.reason_code, Reason::PermissionDenied);
    let missing_lsblk = Runner::new(vec![
        output(0, ROOT, ""),
        Err(ProbeError::new(Reason::MissingTool, "lsblk missing")),
    ]);
    assert_eq!(fedora::encryption(&missing_lsblk).status, Status::Error);
}

struct FixtureFedora(Runner);
impl AuditPlatform for FixtureFedora {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        linux::parse_os_release(FEDORA, "fixture", false)
    }
    fn pending_updates(&self) -> Outcome {
        fedora::updates(&self.0)
    }
    fn root_encryption(&self) -> Outcome {
        fedora::encryption(&self.0)
    }
}
#[test]
fn complete_fedora_vertical_slice_uses_only_fixture_commands() {
    struct ClockFixture;
    impl Clock for ClockFixture {
        fn now_unix_ms(&self) -> Result<u64, String> {
            Ok(123456789)
        }
    }
    let platform = FixtureFedora(Runner::new(vec![
        output(100, include_str!("fixtures/dnf-updates.txt"), ""),
        output(0, ROOT, ""),
        output(0, ENCRYPTED, ""),
    ]));
    let report = builtin::standalone(&platform, &ClockFixture).unwrap();
    assert_eq!(report.summary.pass, 2);
    assert_eq!(report.summary.fail, 1);
    assert_eq!(report.exit_code(), 3);
    assert!(serde_json::to_value(report).unwrap().is_object());
    assert!(platform.0.outputs.borrow().is_empty());
}

#[test]
fn unknown_dnf_option_and_guard_failure_are_execution_errors() {
    for input in [
        output(2, "", "Unknown argument --cacheonly"),
        Err(ProbeError::new(
            Reason::ReadOnlyGuardUnavailable,
            "kernel guard not available",
        )),
    ] {
        assert_eq!(
            fedora::updates(&Runner::new(vec![input])).status,
            Status::Error
        );
    }
}
#[test]
fn invalid_device_identifiers_and_conflicting_root_metadata_do_not_pass() {
    let invalid = encryption(
        &ROOT.replace("253:0", "invalid"),
        &ENCRYPTED.replace("253:0", "invalid"),
    );
    assert_eq!(invalid.status, Status::Error);
    let conflict = encryption(ROOT, &ENCRYPTED.replace("ext4", "xfs"));
    assert_eq!(conflict.status, Status::Warn);
}
