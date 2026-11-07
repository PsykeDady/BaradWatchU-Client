#![cfg(target_os = "linux")]
mod common;
use baradwatchu_agent::{
    audit::{Outcome, Reason, Status},
    observation::{MetadataState, Observation, UpdateClass},
    platform::{
        command::{CommandOutput, CommandRunner, CommandSpec, ProbeError},
        fedora::{
            self,
            topology::{KernelDevice, KernelTopology},
        },
    },
};
use common::*;
const REPOS: &str = include_str!("fixtures/dnf-repos.json");
const CANDIDATES: &str = include_str!("fixtures/dnf-candidates.txt");
const ORDINARY: &str = include_str!("fixtures/dnf-advisory-ordinary.json");
const SECURITY: &str = include_str!("fixtures/dnf-advisory-security.json");
const ROOT: &str = include_str!("fixtures/root-ext4.json");
const BLOCKS: &str = include_str!("fixtures/blocks-encrypted.json");
fn update(repos: &str, candidates: &str, advisories: &str) -> (Outcome, Runner) {
    let runner = Runner::new(vec![
        out(100, "fixture table", ""),
        out(0, repos, ""),
        out(0, candidates, ""),
        out(0, advisories, ""),
    ]);
    let result = fedora::updates(&runner);
    (result, runner)
}
fn facts(outcome: &Outcome) -> &baradwatchu_agent::observation::Updates {
    match outcome.observation.as_ref().unwrap() {
        Observation::Updates(data) => data,
        _ => panic!("wrong observation"),
    }
}
#[test]
fn ordinary_advisories_classify_ordinary_not_security() {
    let (result, runner) = update(REPOS, CANDIDATES, ORDINARY);
    assert_eq!(facts(&result).classification, UpdateClass::OrdinaryPending);
    assert!(facts(&result).classification_complete);
    assert_eq!(facts(&result).security_advisories, Some(0));
    assert_eq!(facts(&result).ordinary_pending, Some(true));
    assert!(runner.outputs.borrow().is_empty());
}
#[test]
fn security_advisory_is_positive_evidence_even_when_superseded_by_newer_candidate() {
    for advisory in [
        SECURITY.to_owned(),
        SECURITY.replace("2.0-1.fc43", "1.5-1.fc43"),
    ] {
        let (result, _) = update(REPOS, CANDIDATES, &advisory);
        assert_eq!(facts(&result).classification, UpdateClass::SecurityPending);
        assert_eq!(facts(&result).security_advisories, Some(1));
    }
}
#[test]
fn absent_partial_or_unrecognized_advisories_do_not_imply_ordinary_updates() {
    let partial = format!("{CANDIDATES}another-pkg-0:2-1.fc43.x86_64\n");
    for (candidates, advisories) in [(CANDIDATES, "[]"), (partial.as_str(), ORDINARY)] {
        let (result, _) = update(REPOS, candidates, advisories);
        assert_eq!(facts(&result).classification, UpdateClass::UnknownSecurity);
        assert!(!facts(&result).classification_complete);
    }
    let mut list: serde_json::Value = serde_json::from_str(ORDINARY).unwrap();
    let mut future = list[0].clone();
    future["type"] = serde_json::json!("future_type");
    list.as_array_mut().unwrap().push(future);
    let (result, _) = update(REPOS, CANDIDATES, &list.to_string());
    assert_eq!(facts(&result).classification, UpdateClass::UnknownSecurity);
}
#[test]
fn security_positive_does_not_hide_unclassified_other_packages() {
    let packages = format!("{CANDIDATES}another-pkg-0:2-1.fc43.x86_64\n");
    let (result, _) = update(REPOS, &packages, SECURITY);
    assert_eq!(facts(&result).classification, UpdateClass::SecurityPending);
    assert!(!facts(&result).classification_complete);
    assert_eq!(facts(&result).pending_packages, Some(2));
}
#[test]
fn no_updates_and_missing_repositories_remain_distinct_facts() {
    for (repos, state) in [
        (REPOS, MetadataState::Available),
        ("[]", MetadataState::Missing),
    ] {
        let runner = Runner::new(vec![out(0, "", ""), out(0, repos, "")]);
        let result = fedora::updates(&runner);
        assert_eq!(facts(&result).classification, UpdateClass::NoPending);
        assert_eq!(facts(&result).metadata_state, state);
        assert_eq!(runner.commands.borrow().len(), 2);
    }
}
#[test]
fn all_four_dnf_queries_are_read_only_guarded_and_machine_readable() {
    let (_, runner) = update(REPOS, CANDIDATES, ORDINARY);
    let commands = runner.commands.borrow();
    assert_eq!(commands.len(), 4);
    for command in commands.iter() {
        assert_eq!(command.program.to_str().unwrap(), "/usr/bin/dnf5");
        assert!(command.read_only_filesystem);
        for flag in [
            "--cacheonly",
            "--no-plugins",
            "--skip-file-locks",
            "--quiet",
            "--setopt=*.build_cache=False",
            "--setopt=*.skip_if_unavailable=False",
            "--setopt=disable_excludes=*",
        ] {
            assert!(command.args.iter().any(|s| s == flag));
        }
        assert!(!command
            .args
            .iter()
            .any(|s| s == "--refresh" || s == "install" || s == "upgrade"));
    }
    assert!(commands[1].args.ends_with(&[
        "repo".into(),
        "info".into(),
        "--enabled".into(),
        "--json".into()
    ]));
    assert!(commands[3].args.ends_with(&[
        "advisory".into(),
        "list".into(),
        "--updates".into(),
        "--json".into()
    ]));
    assert!(commands[2].args.iter().any(|s| s == "--latest-limit=1"));
}
#[test]
fn auxiliary_cache_failures_preserve_missing_evidence_and_permission_errors() {
    for (stderr, status, reason) in [
        ("cache missing", Status::Warn, Reason::CacheUnavailable),
        (
            "cache missing: Operation not permitted",
            Status::Error,
            Reason::PermissionDenied,
        ),
        (
            "cache missing: Permission denied",
            Status::Error,
            Reason::PermissionDenied,
        ),
    ] {
        let runner = Runner::new(vec![out(100, "", ""), out(1, "", stderr)]);
        let result = fedora::updates(&runner);
        assert_eq!(result.status, status);
        assert_eq!(result.reason_code, reason);
        assert!(!result.evidence.is_empty());
        if status == Status::Warn {
            assert_eq!(facts(&result).metadata_state, MetadataState::Missing);
            assert!(!facts(&result).coverage_complete);
        }
        assert_eq!(runner.commands.borrow().len(), 2);
    }
}
#[test]
fn filters_missing_timestamps_and_duplicate_repositories_never_imply_complete_fresh_evidence() {
    let mut json: serde_json::Value = serde_json::from_str(REPOS).unwrap();
    json[0]["exclude_pkgs"] = serde_json::json!(["kernel*"]);
    let (result, _) = update(&json.to_string(), CANDIDATES, ORDINARY);
    assert!(!facts(&result).coverage_complete);
    json[0].as_object_mut().unwrap().remove("timestamp");
    let (result, _) = update(&json.to_string(), CANDIDATES, ORDINARY);
    assert_eq!(facts(&result).repositories[0].timestamp_unix_seconds, None);
    let duplicate = format!("[{},{}]", json[0], json[0]);
    let (result, _) = update(&duplicate, CANDIDATES, ORDINARY);
    assert_eq!(result.status, Status::Error);
}
#[test]
fn corrupt_or_inconsistent_query_outputs_are_explicit_errors() {
    for (repos, packages, advisories) in [
        ("{}", CANDIDATES, ORDINARY),
        (REPOS, "", ORDINARY),
        (REPOS, "invalid-package", ORDINARY),
        (REPOS, CANDIDATES, "{}"),
        (
            REPOS,
            CANDIDATES,
            r#"[{"name":"test","nevra":"invalid","type":"security"}]"#,
        ),
    ] {
        let (result, _) = update(repos, packages, advisories);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.reason_code, Reason::InvalidOutput);
    }
}
#[test]
fn structured_report_excludes_package_lists_repo_credentials_and_advisory_descriptions() {
    let mut json: serde_json::Value = serde_json::from_str(REPOS).unwrap();
    json[0]["base_url"] = serde_json::json!(["https://user:secret@example.invalid"]);
    let (result, _) = update(&json.to_string(), CANDIDATES, ORDINARY);
    let text = serde_json::to_string(&result).unwrap();
    assert!(!text.contains("secret"));
    assert!(!text.contains("fixture-pkg"));
}
struct Denied {
    reason: Reason,
    count: std::cell::Cell<usize>,
}
impl CommandRunner for Denied {
    fn run(&self, _: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        self.count.set(self.count.get() + 1);
        Err(ProbeError::new(self.reason, "synthetic denial"))
    }
}
#[test]
fn landlock_and_permission_failures_have_no_unguarded_retry() {
    for reason in [
        Reason::ReadOnlyGuardUnavailable,
        Reason::PermissionDenied,
        Reason::MissingTool,
        Reason::Timeout,
    ] {
        let runner = Denied {
            reason,
            count: std::cell::Cell::new(0),
        };
        let result = fedora::updates(&runner);
        assert_eq!(result.status, Status::Error);
        assert_eq!(result.reason_code, reason);
        assert_eq!(runner.count.get(), 1);
    }
}
fn encryption(blocks: &str, kernel: &dyn KernelTopology) -> Outcome {
    fedora::encryption_with_topology(
        &Runner::new(vec![out(0, ROOT, ""), out(0, blocks, "")]),
        kernel,
    )
}
#[test]
fn simple_luks_lvm_on_luks_and_luks_on_lvm_are_verified() {
    for blocks in [
        BLOCKS,
        include_str!("fixtures/blocks-lvm-encrypted.json"),
        include_str!("fixtures/blocks-luks-on-lvm.json"),
    ] {
        let result = encryption(blocks, &Kernel::fixture(blocks));
        assert_eq!(result.status, Status::Pass);
        match result.observation.unwrap() {
            Observation::RootEncryption(data) => assert!(data.topology_complete),
            _ => panic!(),
        }
    }
}
#[test]
fn kernel_extra_backing_device_rejects_incomplete_lsblk_graph() {
    let mut kernel = Kernel::fixture(BLOCKS);
    kernel
        .0
        .get_mut("253:0")
        .unwrap()
        .parents
        .push("8:99".into());
    assert_eq!(encryption(BLOCKS, &kernel).status, Status::Warn);
}
#[test]
fn kernel_visibility_and_mapping_identity_are_required() {
    let mut kernel = Kernel::fixture(BLOCKS);
    kernel.0.remove("253:0");
    assert_eq!(encryption(BLOCKS, &kernel).status, Status::Warn);
    let mut kernel = Kernel::fixture(BLOCKS);
    kernel.0.get_mut("253:0").unwrap().luks_mapping = false;
    assert_eq!(encryption(BLOCKS, &kernel).status, Status::Warn);
    let mut kernel = Kernel::fixture(BLOCKS);
    kernel.0.get_mut("253:0").unwrap().kind = "dm".into();
    assert_eq!(encryption(BLOCKS, &kernel).status, Status::Warn);
}
#[test]
fn mixed_multiple_root_paths_fail_and_all_encrypted_paths_pass() {
    let mixed = include_str!("fixtures/blocks-lvm-mixed.json");
    assert_eq!(
        encryption(mixed, &Kernel::fixture(mixed)).status,
        Status::Fail
    );
    let mut json: serde_json::Value = serde_json::from_str(mixed).unwrap();
    json["blockdevices"][1]["children"][0]["fstype"] = serde_json::json!("crypto_LUKS");
    let root = json["blockdevices"][1]["children"][0]["children"][0].clone();
    json["blockdevices"][1]["children"][0]["children"] = serde_json::json!([{"maj:min":"253:2","type":"crypt","fstype":"LVM2_member","children":[root]}]);
    let blocks = json.to_string();
    let result = encryption(&blocks, &Kernel::fixture(&blocks));
    assert_eq!(result.status, Status::Pass);
    match result.observation.unwrap() {
        Observation::RootEncryption(data) => assert_eq!(data.paths.len(), 2),
        _ => panic!(),
    }
}
struct KernelDenied;
impl KernelTopology for KernelDenied {
    fn inspect(&self, _: &str) -> Result<Option<KernelDevice>, ProbeError> {
        Err(ProbeError::new(
            Reason::PermissionDenied,
            "synthetic sysfs denial",
        ))
    }
}
#[test]
fn kernel_permission_error_is_not_compliance_or_an_unsupported_skip() {
    let result = encryption(BLOCKS, &KernelDenied);
    assert_eq!(result.status, Status::Error);
    assert_eq!(result.reason_code, Reason::PermissionDenied);
}
#[test]
fn unsupported_storage_types_remain_inconclusive() {
    for kind in ["raid1", "mpath", "dm", "loop"] {
        let blocks = BLOCKS.replace("\"disk\"", &format!("\"{kind}\""));
        assert_eq!(
            encryption(&blocks, &Kernel::fixture(&blocks)).status,
            Status::Warn
        );
    }
    let runner = Runner::new(vec![
        out(0, include_str!("fixtures/root-btrfs.json"), ""),
        out(0, BLOCKS, ""),
    ]);
    assert_eq!(
        fedora::encryption_with_topology(&runner, &Kernel::fixture(BLOCKS)).status,
        Status::Warn
    );
}
