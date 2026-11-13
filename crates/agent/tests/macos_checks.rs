// Exercises the macOS built-in scripts (catalog/checks-macos) on the host that runs the tests:
// output contract, parameter validation and the offline hosts-list method. Results depend on
// the host's real configuration, so only the contract (not PASS/FAIL) is asserted for the
// live checks. REQ-001 contacts Apple's update catalog and is opt-in (`--ignored`).
#![cfg(target_os = "macos")]

use serde_json::Value;
use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

const STATUSES: [&str; 5] = ["PASS", "FAIL", "WARN", "ERROR", "NOT_APPLICABLE"];

fn catalog() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../catalog/checks-macos")
}

/// Runs a built-in tool the way the agent does: clean environment, fixed PATH, its folder as
/// working directory and the parameters as `{"requirementId","parameters"}` on stdin.
fn run(relative: &str, parameters: Option<Value>) -> Value {
    let tool = catalog().join(relative);
    let mut command = Command::new(&tool);
    command
        .current_dir(tool.parent().unwrap())
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .stdin(if parameters.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for name in ["HOME", "USER", "LOGNAME", "LANG"] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = command.spawn().unwrap();
    if let Some(parameters) = parameters {
        let input = serde_json::json!({"requirementId": "REQ", "parameters": parameters});
        child
            .stdin
            .take()
            .unwrap()
            .write_all(input.to_string().as_bytes())
            .unwrap();
    }
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{relative}: {output:?}");
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{relative}: invalid JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn assert_contract(value: &Value, id: &str) {
    let object = value.as_object().unwrap();
    let mut keys = object.keys().map(String::as_str).collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, ["details", "id", "status", "summary"], "{value}");
    assert_eq!(value["id"], id, "{value}");
    assert!(
        STATUSES.contains(&value["status"].as_str().unwrap()),
        "{value}"
    );
    assert!(!value["summary"].as_str().unwrap().is_empty(), "{value}");
    assert!(value["details"]
        .as_array()
        .unwrap()
        .iter()
        .all(Value::is_string));
}

#[test]
fn every_live_check_follows_the_builtin_output_contract() {
    for (tool, id, parameters) in [
        (
            "REQ-002/providers/xprotect.sh",
            "REQ-002",
            Some(serde_json::json!({"maxSignatureAgeDays": 30})),
        ),
        (
            "REQ-002/providers/bitdefender-gravityzone.sh",
            "REQ-002",
            Some(serde_json::json!({"maxSignatureAgeDays": 3, "expectedCompanyId": ""})),
        ),
        ("REQ-003/check.sh", "REQ-003", None),
        (
            "REQ-004/check.sh",
            "REQ-004",
            Some(
                serde_json::json!({"minimumHostsEntries": 10000, "minimumDnsmasqRules": 1000, "maxListAgeDays": 30, "requireHagezi": true}),
            ),
        ),
        ("REQ-005/check.sh", "REQ-005", None),
        ("REQ-006/check.sh", "REQ-006", None),
        (
            "REQ-007/check.sh",
            "REQ-007",
            Some(serde_json::json!({"maxTimeoutMinutes": 5, "maxLockGraceSeconds": 0})),
        ),
        (
            "REQ-008/check.sh",
            "REQ-008",
            Some(
                serde_json::json!({"maxPasswordAgeDays": 60, "minimumLength": 14, "requireComplexity": true}),
            ),
        ),
        ("REQ-009/check.sh", "REQ-009", None),
    ] {
        let value = run(tool, parameters);
        assert_contract(&value, id);
        assert_ne!(value["status"], "ERROR", "{tool}: {value}");
    }
}

#[test]
#[ignore = "contacts Apple's software update catalog"]
fn software_updates_follow_the_builtin_output_contract() {
    let value = run("REQ-001/check.sh", None);
    assert_contract(&value, "REQ-001");
    assert_ne!(value["status"], "ERROR", "{value}");
}

#[test]
fn invalid_parameters_are_errors_and_nothing_is_evaluated() {
    for (tool, parameters) in [
        (
            "REQ-002/providers/xprotect.sh",
            serde_json::json!({"maxSignatureAgeDays": "30"}),
        ),
        (
            "REQ-002/providers/bitdefender-gravityzone.sh",
            serde_json::json!({"maxSignatureAgeDays": -1}),
        ),
        (
            "REQ-002/providers/bitdefender-gravityzone.sh",
            serde_json::json!({"expectedCompanyId": 7}),
        ),
        (
            "REQ-004/check.sh",
            serde_json::json!({"requireHagezi": "yes"}),
        ),
        (
            "REQ-004/check.sh",
            serde_json::json!({"minimumHostsEntries": 1.5}),
        ),
        (
            "REQ-007/check.sh",
            serde_json::json!({"maxTimeoutMinutes": "5"}),
        ),
        (
            "REQ-008/check.sh",
            serde_json::json!({"requireComplexity": 1}),
        ),
        (
            "REQ-008/check.sh",
            serde_json::json!({"minimumLength": -14}),
        ),
    ] {
        let value = run(tool, Some(parameters));
        assert_eq!(value["status"], "ERROR", "{tool}: {value}");
        assert_eq!(value["details"], serde_json::json!([]), "{tool}: {value}");
    }
}

#[test]
fn strict_limits_are_applied_to_the_observed_configuration() {
    // A zero-minute lock limit can never be met by a real inactivity timer.
    let value = run(
        "REQ-007/check.sh",
        Some(serde_json::json!({"maxTimeoutMinutes": 0, "maxLockGraceSeconds": 0})),
    );
    assert_ne!(value["status"], "PASS", "{value}");
    // No real policy keeps passwords valid for zero days or requires 4096 characters.
    let value = run(
        "REQ-008/check.sh",
        Some(serde_json::json!({"maxPasswordAgeDays": 0, "minimumLength": 4096})),
    );
    assert!(
        ["FAIL", "WARN"].contains(&value["status"].as_str().unwrap()),
        "{value}"
    );
}

#[test]
fn bitdefender_absent_installation_fails_and_never_passes() {
    let value = run(
        "REQ-002/providers/bitdefender-gravityzone.sh",
        Some(serde_json::json!({"installDir": "/nonexistent/Bitdefender/AVP"})),
    );
    assert_eq!(value["status"], "FAIL", "{value}");
    assert!(value["summary"]
        .as_str()
        .unwrap()
        .contains("non risulta installato"));
    // With the real host state the provider can be at best WARN: on-access is unobservable.
    let value = run(
        "REQ-002/providers/bitdefender-gravityzone.sh",
        Some(serde_json::json!({})),
    );
    assert_ne!(value["status"], "PASS", "{value}");
}

fn hosts_method(contents: &str, arguments: &[&str]) -> String {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let file = std::env::temp_dir().join(format!("baradwatchu-macos-hosts-{nonce}"));
    fs::write(&file, contents).unwrap();
    let output = Command::new(catalog().join("REQ-004/hosts.sh"))
        .args(arguments)
        .arg(&file)
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .output()
        .unwrap();
    fs::remove_file(&file).unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout).unwrap()
}

fn hagezi(modified: &str, declared: usize, lines: usize) -> String {
    let mut text = format!(
        "127.0.0.1 localhost\n# Title: HaGeZi's Light DNS Blocklist\n# Homepage: https://github.com/hagezi/dns-blocklists\n# Last modified: {modified}\n# Number of entries: {declared}\n"
    );
    for index in 0..lines {
        text.push_str(&format!("0.0.0.0 ads{index}.example\n"));
    }
    text
}

#[test]
fn hosts_list_method_uses_bsd_dates_and_the_linux_contract() {
    let now = Command::new("/bin/date")
        .args(["-u", "+%d %b %Y %H:%M UTC"])
        .env("LC_ALL", "C")
        .output()
        .unwrap();
    let today = String::from_utf8(now.stdout).unwrap();
    let today = today.trim();
    let code = |text: &str| text.split('|').next().unwrap().to_owned();
    assert_eq!(
        code(&hosts_method(&hagezi(today, 12, 12), &["10", "30", "true"])),
        "PRESENT"
    );
    assert_eq!(
        code(&hosts_method(
            &hagezi("01 Jan 2020 10:00 UTC", 12, 12),
            &["10", "30", "true"]
        )),
        "STALE"
    );
    assert_eq!(
        code(&hosts_method(&hagezi(today, 20, 12), &["10", "30", "true"])),
        "INCOMPLETE"
    );
    assert_eq!(
        code(&hosts_method(&hagezi(today, 5, 5), &["10", "30", "true"])),
        "FEW"
    );
    let plain = "0.0.0.0 a.example\n0.0.0.0 b.example\n";
    assert_eq!(
        code(&hosts_method(plain, &["1", "30", "true"])),
        "NOT_HAGEZI"
    );
    assert_eq!(code(&hosts_method(plain, &["1", "30", "false"])), "PRESENT");
    assert_eq!(
        code(&hosts_method("127.0.0.1 localhost\n", &["1", "30", "true"])),
        "ABSENT"
    );
}
