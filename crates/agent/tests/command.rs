#![cfg(unix)]
use baradwatchu_agent::{
    audit::Reason,
    platform::command::{CommandRunner, CommandSpec, SystemRunner},
};
use std::time::Duration;

#[test]
fn captures_stdout_stderr_and_nonzero_exit_without_treating_it_as_spawn_error() {
    let result = SystemRunner
        .run(&CommandSpec::new(
            "/bin/sh",
            &["-c", "printf fixture; printf diagnostic >&2; exit 7"],
        ))
        .unwrap();
    assert_eq!(result.code, Some(7));
    assert_eq!(result.stdout, "fixture");
    assert_eq!(result.stderr, "diagnostic");
}
#[test]
fn missing_program_is_structured_error() {
    let error = SystemRunner
        .run(&CommandSpec::new(
            "/baradwatchu-nonexistent-fixture-tool",
            &[],
        ))
        .unwrap_err();
    assert_eq!(error.reason, Reason::MissingTool);
}
#[test]
fn spawn_permission_error_is_structured() {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    let path = std::env::temp_dir().join(format!(
        "baradwatchu-nonexec-fixture-{}",
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(b"#!/bin/sh\nexit 0\n").unwrap();
    drop(file);
    let error = SystemRunner
        .run(&CommandSpec::new(path.to_str().unwrap(), &[]))
        .unwrap_err();
    std::fs::remove_file(path).unwrap();
    assert_eq!(error.reason, Reason::PermissionDenied);
}
#[test]
fn timeout_terminates_owned_command_group() {
    let mut spec = CommandSpec::new("/bin/sh", &["-c", "sleep 10 & wait"]);
    spec.timeout = Duration::from_millis(40);
    let start = std::time::Instant::now();
    assert_eq!(SystemRunner.run(&spec).unwrap_err().reason, Reason::Timeout);
    assert!(start.elapsed() < Duration::from_secs(3));
}
#[test]
fn excessive_output_is_bounded_and_not_parsed_as_valid() {
    let mut spec = CommandSpec::new("/bin/sh", &["-c", "while :; do printf 1234567890; done"]);
    spec.output_limit = 64;
    assert_eq!(
        SystemRunner.run(&spec).unwrap_err().reason,
        Reason::OutputLimit
    );
}
#[test]
fn invalid_utf8_output_is_error() {
    let error = SystemRunner
        .run(&CommandSpec::new("/bin/sh", &["-c", "printf '\\377'"]))
        .unwrap_err();
    assert_eq!(error.reason, Reason::InvalidOutput);
}
#[test]
fn environment_is_minimal_and_locale_is_deterministic() {
    let result = SystemRunner
        .run(&CommandSpec::new("/usr/bin/env", &[]))
        .unwrap();
    let mut lines: Vec<_> = result.stdout.lines().collect();
    lines.sort_unstable();
    assert_eq!(
        lines,
        [
            "DNF5_FORCE_INTERACTIVE=0",
            "DNF5_PLUGINS_DIR=",
            "LANG=C",
            "LC_ALL=C",
            "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
            "TZ=UTC"
        ]
    );
}

#[test]
fn only_explicit_kconfig_environment_is_added_to_clean_environment() {
    let mut spec = CommandSpec::new("/usr/bin/env", &[]);
    for (key, value) in [
        ("HOME", "/home/fixture with spaces"),
        ("XDG_CONFIG_HOME", "/home/fixture with spaces/.config"),
        ("XDG_CONFIG_DIRS", "/etc/xdg"),
    ] {
        spec.config_environment.insert(key.into(), value.into());
    }
    let output = SystemRunner.run(&spec).unwrap();
    assert!(output
        .stdout
        .lines()
        .any(|l| l == "HOME=/home/fixture with spaces"));
    assert!(output.stdout.lines().any(|l| l == "LC_ALL=C"));
    assert!(!output.stdout.contains("DBUS_SESSION_BUS_ADDRESS="));
    assert!(!output.stdout.contains("LD_PRELOAD="));
}

#[test]
fn inherited_bus_loader_path_and_proxy_overrides_are_rejected_before_spawn() {
    for key in [
        "DBUS_SESSION_BUS_ADDRESS",
        "LD_PRELOAD",
        "PATH",
        "HTTPS_PROXY",
        "QT_PLUGIN_PATH",
    ] {
        let mut spec = CommandSpec::new("/baradwatchu-nonexistent-fixture-tool", &[]);
        spec.config_environment.insert(key.into(), "unsafe".into());
        assert_eq!(
            SystemRunner.run(&spec).unwrap_err().reason,
            Reason::InvalidOutput
        );
    }
}

#[test]
fn missing_read_only_tool_is_not_misreported_as_guard_failure() {
    let mut spec = CommandSpec::new("/baradwatchu-nonexistent-fixture-tool", &[]);
    spec.read_only_filesystem = true;
    assert_eq!(
        SystemRunner.run(&spec).unwrap_err().reason,
        Reason::MissingTool
    );
}

#[cfg(target_os = "linux")]
#[test]
fn landlock_prevents_probe_writes_or_fails_before_execution() {
    let directory = std::env::temp_dir().join(format!(
        "baradwatchu-read-only-fixture-{}",
        std::process::id()
    ));
    std::fs::create_dir(&directory).unwrap();
    let original = directory.join("original");
    let new = directory.join("new");
    let subdir = directory.join("subdir");
    std::fs::write(&original, "unchanged").unwrap();
    let mut spec = CommandSpec::new(
        "/bin/sh",
        &[
            "-c",
            "printf changed > \"$1\"; rm -f \"$1\"; printf created > \"$2\"; mkdir \"$3\"",
            "fixture",
        ],
    );
    spec.args.extend([
        original.to_string_lossy().into_owned(),
        new.to_string_lossy().into_owned(),
        subdir.to_string_lossy().into_owned(),
    ]);
    spec.read_only_filesystem = true;
    match SystemRunner.run(&spec) {
        Ok(output) => {
            assert_ne!(output.code, Some(0));
            assert!(
                output.stderr.contains("Permission denied")
                    || output.stderr.contains("Operation not permitted")
            );
            eprintln!("Landlock enforcement executed: file create/write/unlink/mkdir denied");
        }
        Err(error) => {
            assert_eq!(error.reason, Reason::ReadOnlyGuardUnavailable);
            eprintln!("Landlock unavailable: verified fail-closed execution only");
        }
    }
    assert_eq!(std::fs::read_to_string(&original).unwrap(), "unchanged");
    assert!(!new.exists());
    assert!(!subdir.exists());
    // Parent remains unrestricted; cleanup is limited to this fixture directory.
    std::fs::remove_file(original).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[cfg(target_os = "linux")]
#[test]
fn null_device_exception_preserves_file_write_denial() {
    let directory =
        std::env::temp_dir().join(format!("baradwatchu-null-guard-{}", std::process::id()));
    std::fs::create_dir(&directory).unwrap();
    let original = directory.join("original");
    std::fs::write(&original, "unchanged").unwrap();
    let mut spec = CommandSpec::new(
        "/bin/sh",
        &["-c", "exec 3<>/dev/null || exit 10; printf safe >&3; if printf changed > \"$1\" 2>/dev/null; then exit 11; fi; if rm -f \"$1\" 2>/dev/null; then exit 12; fi; if mkdir \"$2\" 2>/dev/null; then exit 13; fi; if (exec 4<>/dev/zero) 2>/dev/null; then exit 14; fi", "fixture"],
    );
    spec.args.push(original.to_string_lossy().into_owned());
    spec.args
        .push(directory.join("new").to_string_lossy().into_owned());
    spec.read_only_filesystem = true;
    let denied = SystemRunner.run(&spec);
    spec.allow_null_device = true;
    let allowed = SystemRunner.run(&spec);
    match (denied, allowed) {
        (Ok(denied), Ok(allowed)) => {
            assert_ne!(denied.code, Some(0));
            assert_eq!(allowed.code, Some(0));
        }
        (Err(a), Err(b)) => {
            assert_eq!(a.reason, Reason::ReadOnlyGuardUnavailable);
            assert_eq!(b.reason, Reason::ReadOnlyGuardUnavailable);
        }
        other => panic!("inconsistent guard outcomes: {other:?}"),
    }
    assert_eq!(std::fs::read_to_string(&original).unwrap(), "unchanged");
    assert!(!directory.join("new").exists());
    std::fs::remove_file(original).unwrap();
    std::fs::remove_dir(directory).unwrap();
}

#[test]
fn null_device_exception_requires_guard() {
    let mut spec = CommandSpec::new("/usr/bin/env", &[]);
    spec.allow_null_device = true;
    assert_eq!(
        SystemRunner.run(&spec).unwrap_err().reason,
        Reason::InvalidOutput
    );
}
