use std::process::Command;

/// The binary must never read or migrate the developer's real configuration in tests.
fn agent() -> Command {
    let root = std::env::temp_dir().join(format!("bwu-cli-test-{}", std::process::id()));
    let mut command = Command::new(env!("CARGO_BIN_EXE_baradwatchu-agent"));
    command
        .env("XDG_CONFIG_HOME", root.join("config"))
        .env("XDG_STATE_HOME", root.join("state"))
        .env("XDG_CACHE_HOME", root.join("cache"));
    command
}

#[test]
fn no_arguments_prints_local_cli_usage_without_service_or_ui() {
    let output = agent().output().unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.starts_with(concat!("BaradWatchU Client ", env!("CARGO_PKG_VERSION"))));
    assert!(stdout.contains("baradwatchu-agent audit [--json]"));
    assert!(output.stderr.is_empty());
}

#[test]
fn informational_flags_do_not_run_bootstrap() {
    for flag in ["--version", "-V", "--help", "-h"] {
        let output = agent().arg(flag).output().unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .starts_with(concat!("BaradWatchU Client ", env!("CARGO_PKG_VERSION"))));
    }
}

#[test]
fn invalid_cli_returns_usage_error() {
    let output = agent().arg("--invalid").output().unwrap();
    assert_eq!(output.status.code(), Some(2));
    #[cfg(unix)]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let output = agent()
            .arg(OsString::from_vec(vec![b'-', b'-', 0xff]))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}
