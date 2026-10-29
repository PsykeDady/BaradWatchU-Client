use std::process::Command;

#[test]
fn bootstrap_exits_cleanly_without_service_or_ui() {
    let output = Command::new(env!("CARGO_BIN_EXE_baradwatchu-agent"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains(concat!(
        "BaradWatchU Client ",
        env!("CARGO_PKG_VERSION"),
        " bootstrap"
    )));
    assert!(stdout.contains(std::env::consts::OS));
    assert!(output.stderr.is_empty());
}

#[test]
fn informational_flags_do_not_run_bootstrap() {
    for flag in ["--version", "-V", "--help", "-h"] {
        let output = Command::new(env!("CARGO_BIN_EXE_baradwatchu-agent"))
            .arg(flag)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert!(String::from_utf8(output.stdout)
            .unwrap()
            .starts_with(concat!("BaradWatchU Client ", env!("CARGO_PKG_VERSION"))));
    }
}

#[test]
fn invalid_cli_returns_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_baradwatchu-agent"))
        .arg("--invalid")
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    #[cfg(unix)]
    {
        use std::{ffi::OsString, os::unix::ffi::OsStringExt};
        let output = Command::new(env!("CARGO_BIN_EXE_baradwatchu-agent"))
            .arg(OsString::from_vec(vec![b'-', b'-', 0xff]))
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("panicked"));
    }
}
