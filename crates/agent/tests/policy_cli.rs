use baradwatchu_agent::cli;
use std::ffi::OsString;

#[test]
fn legacy_commands_and_options_are_rejected() {
    // Isolate XDG paths: the CLI may scan configuration before rejecting an option.
    let root = std::env::temp_dir().join(format!("bwu-policy-cli-{}", std::process::id()));
    std::env::set_var("XDG_CONFIG_HOME", root.join("config"));
    std::env::set_var("XDG_STATE_HOME", root.join("state"));
    for command in [
        vec!["workstation", "list"],
        vec!["workstation", "audit"],
        vec!["policy", "validate", "policies/default.json"],
        vec!["audit", "--policy", "policies/default.json"],
        vec!["audit", "--format", "json"],
        vec!["audit", "--local-config", "config.json"],
    ] {
        let args = command.iter().map(OsString::from).collect::<Vec<_>>();
        let error = cli::run(&args).expect_err("legacy command must be removed");
        assert_eq!(error.code, 2, "command: {command:?}");
        assert!(error.message.contains("Usage"), "command: {command:?}");
    }
}
