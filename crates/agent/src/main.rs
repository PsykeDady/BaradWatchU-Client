use baradwatchu_agent::{
    audit::SystemClock,
    checks::builtin,
    platform::{self, NativePlatform},
};
use std::{
    ffi::OsString,
    io::{self, Write},
    process::ExitCode,
};

enum Action {
    Bootstrap,
    Help,
    Version,
    Audit { json: bool },
}

fn parse(args: &[OsString]) -> Result<Action, &'static str> {
    match args {
        [] => Ok(Action::Bootstrap),
        [flag] if flag == "--version" || flag == "-V" => Ok(Action::Version),
        [flag] if flag == "--help" || flag == "-h" => Ok(Action::Help),
        [command, flag] if command == "audit" && (flag == "--help" || flag == "-h") => {
            Ok(Action::Help)
        }
        [command] if command == "audit" => Ok(Action::Audit { json: false }),
        [command, flag, format] if command == "audit" && flag == "--format" && format == "json" => {
            Ok(Action::Audit { json: true })
        }
        _ => Err("invalid arguments; use --help for usage"),
    }
}

fn execute(action: Action) -> Result<u8, String> {
    let (text, code) = match action {
        Action::Bootstrap => (format!("BaradWatchU Client {} bootstrap ({})\n", env!("CARGO_PKG_VERSION"), platform::current_platform()), 0),
        Action::Version => (format!("BaradWatchU Client {}\n", env!("CARGO_PKG_VERSION")), 0),
        Action::Help => (format!(
            "BaradWatchU Client {}\n\nUsage: baradwatchu-agent [OPTIONS]\n       baradwatchu-agent audit [--format json]\n\nOptions:\n  -h, --help       Show this help and exit\n  -V, --version    Show product version and exit\n\nNo arguments: identify the compile-time platform and exit (bootstrap).\nAudit: standalone read-only Fedora RPM/DNF5 checks; no server, UI,\nnetwork refresh, package changes or privilege escalation. Human output\nby default; JSON uses the independent baradwatchu.audit-report.v1 schema.\nCached update freshness and complex root storage can remain WARN.\n\nExit codes: 0 PASS/bootstrap/info; 1 execution error; 2 usage error;\n            3 noncompliance (FAIL); 4 inconclusive/unsupported (WARN).\nERROR takes precedence over FAIL, then WARN. Full service lifecycle,\npolicy validation and server communication remain unimplemented.\n", env!("CARGO_PKG_VERSION")), 0),
        Action::Audit { json } => {
            let report = builtin::standalone(&NativePlatform, &SystemClock)?;
            let code = report.exit_code();
            let text = if json {
                serde_json::to_string_pretty(&report).map_err(|error| error.to_string())? + "\n"
            } else { report.human_readable() };
            (text, code)
        }
    };
    io::stdout()
        .lock()
        .write_all(text.as_bytes())
        .map_err(|error| format!("Cannot write report/output: {error}"))?;
    Ok(code)
}

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    match parse(&args) {
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(2)
        }
        Ok(action) => match execute(action) {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::FAILURE
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn arguments(items: &[&str]) -> Vec<OsString> {
        items.iter().map(OsString::from).collect()
    }
    #[test]
    fn accepts_audit_formats_and_existing_cli() {
        assert!(matches!(
            parse(&arguments(&["audit"])),
            Ok(Action::Audit { json: false })
        ));
        assert!(matches!(
            parse(&arguments(&["audit", "--format", "json"])),
            Ok(Action::Audit { json: true })
        ));
        assert!(matches!(parse(&[]), Ok(Action::Bootstrap)));
        assert!(matches!(
            parse(&arguments(&["audit", "--help"])),
            Ok(Action::Help)
        ));
    }
    #[test]
    fn rejects_incomplete_unknown_and_conflicting_audit_options() {
        for args in [
            vec!["audit", "--format"],
            vec!["audit", "--format", "xml"],
            vec!["audit", "--offline"],
            vec!["audit", "--version"],
            vec!["audit", "--format", "json", "extra"],
        ] {
            assert!(parse(&arguments(&args)).is_err());
        }
    }
}
