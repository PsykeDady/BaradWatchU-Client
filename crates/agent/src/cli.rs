//! User-facing CLI for the local requirement catalog.
use std::ffi::OsString;

#[derive(Debug)]
pub struct Output {
    pub text: String,
    pub code: u8,
}

#[derive(Debug)]
pub struct Error {
    pub message: String,
    pub code: u8,
}

pub fn run(args: &[OsString]) -> Result<Output, Error> {
    match args {
        [] => {
            return Ok(Output {
                text: crate::requirements::help(),
                code: 0,
            });
        }
        [arg] if arg == "--help" || arg == "-h" => {
            return Ok(Output {
                text: crate::requirements::help(),
                code: 0,
            });
        }
        [arg] if arg == "--version" || arg == "-V" => {
            return Ok(Output {
                text: format!("BaradWatchU Client {}\n", env!("CARGO_PKG_VERSION")),
                code: 0,
            });
        }
        _ => {}
    }
    let routed = match args.first().and_then(|arg| arg.to_str()) {
        Some("consent") => Some(crate::consent::run(&args[1..])),
        Some("notifications") => Some(crate::events::run_notifications(&args[1..])),
        Some("events") => Some(crate::events::run_events(&args[1..])),
        Some("history") => Some(crate::history::run(&args[1..])),
        Some("report-theme") => Some(crate::pdf::run_theme(&args[1..])),
        Some("identity") => Some(crate::identity::run_identity(&args[1..])),
        Some("trust") => Some(crate::identity::run_trust(&args[1..])),
        Some("remote") => Some(crate::remote::run(&args[1..])),
        Some("service") => Some(crate::service::run(&args[1..])),
        Some("quit") => Some(if args.len() == 1 {
            crate::dashboard::quit()
                .map(|text| crate::requirements::CliOutput { text, code: 0 })
                .map_err(crate::requirements::CliError)
        } else {
            Err(crate::requirements::CliError("Usage: quit".into()))
        }),
        _ => None,
    };
    routed
        .unwrap_or_else(|| crate::requirements::run(args))
        .map(|output| Output {
            text: output.text,
            code: output.code,
        })
        .map_err(|error| Error {
            message: baradwatchu_messages::localize_diagnostic(
                &error.0,
                baradwatchu_messages::configured_language(),
            ),
            code: 2,
        })
}
