use baradwatchu_agent::cli;
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    // sudo started this executable as SUDO_ASKPASS for a privileged check (Barad Policy):
    // show the password dialog with the reason, print the answer for sudo only.
    if std::env::var_os(baradwatchu_agent::elevation::ASKPASS_VARIABLE).is_some() {
        let prompt = args
            .first()
            .map(|arg| arg.to_string_lossy().into_owned())
            .unwrap_or_default();
        return match baradwatchu_agent::elevation::askpass(&prompt) {
            Some(password) => {
                let mut out = io::stdout().lock();
                let _ = writeln!(out, "{password}");
                ExitCode::SUCCESS
            }
            None => ExitCode::FAILURE,
        };
    }
    if args.first().is_some_and(|arg| arg == "dashboard") {
        let options = match baradwatchu_agent::dashboard::parse_options(&args[1..]) {
            Ok(options) => options,
            Err(usage) => {
                eprintln!(
                    "{}: {usage}",
                    baradwatchu_agent::messages::message(
                        "cli.error",
                        baradwatchu_messages::configured_language()
                    )
                );
                return ExitCode::from(2);
            }
        };
        return match baradwatchu_agent::dashboard::run(options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                let error = baradwatchu_messages::localize_diagnostic(
                    &error,
                    baradwatchu_messages::configured_language(),
                );
                eprintln!(
                    "{}: {error}",
                    baradwatchu_agent::messages::message(
                        "cli.error",
                        baradwatchu_messages::configured_language()
                    )
                );
                ExitCode::FAILURE
            }
        };
    }
    match cli::run(&args) {
        Ok(output) => match io::stdout().lock().write_all(output.text.as_bytes()) {
            Ok(()) => ExitCode::from(output.code),
            Err(_error) => {
                eprintln!(
                    "{}: {}",
                    baradwatchu_agent::messages::message(
                        "cli.error",
                        baradwatchu_messages::configured_language()
                    ),
                    baradwatchu_messages::message(
                        "cli.output_error",
                        baradwatchu_messages::configured_language()
                    )
                );
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!(
                "{}: {}",
                baradwatchu_agent::messages::message(
                    "cli.error",
                    baradwatchu_messages::configured_language()
                ),
                error.message
            );
            ExitCode::from(error.code)
        }
    }
}
