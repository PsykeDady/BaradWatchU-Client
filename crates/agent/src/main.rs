use baradwatchu_agent::cli;
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.first().is_some_and(|arg| arg == "dashboard") {
        let options = match baradwatchu_agent::dashboard::parse_options(&args[1..]) {
            Ok(options) => options,
            Err(usage) => {
                eprintln!("Error: {usage}");
                return ExitCode::from(2);
            }
        };
        return match baradwatchu_agent::dashboard::run(options) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("Error: {error}");
                ExitCode::FAILURE
            }
        };
    }
    match cli::run(&args) {
        Ok(output) => match io::stdout().lock().write_all(output.text.as_bytes()) {
            Ok(()) => ExitCode::from(output.code),
            Err(error) => {
                eprintln!("Cannot write output: {error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            eprintln!("Error: {}", error.message);
            ExitCode::from(error.code)
        }
    }
}
