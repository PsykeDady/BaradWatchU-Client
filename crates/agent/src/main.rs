use baradwatchu_agent::cli;
use std::{
    io::{self, Write},
    process::ExitCode,
};

fn main() -> ExitCode {
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    if args.len() == 1 && args[0] == "dashboard" {
        return match baradwatchu_agent::dashboard::run() {
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
