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
    crate::requirements::run(args)
        .map(|output| Output {
            text: output.text,
            code: output.code,
        })
        .map_err(|error| Error {
            message: error.0,
            code: 2,
        })
}
