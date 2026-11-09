//! BaradWatchU Tray Companion: system tray icon, native notifications and the local consent
//! window. It only talks to the locally installed agent; it never audits by itself and
//! closing it does not stop the agent or the dashboard.
// Windows: GUI subsystem, so starting the tray (Start menu, login) opens no console window.
// Command-line output is handled by `platform::attach_parent_console`.
#![cfg_attr(windows, windows_subsystem = "windows")]
mod agent;
mod app;
mod icon;
mod model;
mod platform;

use std::process::ExitCode;

fn usage() -> &'static str {
    baradwatchu_messages::message("tray.usage", baradwatchu_messages::configured_language())
}

fn help() -> String {
    format!(
        "BaradWatchU Tray {}\n\n{}\n\n{}\n",
        env!("CARGO_PKG_VERSION"),
        usage(),
        baradwatchu_messages::message("tray.help", baradwatchu_messages::configured_language())
    )
}

fn run() -> Result<(), String> {
    platform::check_session()?;
    let Some(lock) = platform::acquire_instance_lock()? else {
        println!(
            "{}",
            baradwatchu_messages::message(
                "tray.already_running",
                baradwatchu_messages::configured_language()
            )
        );
        return Ok(());
    };
    let agent = agent::Agent::locate()?;
    platform::run(Box::new(move |post| app::App::new(post, agent, lock)))
}

fn autostart(action: &str) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|_| {
        baradwatchu_messages::message(
            "tray.executable_missing",
            baradwatchu_messages::configured_language(),
        )
    })?;
    match action {
        "enable" => platform::set_autostart(true, &exe).map(|_| {
            baradwatchu_messages::message(
                "tray.autostart_enabled",
                baradwatchu_messages::configured_language(),
            )
            .into()
        }),
        "disable" => platform::set_autostart(false, &exe).map(|_| {
            baradwatchu_messages::message(
                "tray.autostart_disabled",
                baradwatchu_messages::configured_language(),
            )
            .into()
        }),
        "status" => Ok(if platform::autostart_enabled() {
            baradwatchu_messages::message(
                "tray.autostart_on",
                baradwatchu_messages::configured_language(),
            )
            .into()
        } else {
            baradwatchu_messages::message(
                "tray.autostart_off",
                baradwatchu_messages::configured_language(),
            )
            .into()
        }),
        _ => Err(usage().into()),
    }
}

fn main() -> ExitCode {
    // Command-line mode only: the running tray stays detached from any terminal.
    #[cfg(windows)]
    if std::env::args_os().len() > 1 {
        platform::attach_parent_console();
    }
    let args: Vec<String> = match std::env::args_os()
        .skip(1)
        .map(|arg| arg.into_string())
        .collect::<Result<_, _>>()
    {
        Ok(args) => args,
        Err(_) => {
            eprintln!(
                "{}: {}",
                baradwatchu_messages::message(
                    "cli.error",
                    baradwatchu_messages::configured_language()
                ),
                usage()
            );
            return ExitCode::from(2);
        }
    };
    let result = match args
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => run().map(|_| None),
        ["--version" | "-V"] => Ok(Some(format!(
            "BaradWatchU Tray {}",
            env!("CARGO_PKG_VERSION")
        ))),
        ["--help" | "-h"] => Ok(Some(help())),
        ["autostart", action @ ("enable" | "disable" | "status")] => autostart(action).map(Some),
        // Machine-readable state for the agent's dashboard settings page.
        ["autostart", "status", "--json"] => Ok(Some(format!(
            "{{\"enabled\":{}}}",
            platform::autostart_enabled()
        ))),
        _ => {
            eprintln!(
                "{}: {}",
                baradwatchu_messages::message(
                    "cli.error",
                    baradwatchu_messages::configured_language()
                ),
                usage()
            );
            return ExitCode::from(2);
        }
    };
    match result {
        Ok(Some(text)) => {
            println!("{}", text.trim_end());
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(error) => {
            let error = baradwatchu_messages::localize_diagnostic(
                &error,
                baradwatchu_messages::configured_language(),
            );
            eprintln!(
                "{}: {error}",
                baradwatchu_messages::message(
                    "cli.error",
                    baradwatchu_messages::configured_language()
                )
            );
            ExitCode::FAILURE
        }
    }
}
