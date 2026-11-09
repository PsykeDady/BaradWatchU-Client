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

const USAGE: &str =
    "Usage: baradwatchu-tray [--version | --help | autostart enable|disable|status]";

fn help() -> String {
    format!(
        "BaradWatchU Tray {}\n\n{USAGE}\n\nWithout arguments the tray starts in the current desktop session (one instance per user).\nIt shows the agent state, runs audits through the agent, sends native notifications and\nopens a dedicated window for consent requests. Closing it does not stop the agent.\n`autostart` manages start at login for the current user only (no administrator rights).\n",
        env!("CARGO_PKG_VERSION")
    )
}

fn run() -> Result<(), String> {
    platform::check_session()?;
    let Some(lock) = platform::acquire_instance_lock()? else {
        println!("BaradWatchU Tray è già attiva in questa sessione.");
        return Ok(());
    };
    let agent = agent::Agent::locate()?;
    platform::run(Box::new(move |post| app::App::new(post, agent, lock)))
}

fn autostart(action: &str) -> Result<String, String> {
    let exe = std::env::current_exe().map_err(|_| "eseguibile della tray non trovato")?;
    match action {
        "enable" => platform::set_autostart(true, &exe)
            .map(|_| "Avvio automatico al login attivato.".into()),
        "disable" => platform::set_autostart(false, &exe)
            .map(|_| "Avvio automatico al login disattivato.".into()),
        "status" => Ok(if platform::autostart_enabled() {
            "Avvio automatico al login: attivo".into()
        } else {
            "Avvio automatico al login: non attivo".into()
        }),
        _ => Err(USAGE.into()),
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
            eprintln!("Error: {USAGE}");
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
        _ => {
            eprintln!("Error: {USAGE}");
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
            eprintln!("Errore: {error}");
            ExitCode::FAILURE
        }
    }
}
