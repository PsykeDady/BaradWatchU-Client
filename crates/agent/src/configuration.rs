//! Dashboard "Impostazioni" page: installation facts, tray state, the tray's start at login and
//! where local data lives. Start at login is owned by the tray companion: the agent only runs
//! the tray installed next to it with fixed arguments (`autostart enable|disable|status
//! --json`), without a shell and with a timeout, exactly as the tray runs the agent.
use crate::requirements::{self as req, CliError};
use serde::Serialize;
use std::{
    io::Read,
    path::PathBuf,
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const VIEW_SCHEMA: &str = "baradwatchu.configuration-view.v1";
const TRAY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TrayView {
    installed: bool,
    running: Option<bool>,
    /// `None` when the tray is missing or its state could not be read.
    autostart: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DataPaths {
    configuration: String,
    custom_checks: String,
    state: String,
    history: String,
    runtime: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigurationView {
    schema_version: &'static str,
    version: &'static str,
    platform: &'static str,
    language: baradwatchu_messages::Language,
    effective_language: &'static str,
    install_root: String,
    tray: TrayView,
    paths: DataPaths,
}

fn tray_path() -> Option<PathBuf> {
    let name = if cfg!(windows) {
        "baradwatchu-tray.exe"
    } else {
        "baradwatchu-tray"
    };
    std::env::current_exe()
        .ok()?
        .parent()
        .map(|dir| dir.join(name))
}

/// Runs the installed tray with fixed arguments and returns its stdout.
fn run_tray(args: &[&str]) -> Result<String, String> {
    let tray = tray_path()
        .filter(|path| path.is_file())
        .ok_or_else(|| "BaradWatchU Tray non è installata accanto all'agente".to_owned())?;
    let mut command = Command::new(&tray);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("avvio della tray non riuscito: {error}"))?;
    let mut stdout = child
        .stdout
        .take()
        .ok_or("output della tray non leggibile")?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or("output della tray non leggibile")?;
    let out_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stdout).take(16 * 1024).read_to_string(&mut text);
        text
    });
    let err_reader = thread::spawn(move || {
        let mut text = String::new();
        let _ = (&mut stderr).take(4 * 1024).read_to_string(&mut text);
        text
    });
    let deadline = Instant::now() + TRAY_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => thread::sleep(Duration::from_millis(20)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("la tray non ha risposto entro 10 secondi".into());
            }
        }
    };
    let out = out_reader.join().unwrap_or_default();
    let err = err_reader.join().unwrap_or_default();
    if status.success() {
        Ok(out)
    } else {
        Err(format!(
            "la tray ha restituito un errore: {}",
            err.trim().trim_start_matches("Errore: ")
        ))
    }
}

fn autostart_state() -> Result<bool, String> {
    let text = run_tray(&["autostart", "status", "--json"])?;
    serde_json::from_str::<serde_json::Value>(text.trim())
        .ok()
        .and_then(|value| value.get("enabled").and_then(serde_json::Value::as_bool))
        .ok_or_else(|| "risposta della tray non interpretabile".into())
}

fn shown(path: Result<PathBuf, CliError>) -> String {
    match path {
        Ok(path) => path.display().to_string(),
        Err(error) => {
            let language = baradwatchu_messages::configured_language();
            let reason = baradwatchu_messages::localize_diagnostic(&error.0, language);
            format!(
                "{} ({reason})",
                baradwatchu_messages::message("cli.value.undetermined", language)
            )
        }
    }
}

fn view(error: Option<String>) -> Result<String, CliError> {
    let language = baradwatchu_messages::configured_language();
    let installed = tray_path().is_some_and(|path| path.is_file());
    let (autostart, read_error) = if installed {
        match autostart_state() {
            Ok(enabled) => (Some(enabled), None),
            Err(error) => (None, Some(error)),
        }
    } else {
        (None, None)
    };
    req::output_json(&ConfigurationView {
        schema_version: VIEW_SCHEMA,
        version: env!("CARGO_PKG_VERSION"),
        platform: req::platform_key(),
        language: baradwatchu_messages::configured_language(),
        effective_language: baradwatchu_messages::configured_language()
            .effective()
            .code(),
        install_root: shown(req::install_root()),
        tray: TrayView {
            installed,
            running: crate::events::tray_running(),
            autostart,
            error: error
                .or(read_error)
                .map(|text| baradwatchu_messages::localize_diagnostic(&text, language)),
        },
        paths: DataPaths {
            configuration: shown(req::state_dir()),
            custom_checks: shown(req::custom_root()),
            state: shown(req::state_home()),
            history: shown(req::history_dir()),
            runtime: shown(req::runtime_dir()),
        },
    })
}

pub(crate) fn dashboard_configuration_json() -> Result<String, CliError> {
    view(None)
}

pub(crate) fn dashboard_messages_json() -> Result<String, CliError> {
    let language = baradwatchu_messages::configured_language();
    req::output_json(&serde_json::json!({
        "language": language,
        "effectiveLanguage": language.effective().code(),
        "messages": baradwatchu_messages::dashboard_catalog(language),
    }))
}

/// `{"enabled": true|false}`: asks the tray to enable or disable its start at login.
pub(crate) fn dashboard_set_autostart(text: &str) -> Result<String, CliError> {
    let enabled = serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|value| {
            let object = value.as_object()?;
            (object.len() == 1)
                .then(|| object.get("enabled")?.as_bool())
                .flatten()
        })
        .ok_or_else(|| CliError("Richiesta non valida: atteso {\"enabled\": true|false}".into()))?;
    let action = if enabled { "enable" } else { "disable" };
    run_tray(&["autostart", action])
        .map_err(|error| CliError(format!("Avvio automatico non modificato: {error}")))?;
    view(None)
}

pub(crate) fn dashboard_set_language(text: &str) -> Result<String, CliError> {
    let value = serde_json::from_str::<serde_json::Value>(text)
        .map_err(|_| CliError("Invalid language request".into()))?;
    let object = value
        .as_object()
        .ok_or_else(|| CliError("Invalid language request".into()))?;
    if object.len() != 1 || !object.contains_key("language") {
        return Err(CliError(
            "Expected {\"language\":\"system|italian|english\"}".into(),
        ));
    }
    let language = match object["language"].as_str() {
        Some("system") => baradwatchu_messages::Language::System,
        Some("italian") => baradwatchu_messages::Language::Italian,
        Some("english") => baradwatchu_messages::Language::English,
        _ => {
            return Err(CliError(
                "Language must be system, italian, or english".into(),
            ))
        }
    };
    let directory = req::state_dir()?;
    req::ensure_private_dir(&directory)?;
    req::atomic_json(
        &directory.join("language.json"),
        &baradwatchu_messages::LanguagePreference {
            schema_version: "baradwatchu.language.v1".into(),
            language,
        },
    )?;
    view(None)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn autostart_request_must_be_a_single_boolean() {
        for body in [
            "",
            "{}",
            "{\"enabled\":\"yes\"}",
            "{\"enabled\":true,\"x\":1}",
            "[true]",
        ] {
            assert!(dashboard_set_autostart(body).is_err(), "{body}");
        }
    }
}
