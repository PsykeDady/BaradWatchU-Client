//! Windows: notification-area icon, toast notifications (notify-rust/WinRT), message-box
//! consent window (rfd), autostart through the per-user `Run` registry key.
use super::{DialogDone, DialogOutcome};
use std::{
    path::{Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::Duration,
};

const RUN_KEY: &str = r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run";
const RUN_VALUE: &str = "BaradWatchU-Tray";

pub fn check_session() -> Result<(), String> {
    Ok(())
}

fn ask(title: &str, text: &str) -> DialogOutcome {
    let text = format!("{text}\n\n(Sì/Accetta = autorizza solo questa richiesta · No/Rifiuta · Annulla = decidi più tardi)");
    match rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Warning)
        .set_title(title)
        .set_description(text)
        .set_buttons(rfd::MessageButtons::YesNoCancelCustom(
            "Accetta".into(),
            "Rifiuta".into(),
            "Decidi più tardi".into(),
        ))
        .show()
    {
        rfd::MessageDialogResult::Custom(label) if label == "Accetta" => DialogOutcome::Accept,
        rfd::MessageDialogResult::Custom(label) if label == "Rifiuta" => DialogOutcome::Reject,
        rfd::MessageDialogResult::Yes => DialogOutcome::Accept,
        rfd::MessageDialogResult::No => DialogOutcome::Reject,
        _ => DialogOutcome::Later,
    }
}

/// The message box cannot close itself on expiry: a late Accept is refused by the agent.
pub fn consent_dialog(title: &str, text: &str, _timeout: Duration, done: DialogDone) {
    let (title, text) = (title.to_owned(), text.to_owned());
    thread::spawn(move || done(ask(&title, &text)));
}

pub fn info_dialog(title: &str, text: &str) -> bool {
    let (title, text) = (title.to_owned(), text.to_owned());
    thread::spawn(move || {
        rfd::MessageDialog::new()
            .set_level(rfd::MessageLevel::Info)
            .set_title(title)
            .set_description(text)
            .set_buttons(rfd::MessageButtons::Ok)
            .show()
    });
    true
}

fn reg() -> Command {
    let system = std::env::var_os("SystemRoot").unwrap_or_else(|| "C:\\Windows".into());
    let mut command = Command::new(PathBuf::from(system).join("System32").join("reg.exe"));
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    super::no_console(&mut command);
    command
}

pub fn autostart_enabled() -> bool {
    reg()
        .args(["query", RUN_KEY, "/v", RUN_VALUE])
        .status()
        .is_ok_and(|status| status.success())
}

pub fn set_autostart(enabled: bool, exe: &Path) -> Result<(), String> {
    let status = if enabled {
        let exe = exe.to_str().ok_or("percorso dell'eseguibile non valido")?;
        if exe.contains('"') {
            return Err("percorso dell'eseguibile non supportato".into());
        }
        reg()
            .args(["add", RUN_KEY, "/v", RUN_VALUE, "/t", "REG_SZ", "/d"])
            .arg(format!("\"{exe}\""))
            .arg("/f")
            .status()
    } else if !autostart_enabled() {
        return Ok(());
    } else {
        reg()
            .args(["delete", RUN_KEY, "/v", RUN_VALUE, "/f"])
            .status()
    };
    match status {
        Ok(status) if status.success() => Ok(()),
        _ => Err("impossibile aggiornare la chiave Run del registro".into()),
    }
}
