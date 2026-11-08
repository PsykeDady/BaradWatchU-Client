//! macOS: menu-bar status item, Notification Center (notify-rust), NSAlert consent window
//! (rfd), autostart through a per-user LaunchAgent limited to the Aqua session.
use super::{DialogDone, DialogOutcome};
use std::{fs, path::Path, path::PathBuf, time::Duration};

const LABEL: &str = "io.baradwatchu.tray";

pub fn check_session() -> Result<(), String> {
    Ok(())
}

/// NSAlert must run on the main thread: the call blocks the tray loop until answered.
/// It cannot close itself on expiry; a late Accept is refused by the agent.
pub fn consent_dialog(title: &str, text: &str, _timeout: Duration, done: DialogDone) {
    let outcome = match rfd::MessageDialog::new()
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
        _ => DialogOutcome::Later,
    };
    done(outcome);
}

pub fn info_dialog(title: &str, text: &str) -> bool {
    rfd::MessageDialog::new()
        .set_level(rfd::MessageLevel::Info)
        .set_title(title)
        .set_description(text)
        .set_buttons(rfd::MessageButtons::Ok)
        .show();
    true
}

fn agent_file() -> Result<PathBuf, String> {
    std::env::var_os("HOME")
        .map(|home| {
            PathBuf::from(home)
                .join("Library/LaunchAgents")
                .join(format!("{LABEL}.plist"))
        })
        .ok_or_else(|| "HOME non impostata".to_owned())
}

fn xml_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

pub fn autostart_enabled() -> bool {
    agent_file().is_ok_and(|path| path.is_file())
}

pub fn set_autostart(enabled: bool, exe: &Path) -> Result<(), String> {
    let path = agent_file()?;
    if !enabled {
        return match fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(_) => Err(format!("impossibile rimuovere {}", path.display())),
        };
    }
    let exe = exe.to_str().ok_or("percorso dell'eseguibile non valido")?;
    let plist = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n<plist version=\"1.0\"><dict>\n<key>Label</key><string>{LABEL}</string>\n<key>ProgramArguments</key><array><string>{}</string></array>\n<key>RunAtLoad</key><true/>\n<key>LimitLoadToSessionType</key><string>Aqua</string>\n<key>ProcessType</key><string>Interactive</string>\n</dict></plist>\n", xml_escape(exe));
    let dir = path.parent().ok_or("percorso LaunchAgents non valido")?;
    fs::create_dir_all(dir).map_err(|_| format!("impossibile creare {}", dir.display()))?;
    fs::write(&path, plist).map_err(|_| format!("impossibile scrivere {}", path.display()))
}
