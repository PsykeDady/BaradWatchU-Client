//! Linux: StatusNotifierItem (KDE Plasma, AppIndicator-compatible desktops) over the user's
//! D-Bus session, freedesktop notifications, zenity/kdialog consent window, XDG autostart.
use super::{Builder, DialogDone, DialogOutcome};
use crate::app::Control;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::{mpsc, Arc},
    thread,
    time::{Duration, Instant},
};

const ZENITY: &str = "/usr/bin/zenity";
const KDIALOG: &str = "/usr/bin/kdialog";
const AUTOSTART_MARKER: &str = "X-BaradWatchU-Managed=true";

fn non_empty(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|value| !value.is_empty())
}

/// A tray needs the user's graphical session and session bus; refuse to run as a
/// session-less system service.
pub fn check_session() -> Result<(), String> {
    let display = non_empty("WAYLAND_DISPLAY") || non_empty("DISPLAY");
    let bus = non_empty("DBUS_SESSION_BUS_ADDRESS")
        || std::env::var_os("XDG_RUNTIME_DIR")
            .is_some_and(|dir| Path::new(&dir).join("bus").exists());
    if display && bus {
        Ok(())
    } else {
        Err("nessuna sessione grafica con D-Bus: avvia la tray dalla sessione desktop dell'utente, non come servizio di sistema".into())
    }
}

/// The StatusNotifierItem backend runs its own D-Bus worker thread, so the main thread
/// only needs to process tray messages.
pub fn run(build: Builder) -> Result<(), String> {
    let (sender, receiver) = mpsc::channel();
    let mut app = build(Arc::new(move |message| {
        let _ = sender.send(message);
    }))?;
    while let Ok(message) = receiver.recv() {
        if app.handle(message) == Control::Exit {
            break;
        }
    }
    Ok(())
}

fn wait_with_timeout(mut child: std::process::Child, timeout: Duration) -> Option<(i32, String)> {
    let started = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = String::new();
                if let Some(mut pipe) = child.stdout.take() {
                    let _ = pipe.read_to_string(&mut stdout);
                }
                return Some((status.code().unwrap_or(-1), stdout));
            }
            Ok(None) if started.elapsed() >= timeout => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => return Some((-1, String::new())),
        }
    }
}

fn consent_blocking(title: &str, text: &str, timeout: Duration) -> DialogOutcome {
    let language = baradwatchu_messages::configured_language();
    let accept = baradwatchu_messages::message("consent.button.accept", language);
    let reject = baradwatchu_messages::message("consent.button.reject", language);
    let later = baradwatchu_messages::message("consent.button.later", language);
    if Path::new(ZENITY).is_file() {
        // Accept is never the default button: Enter/Escape/closing mean "decide later".
        let child = Command::new(ZENITY)
            .args([
                "--question",
                "--no-markup",
                "--width=560",
                "--default-cancel",
            ])
            .args(["--icon=dialog-warning", "--title", title, "--text", text])
            .arg(format!("--ok-label={accept}"))
            .arg(format!("--cancel-label={later}"))
            .arg(format!("--extra-button={reject}"))
            .arg(format!("--timeout={}", timeout.as_secs().max(1)))
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn();
        let Ok(child) = child else {
            return DialogOutcome::Unavailable("zenity non avviabile".into());
        };
        return match wait_with_timeout(child, timeout + Duration::from_secs(5)) {
            Some((0, _)) => DialogOutcome::Accept,
            Some((1, stdout)) if stdout.trim() == reject => DialogOutcome::Reject,
            Some((5, _)) | None => DialogOutcome::TimedOut,
            Some(_) => DialogOutcome::Later,
        };
    }
    if Path::new(KDIALOG).is_file() {
        let child = Command::new(KDIALOG)
            .args(["--title", title])
            .args(["--yes-label", accept, "--no-label", reject])
            .args(["--cancel-label", later])
            .args(["--warningyesnocancel", text])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn();
        let Ok(child) = child else {
            return DialogOutcome::Unavailable("kdialog non avviabile".into());
        };
        // kdialog has no timeout option: the window is closed when the request expires.
        return match wait_with_timeout(child, timeout) {
            Some((0, _)) => DialogOutcome::Accept,
            Some((1, _)) => DialogOutcome::Reject,
            None => DialogOutcome::TimedOut,
            Some(_) => DialogOutcome::Later,
        };
    }
    DialogOutcome::Unavailable("per la finestra di consenso installa zenity oppure kdialog".into())
}

/// Dedicated consent window in its own process; the tray keeps running meanwhile.
pub fn consent_dialog(title: &str, text: &str, timeout: Duration, done: DialogDone) {
    let (title, text) = (title.to_owned(), text.to_owned());
    thread::spawn(move || {
        done(
            consent_blocking(&title, &text, timeout),
            super::DecisionVia::Window,
        )
    });
}

/// The consent prompt is a separate window; consent events also get a plain notification.
pub const CONSENT_IS_NOTIFICATION: bool = false;

/// Informational window; returns false when no dialog tool is available.
pub fn info_dialog(title: &str, text: &str) -> bool {
    let mut command = if Path::new(KDIALOG).is_file() {
        let mut command = Command::new(KDIALOG);
        command.args(["--title", title, "--msgbox", text]);
        command
    } else if Path::new(ZENITY).is_file() {
        let mut command = Command::new(ZENITY);
        command.args([
            "--info",
            "--no-markup",
            "--width=480",
            "--title",
            title,
            "--text",
            text,
        ]);
        command
    } else {
        return false;
    };
    match command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
    {
        Ok(mut child) => {
            thread::spawn(move || child.wait());
            true
        }
        Err(_) => false,
    }
}

fn autostart_file() -> Result<PathBuf, String> {
    std::env::var_os("XDG_CONFIG_HOME")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .map(|base| base.join("autostart").join("baradwatchu-tray.desktop"))
        .ok_or_else(|| "impossibile determinare la cartella di configurazione".to_owned())
}

pub fn autostart_enabled() -> bool {
    autostart_file()
        .ok()
        .and_then(|path| fs::read_to_string(path).ok())
        .is_some_and(|text| {
            text.lines().any(|line| line == AUTOSTART_MARKER)
                && !text.lines().any(|line| line == "Hidden=true")
        })
}

/// Desktop-entry `Exec` value; characters that need escaping are refused instead.
fn exec_value(exe: &Path) -> Result<String, String> {
    let text = exe.to_str().ok_or("percorso dell'eseguibile non UTF-8")?;
    if !exe.is_absolute()
        || text
            .chars()
            .any(|c| c.is_control() || matches!(c, '"' | '\\' | '`' | '$' | '%'))
    {
        return Err("percorso dell'eseguibile non supportato per l'avvio automatico".into());
    }
    Ok(format!("\"{text}\""))
}

pub fn desktop_entry(exe: &Path) -> Result<String, String> {
    let language = baradwatchu_messages::configured_language();
    let comment = baradwatchu_messages::message("tray.desktop.comment", language);
    Ok(format!(
        "[Desktop Entry]\nType=Application\nName=BaradWatchU Tray\nComment={comment}\nExec={}\nIcon=security-high\nTerminal=false\nCategories=System;Security;\nX-GNOME-Autostart-enabled=true\nX-KDE-autostart-after=panel\n{AUTOSTART_MARKER}\n",
        exec_value(exe)?
    ))
}

pub fn set_autostart(enabled: bool, exe: &Path) -> Result<(), String> {
    let path = autostart_file()?;
    if !enabled {
        return match fs::read_to_string(&path) {
            Ok(text) if text.lines().any(|line| line == AUTOSTART_MARKER) => fs::remove_file(&path)
                .map_err(|_| format!("impossibile rimuovere {}", path.display())),
            Ok(_) => Err(format!(
                "{} non è gestito da BaradWatchU: rimuovilo a mano",
                path.display()
            )),
            Err(_) => Ok(()),
        };
    }
    let entry = desktop_entry(exe)?;
    let dir = path
        .parent()
        .ok_or("percorso di avvio automatico non valido")?;
    fs::create_dir_all(dir).map_err(|_| format!("impossibile creare {}", dir.display()))?;
    let temp = dir.join(format!(".baradwatchu-tray.{}.tmp", std::process::id()));
    fs::write(&temp, entry)
        .and_then(|_| fs::rename(&temp, &path))
        .map_err(|_| {
            let _ = fs::remove_file(&temp);
            format!("impossibile scrivere {}", path.display())
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_quotes_exec_and_rejects_unsafe_paths() {
        let entry = desktop_entry(Path::new("/opt/Barad Watch/bin/baradwatchu-tray")).unwrap();
        assert!(entry.contains("Exec=\"/opt/Barad Watch/bin/baradwatchu-tray\"\n"));
        assert!(entry.contains(AUTOSTART_MARKER));
        assert!(desktop_entry(Path::new("relative/tray")).is_err());
        assert!(desktop_entry(Path::new("/tmp/$(evil)/tray")).is_err());
        assert!(desktop_entry(Path::new("/tmp/100%/tray")).is_err());
    }
}
