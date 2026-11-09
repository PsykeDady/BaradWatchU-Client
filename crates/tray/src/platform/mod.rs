//! Operating-system adapters behind one interface. Each platform module provides:
//! `check_session`, `run` (event loop), `consent_dialog`, `info_dialog`,
//! `autostart_enabled` and `set_autostart`. Everything else in the tray is shared.
use crate::{
    app::{App, Msg},
    model::Note,
};
use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::PathBuf,
    process::Command,
    sync::Arc,
    time::Duration,
};

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

#[cfg(any(target_os = "windows", target_os = "macos"))]
mod native_loop;
#[cfg(any(target_os = "windows", target_os = "macos"))]
pub use native_loop::run;

#[cfg(target_os = "windows")]
mod windows;
#[cfg(target_os = "windows")]
pub use windows::*;

#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "macos")]
pub use macos::*;

/// Posts a message to the tray's main-thread event loop from any thread.
pub type Poster = Arc<dyn Fn(Msg) + Send + Sync>;
pub type Builder = Box<dyn FnOnce(Poster) -> Result<App, String>>;
pub type DialogDone = Box<dyn FnOnce(DialogOutcome) + Send>;

/// Result of the dedicated consent window. Only `Accept` may lead to an authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
// Windows/macOS message boxes have no timeout and are always available.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub enum DialogOutcome {
    Accept,
    Reject,
    /// Closed or postponed: no decision, the request stays pending until it expires.
    Later,
    TimedOut,
    Unavailable(String),
}

/// Same rule as the agent: `$XDG_RUNTIME_DIR/baradwatchu`, else the state dir (`run/`).
/// State dir: `$XDG_STATE_HOME/baradwatchu`, on Windows `%LOCALAPPDATA%\baradwatchu\state`,
/// else `$HOME/.local/state/baradwatchu`.
pub fn runtime_dir() -> Option<PathBuf> {
    if let Some(base) = std::env::var_os("XDG_RUNTIME_DIR").filter(|v| !v.is_empty()) {
        return Some(PathBuf::from(base).join("baradwatchu"));
    }
    let state = std::env::var_os("XDG_STATE_HOME")
        .filter(|v| !v.is_empty())
        .map(|base| PathBuf::from(base).join("baradwatchu"))
        .or_else(|| {
            cfg!(windows)
                .then(|| std::env::var_os("LOCALAPPDATA").filter(|v| !v.is_empty()))
                .flatten()
                .map(|base| PathBuf::from(base).join("baradwatchu").join("state"))
        })
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|h| PathBuf::from(h).join(".local/state").join("baradwatchu"))
        })?;
    Some(state.join("run"))
}

fn private_dir(path: &std::path::Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(path)
        .map_err(|_| format!("impossibile creare {}", path.display()))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| "cartella runtime non valida")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("cartella runtime non sicura".into());
    }
    Ok(())
}

/// Held for the tray's lifetime; the OS releases it if the process dies.
pub struct InstanceLock(#[allow(dead_code)] File);

/// `Ok(None)` when another tray of this user already holds the lock.
pub fn acquire_instance_lock() -> Result<Option<InstanceLock>, String> {
    let dir = runtime_dir().ok_or("impossibile determinare la cartella runtime")?;
    private_dir(&dir)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let mut file = options
        .open(dir.join("tray.lock"))
        .map_err(|_| "impossibile aprire il lock della tray".to_owned())?;
    match file.try_lock() {
        Ok(()) => {}
        Err(fs::TryLockError::WouldBlock) => return Ok(None),
        Err(fs::TryLockError::Error(_)) => {
            return Err("impossibile bloccare il lock della tray".into())
        }
    }
    // The PID lets the agent/dashboard report whether the tray is running.
    let _ = file.set_len(0);
    let _ = writeln!(file, "{}", std::process::id());
    Ok(Some(InstanceLock(file)))
}

/// Native desktop notification, sent off the event-loop thread.
pub fn notify(note: Note) {
    std::thread::spawn(move || {
        let mut notification = notify_rust::Notification::new();
        notification
            .appname("BaradWatchU")
            .summary(&note.title)
            .body(&note.body);
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            notification
                .icon("security-high")
                .urgency(match note.urgency {
                    crate::model::Urgency::Low => notify_rust::Urgency::Low,
                    crate::model::Urgency::Normal => notify_rust::Urgency::Normal,
                    crate::model::Urgency::Critical => notify_rust::Urgency::Critical,
                });
        }
        #[cfg(not(all(unix, not(target_os = "macos"))))]
        let _ = note.urgency;
        if let Err(error) = notification.show() {
            let language = baradwatchu_messages::configured_language();
            eprintln!(
                "{}",
                baradwatchu_messages::message("tray.notification.failed", language)
                    .replace("{title}", &note.title)
                    .replace("{error}", &error.to_string())
            );
        }
    });
}

/// Starts a child that must outlive the tray (the dashboard server).
pub fn detach(command: &mut Command) {
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        command.process_group(0);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
        command.creation_flags(0x0000_0200 | 0x0800_0000);
    }
}

/// Windows: never flash a console window for agent calls.
pub fn no_console(command: &mut Command) {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x0800_0000);
    }
    let _ = command;
}

/// Seconds left for a consent window, never zero.
pub fn dialog_timeout(remaining_seconds: u64) -> Duration {
    Duration::from_secs(remaining_seconds.max(1))
}
