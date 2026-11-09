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

#[link(name = "kernel32")]
extern "system" {
    fn AttachConsole(process_id: u32) -> i32;
    fn GetStdHandle(std_handle: u32) -> *mut std::ffi::c_void;
    fn SetStdHandle(std_handle: u32, handle: *mut std::ffi::c_void) -> i32;
}

const ATTACH_PARENT_PROCESS: u32 = u32::MAX;
const STD_OUTPUT_HANDLE: u32 = -11i32 as u32;
const STD_ERROR_HANDLE: u32 = -12i32 as u32;

/// The tray is a GUI-subsystem program on Windows (no console window from the Start menu or
/// at login). For command-line use (`--version`, `--help`, `autostart`) its output goes to
/// redirected handles when there are any (pipes, files: installers capture it), otherwise to
/// the console of the terminal that started it. Never called when the tray itself runs, so
/// closing that terminal cannot end the tray.
pub fn attach_parent_console() {
    let missing = |handle: *mut std::ffi::c_void| handle.is_null() || handle as isize == -1;
    // SAFETY: plain kernel32 calls; handles opened here are handed over to the process
    // standard handles and intentionally never closed.
    unsafe {
        let out = GetStdHandle(STD_OUTPUT_HANDLE);
        let err = GetStdHandle(STD_ERROR_HANDLE);
        if !missing(out) && !missing(err) {
            return;
        }
        if AttachConsole(ATTACH_PARENT_PROCESS) == 0 {
            return;
        }
        for (id, current) in [(STD_OUTPUT_HANDLE, out), (STD_ERROR_HANDLE, err)] {
            if missing(current) {
                use std::os::windows::io::IntoRawHandle;
                if let Ok(console) = std::fs::OpenOptions::new().write(true).open("CONOUT$") {
                    SetStdHandle(id, console.into_raw_handle());
                }
            }
        }
    }
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
