//! Barad Policy `privilegedAudit`: a built-in requirement or provider that declares
//! `privilegeReason` in its `configuration.json` may run its (hash-verified, root-owned) tool
//! with administrator rights, after the user authenticates in a prompt that states the reason.
//!
//! - The policy only *permits* the request; normal checks never elevate.
//! - Linux/macOS: `sudo -k` (cached credentials are never reused), with a graphical password
//!   prompt (`SUDO_ASKPASS` = this agent in askpass mode) or the terminal. sudoers is never
//!   changed; nothing is stored.
//! - Never for custom checks, configuration overrides, scheduled (unattended) audits or tools
//!   that an unprivileged account could modify.
//! - Without elevation the tool still runs unprivileged (`BARADWATCHU_ELEVATION` tells it why)
//!   and a PASS is reported as WARN: privileged verification was not completed.
use crate::requirements::{ControlOrigin, Requirement, ResultRecord, ResultStatus};
use std::{cell::Cell, path::Path};

thread_local! {
    /// False for scheduled audits: nobody is there to authenticate.
    static INTERACTIVE: Cell<bool> = const { Cell::new(true) };
}

#[cfg(test)]
thread_local! {
    pub(crate) static TEST_SUDO: std::cell::RefCell<Option<std::path::PathBuf>> = const { std::cell::RefCell::new(None) };
    /// Accept tools owned by the test user (tests cannot create root-owned files).
    pub(crate) static TEST_TRUST_TOOLS: Cell<bool> = const { Cell::new(false) };
    /// Some(graphical) forces the prompt kind in tests.
    pub(crate) static TEST_PROMPT: Cell<Option<bool>> = const { Cell::new(None) };
    /// Overrides the policy decision in tests.
    pub(crate) static TEST_POLICY_ALLOWS: Cell<Option<bool>> = const { Cell::new(None) };
}

pub(crate) fn set_non_interactive() {
    INTERACTIVE.with(|value| value.set(false));
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    Granted,
    Denied,
    Unavailable(String),
    Disabled,
}

impl Outcome {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::Granted => "GRANTED",
            Self::Denied => "DENIED",
            Self::Unavailable(_) => "UNAVAILABLE",
            Self::Disabled => "DISABLED",
        }
    }
}

/// How the password is asked (never constructed on Windows, where elevation is unavailable).
#[cfg_attr(windows, allow(dead_code))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Prompt {
    pub graphical: bool,
    /// The agent already runs as root (an administrator ran it with sudo): no prompt.
    pub already_root: bool,
    pub text: String,
}

fn localized(key: &str) -> String {
    baradwatchu_messages::message(key, baradwatchu_messages::configured_language()).to_owned()
}

fn policy_allows() -> bool {
    #[cfg(test)]
    if let Some(value) = TEST_POLICY_ALLOWS.with(Cell::get) {
        return value;
    }
    crate::policy::load().privileged_audit()
}

#[cfg(unix)]
fn sudo_path() -> std::path::PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_SUDO.with(|slot| slot.borrow().clone()) {
        return path;
    }
    "/usr/bin/sudo".into()
}

/// sudo expands `%` sequences in the prompt.
#[cfg_attr(windows, allow(dead_code))]
fn sudo_prompt(text: &str) -> String {
    text.replace('%', "%%")
}

#[cfg_attr(windows, allow(dead_code))]
pub(crate) fn prompt_text(requirement: &Requirement, reason: &str) -> String {
    let language = baradwatchu_messages::configured_language();
    let text = baradwatchu_messages::message("privilege.prompt", language)
        .replace("{name}", &requirement.name)
        .replace("{id}", &requirement.id)
        .replace("{reason}", reason);
    text.chars().filter(|c| !c.is_control()).take(400).collect()
}

/// Whether and how this privileged control may ask for elevation now.
pub(crate) fn plan(requirement: &Requirement, reason: &str) -> Result<Prompt, Outcome> {
    if !policy_allows() {
        return Err(Outcome::Disabled);
    }
    if requirement.configuration_override || requirement.origin != ControlOrigin::Builtin {
        return Err(Outcome::Unavailable(localized("privilege.why.override")));
    }
    if !INTERACTIVE.with(Cell::get) {
        return Err(Outcome::Unavailable(localized("privilege.why.scheduled")));
    }
    platform_plan(requirement, reason)
}

#[cfg(windows)]
fn platform_plan(_requirement: &Requirement, _reason: &str) -> Result<Prompt, Outcome> {
    Err(Outcome::Unavailable(localized("privilege.why.windows")))
}

#[cfg(unix)]
fn platform_plan(requirement: &Requirement, reason: &str) -> Result<Prompt, Outcome> {
    let text = prompt_text(requirement, reason);
    // SAFETY: no preconditions.
    if unsafe { libc::geteuid() } == 0 {
        return Ok(Prompt {
            graphical: false,
            already_root: true,
            text,
        });
    }
    if !sudo_path().is_file() {
        return Err(Outcome::Unavailable(localized("privilege.why.no_sudo")));
    }
    #[cfg(test)]
    if let Some(graphical) = TEST_PROMPT.with(Cell::get) {
        return Ok(Prompt {
            graphical,
            already_root: false,
            text,
        });
    }
    if graphical_prompt_available() {
        return Ok(Prompt {
            graphical: true,
            already_root: false,
            text,
        });
    }
    if std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/tty")
        .is_ok()
    {
        return Ok(Prompt {
            graphical: false,
            already_root: false,
            text,
        });
    }
    Err(Outcome::Unavailable(localized("privilege.why.no_prompt")))
}

#[cfg(all(unix, not(target_os = "macos")))]
fn graphical_prompt_available() -> bool {
    let display = ["DISPLAY", "WAYLAND_DISPLAY"]
        .iter()
        .any(|name| std::env::var_os(name).is_some_and(|v| !v.is_empty()));
    display
        && ["/usr/bin/zenity", "/usr/bin/kdialog"]
            .iter()
            .any(|p| Path::new(p).is_file())
}

#[cfg(target_os = "macos")]
fn graphical_prompt_available() -> bool {
    // The user agent runs inside the login session (dashboard, tray, terminal of the user).
    Path::new("/usr/bin/osascript").is_file()
}

/// The tool, its folders and the installation must be writable only by root: otherwise the
/// account that asks could change what then runs as root.
#[cfg(unix)]
pub(crate) fn tool_is_root_protected(tool: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    #[cfg(test)]
    if TEST_TRUST_TOOLS.with(Cell::get) {
        return Ok(());
    }
    for path in tool.ancestors() {
        let meta = std::fs::symlink_metadata(path).map_err(|e| {
            localized("privilege.why.inspect")
                .replace("{path}", &path.display().to_string())
                .replace("{error}", &e.to_string())
        })?;
        if meta.file_type().is_symlink() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
            return Err(localized("privilege.why.unprotected")
                .replace("{path}", &path.display().to_string())
                .replace("{uid}", &meta.uid().to_string())
                .replace("{mode}", &format!("{:04o}", meta.mode() & 0o7777)));
        }
    }
    Ok(())
}

/// `sudo -k [-A] -p PROMPT -- TOOL`; the caller adds the tool arguments, folder and pipes.
#[cfg(unix)]
pub(crate) fn command(tool: &Path, prompt: &Prompt) -> std::process::Command {
    if prompt.already_root {
        return std::process::Command::new(tool);
    }
    let mut command = std::process::Command::new(sudo_path());
    command.arg("-k");
    if prompt.graphical {
        command.arg("-A");
    }
    command
        .arg("-p")
        .arg(sudo_prompt(&prompt.text))
        .arg("--")
        .arg(tool);
    command
}

/// Variables sudo needs to show the prompt (added after the tool's clean environment; sudo
/// resets the environment of the tool itself).
#[cfg(unix)]
pub(crate) fn prompt_environment(command: &mut std::process::Command, prompt: &Prompt) {
    if prompt.graphical {
        if let Ok(exe) = std::env::current_exe() {
            command.env("SUDO_ASKPASS", exe).env(ASKPASS_VARIABLE, "1");
        }
        for name in ["XAUTHORITY", "LC_ALL", "LC_MESSAGES"] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
}

/// States the elevation in the result; without it a PASS cannot stand.
pub(crate) fn annotate(mut result: ResultRecord, reason: &str, outcome: &Outcome) -> ResultRecord {
    let language = baradwatchu_messages::configured_language();
    let detail = match outcome {
        Outcome::Unavailable(why) => {
            baradwatchu_messages::message("privilege.detail.unavailable", language)
                .replace("{why}", why)
        }
        other => baradwatchu_messages::message(
            match other {
                Outcome::Granted => "privilege.detail.granted",
                Outcome::Denied => "privilege.detail.denied",
                _ => "privilege.detail.disabled",
            },
            language,
        )
        .to_owned(),
    };
    result.details.insert(
        0,
        baradwatchu_messages::message("privilege.detail.reason", language)
            .replace("{reason}", reason)
            .replace("{outcome}", &detail),
    );
    if *outcome != Outcome::Granted && result.status == ResultStatus::Pass {
        result.status = ResultStatus::Warn;
        result.summary = baradwatchu_messages::message("privilege.summary.incomplete", language)
            .replace("{summary}", &result.summary);
    }
    result
}

// ---------------------------------------------------------------------------------------
// Askpass mode: sudo starts this executable with the prompt as its only argument.
// ---------------------------------------------------------------------------------------

pub const ASKPASS_VARIABLE: &str = "BARADWATCHU_ASKPASS";

/// Shows a password dialog; Some(password) on OK, None on cancel or when no dialog works.
pub fn askpass(prompt: &str) -> Option<String> {
    use std::process::{Command, Stdio};
    let prompt: String = prompt
        .chars()
        .filter(|c| !c.is_control())
        .take(400)
        .collect();
    let attempts: Vec<Command> = if cfg!(target_os = "macos") {
        let mut osascript = Command::new("/usr/bin/osascript");
        osascript.args([
            "-e",
            "on run argv",
            "-e",
            "display dialog (item 1 of argv) default answer \"\" with hidden answer with title \"BaradWatchU\" with icon caution",
            "-e",
            "return text returned of result",
            "-e",
            "end run",
            "--",
            &prompt,
        ]);
        vec![osascript]
    } else {
        let mut zenity = Command::new("/usr/bin/zenity");
        zenity.args([
            "--entry",
            "--hide-text",
            "--title=BaradWatchU",
            &format!("--text={prompt}"),
        ]);
        let mut kdialog = Command::new("/usr/bin/kdialog");
        kdialog.args(["--title", "BaradWatchU", "--password", &prompt]);
        vec![zenity, kdialog]
    };
    for mut command in attempts {
        if !Path::new(command.get_program()).is_file() {
            continue;
        }
        let output = command
            .stdin(Stdio::null())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        // A cancelled dialog ends the attempt: never fall through to a second dialog.
        if !output.status.success() {
            return None;
        }
        let text = String::from_utf8(output.stdout).ok()?;
        return Some(text.trim_end_matches(['\n', '\r']).to_owned());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prompt_escapes_sudo_sequences_and_controls() {
        assert_eq!(sudo_prompt("100% sure %u"), "100%% sure %%u");
        let requirement = Requirement {
            name: "Antivirus\nX".into(),
            ..crate::requirements::test_requirement("REQ-002")
        };
        let text = prompt_text(&requirement, "Bitdefender data");
        assert!(text.contains("REQ-002") && text.contains("Bitdefender data"));
        assert!(!text.contains('\n'));
    }

    #[test]
    fn pass_without_elevation_becomes_warn_and_states_why() {
        let record = |status| ResultRecord {
            id: "REQ-002".into(),
            name: "AV".into(),
            description: String::new(),
            priority: crate::requirements::Priority::High,
            status,
            compliance_status: None,
            summary: "ok".into(),
            details: vec![],
            completed_at_unix_ms: 0,
            provenance: None,
        };
        for outcome in [
            Outcome::Denied,
            Outcome::Disabled,
            Outcome::Unavailable("no tty".into()),
        ] {
            let annotated = annotate(record(ResultStatus::Pass), "why", &outcome);
            assert_eq!(annotated.status, ResultStatus::Warn, "{outcome:?}");
            assert!(annotated.summary.contains("ok"));
            assert!(annotated.details[0].contains("why"));
            let failed = annotate(record(ResultStatus::Fail), "why", &outcome);
            assert_eq!(failed.status, ResultStatus::Fail);
        }
        let granted = annotate(record(ResultStatus::Pass), "why", &Outcome::Granted);
        assert_eq!(granted.status, ResultStatus::Pass);
    }

    #[test]
    fn policy_overrides_and_scheduled_audits_never_elevate() {
        let requirement = crate::requirements::test_requirement("REQ-002");
        TEST_POLICY_ALLOWS.with(|v| v.set(Some(false)));
        assert_eq!(plan(&requirement, "r"), Err(Outcome::Disabled));
        TEST_POLICY_ALLOWS.with(|v| v.set(Some(true)));
        let overridden = Requirement {
            configuration_override: true,
            ..requirement.clone()
        };
        assert!(matches!(
            plan(&overridden, "r"),
            Err(Outcome::Unavailable(_))
        ));
        let custom = Requirement {
            origin: ControlOrigin::Custom,
            ..requirement.clone()
        };
        assert!(matches!(plan(&custom, "r"), Err(Outcome::Unavailable(_))));
        set_non_interactive();
        assert!(matches!(
            plan(&requirement, "r"),
            Err(Outcome::Unavailable(_))
        ));
        INTERACTIVE.with(|v| v.set(true));
        TEST_POLICY_ALLOWS.with(|v| v.set(None));
    }

    #[cfg(unix)]
    #[test]
    fn user_owned_tools_are_not_root_protected() {
        let dir = std::env::temp_dir();
        assert!(tool_is_root_protected(&dir.join("does-not-exist")).is_err());
        let exe = std::env::current_exe().unwrap();
        // The test binary belongs to the developer, not to root.
        // SAFETY: no preconditions.
        if unsafe { libc::geteuid() } != 0 {
            assert!(tool_is_root_protected(&exe).is_err());
        }
        assert!(
            tool_is_root_protected(Path::new("/usr/bin/env")).is_ok()
                || !Path::new("/usr/bin/env").exists()
        );
    }
}
