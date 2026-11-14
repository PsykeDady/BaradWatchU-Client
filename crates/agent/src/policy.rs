//! Barad Policy: the machine-wide `barad-policy.json` that a company administrator installs
//! locally (never received from a Server). Only a file owned by the system administrator and
//! writable by nobody else is applied; anything else keeps the behavior of a Client without
//! policy and is reported as such, with the SHA-256 of the exact bytes that were read.
//!
//! Locations: Linux/Unix `/etc/baradwatchu/barad-policy.json`; macOS
//! `/Library/Application Support/BaradWatchU/barad-policy.json`; Windows
//! `%ProgramData%\BaradWatchU\barad-policy.json`.
use crate::requirements::{CliError, CliOutput};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    ffi::OsString,
    fs,
    io::Read,
    path::{Path, PathBuf},
};

pub(crate) const FILE_NAME: &str = "barad-policy.json";
const MAX_POLICY_BYTES: u64 = 64 * 1024;

/// The whole schema of this milestone: every field is mandatory, nothing else is accepted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct BaradPolicy {
    pub on_change_detecting: OnChangeDetecting,
    pub privileged_audit: bool,
    pub start_on_boot: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct OnChangeDetecting {
    pub enabled: bool,
    pub cron_job: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyState {
    /// Trusted, valid and in force.
    Applied,
    /// No policy file: the Client behaves exactly as without the Barad Policy.
    Absent,
    /// Trusted file whose content is not a valid policy: nothing is enabled.
    Invalid,
    /// Wrong owner, permissions or file type: nothing is enabled.
    Untrusted,
}

/// What every audit report carries about the policy (`report.policy`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyReport {
    pub state: PolicyState,
    pub path: String,
    /// SHA-256 of the exact bytes read; absent when nothing could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Clone, Debug)]
pub(crate) struct LoadedPolicy {
    pub report: PolicyReport,
    /// Some only when `report.state` is APPLIED.
    pub policy: Option<BaradPolicy>,
}

impl LoadedPolicy {
    pub(crate) fn privileged_audit(&self) -> bool {
        self.policy.as_ref().is_some_and(|p| p.privileged_audit)
    }
}

#[cfg(test)]
thread_local! {
    static TEST_PATH: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
    /// Unix owner accepted instead of root in tests (non-root test runs).
    static TEST_OWNER: std::cell::Cell<Option<u32>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
pub(crate) fn set_test_policy(path: Option<PathBuf>, owner: Option<u32>) {
    TEST_PATH.with(|slot| *slot.borrow_mut() = path);
    TEST_OWNER.with(|slot| slot.set(owner));
}

pub(crate) fn policy_dir() -> PathBuf {
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(base).join("BaradWatchU")
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/BaradWatchU".into()
    } else {
        "/etc/baradwatchu".into()
    }
}

pub(crate) fn policy_path() -> PathBuf {
    #[cfg(test)]
    if let Some(path) = TEST_PATH.with(|slot| slot.borrow().clone()) {
        return path;
    }
    policy_dir().join(FILE_NAME)
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Reads, checks and parses the installed policy. Never fails: problems become states.
pub(crate) fn load() -> LoadedPolicy {
    load_at(&policy_path())
}

pub(crate) fn load_at(path: &Path) -> LoadedPolicy {
    let shown = path.display().to_string();
    let outcome = |state, sha256, error: Option<String>| LoadedPolicy {
        report: PolicyReport {
            state,
            path: shown.clone(),
            sha256,
            error,
        },
        policy: None,
    };
    let bytes = match read_trusted(path) {
        Ok(None) => return outcome(PolicyState::Absent, None, None),
        Ok(Some(bytes)) => bytes,
        Err(Untrusted { reason, bytes }) => {
            return outcome(
                PolicyState::Untrusted,
                bytes.as_deref().map(sha256_hex),
                Some(reason),
            )
        }
    };
    let sha256 = sha256_hex(&bytes);
    match parse(&bytes) {
        Ok(policy) => LoadedPolicy {
            report: PolicyReport {
                state: PolicyState::Applied,
                path: shown,
                sha256: Some(sha256),
                error: None,
            },
            policy: Some(policy),
        },
        Err(reason) => outcome(PolicyState::Invalid, Some(sha256), Some(reason)),
    }
}

/// Diagnostic in the configured language (`policy.error.*`), placeholders `{name}`.
fn diagnostic(key: &str, values: &[(&str, String)]) -> String {
    values.iter().fold(msg(key), |text, (name, value)| {
        text.replace(&format!("{{{name}}}"), value)
    })
}

pub(crate) fn parse(bytes: &[u8]) -> Result<BaradPolicy, String> {
    let policy: BaradPolicy = serde_json::from_slice(bytes)
        .map_err(|e| diagnostic("policy.error.json", &[("error", e.to_string())]))?;
    crate::cron::Cron::parse(&policy.on_change_detecting.cron_job)
        .map_err(|e| diagnostic("policy.error.cron", &[("error", e)]))?;
    Ok(policy)
}

struct Untrusted {
    reason: String,
    /// The bytes, when they could be read anyway (for the reported hash).
    bytes: Option<Vec<u8>>,
}

fn untrusted(reason: impl Into<String>) -> Untrusted {
    Untrusted {
        reason: reason.into(),
        bytes: None,
    }
}

fn read_limited(mut file: fs::File) -> Result<Vec<u8>, Untrusted> {
    let mut bytes = Vec::new();
    file.by_ref()
        .take(MAX_POLICY_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| untrusted(diagnostic("policy.error.read", &[("error", e.to_string())])))?;
    if bytes.len() as u64 > MAX_POLICY_BYTES {
        return Err(untrusted(msg("policy.error.too_large")));
    }
    Ok(bytes)
}

/// Ok(None): no policy file. The file must be a regular file (no link) owned by root (Unix)
/// or by SYSTEM/Administrators (Windows) and writable only by its owner, in folders with the
/// same protection; the checks are made on the opened handle where the platform allows it.
#[cfg(unix)]
fn read_trusted(path: &Path) -> Result<Option<Vec<u8>>, Untrusted> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    #[cfg(test)]
    let owner = TEST_OWNER.with(|slot| slot.get()).unwrap_or(0);
    #[cfg(not(test))]
    let owner = 0u32;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
            return Err(untrusted(msg("policy.error.link")))
        }
        Err(error) => {
            return Err(untrusted(diagnostic(
                "policy.error.open",
                &[("error", error.to_string())],
            )))
        }
    };
    let metadata = file.metadata().map_err(|e| {
        untrusted(diagnostic(
            "policy.error.inspect",
            &[("error", e.to_string())],
        ))
    })?;
    let problem = if !metadata.is_file() {
        Some(msg("policy.error.not_file"))
    } else if metadata.uid() != owner {
        Some(diagnostic(
            "policy.error.owner_uid",
            &[("uid", metadata.uid().to_string())],
        ))
    } else if metadata.mode() & 0o022 != 0 {
        Some(diagnostic(
            "policy.error.writable",
            &[("mode", format!("{:04o}", metadata.mode() & 0o7777))],
        ))
    } else {
        None
    };
    // Every parent folder must be root-owned and not writable by others (or sticky /tmp-like
    // folders could let anyone replace the file).
    let problem = problem.or_else(|| {
        path.parent()
            .and_then(|dir| dir.canonicalize().ok())
            .and_then(|dir| {
                // Tests run in a private temporary folder: only that folder is checked.
                #[cfg(test)]
                let depth = if TEST_OWNER.with(|slot| slot.get()).is_some() {
                    1
                } else {
                    usize::MAX
                };
                #[cfg(not(test))]
                let depth = usize::MAX;
                dir.ancestors().take(depth).find_map(|ancestor| {
                    let meta = fs::metadata(ancestor).ok()?;
                    (meta.uid() != owner && meta.uid() != 0 || meta.mode() & 0o022 != 0).then(
                        || {
                            diagnostic(
                                "policy.error.folder",
                                &[
                                    ("path", ancestor.display().to_string()),
                                    ("uid", meta.uid().to_string()),
                                    ("mode", format!("{:04o}", meta.mode() & 0o7777)),
                                ],
                            )
                        },
                    )
                })
            })
    });
    let bytes = if metadata.is_file() {
        read_limited(file)
    } else {
        Err(untrusted(""))
    };
    match (problem, bytes) {
        (None, Ok(bytes)) => Ok(Some(bytes)),
        (None, Err(error)) => Err(error),
        (Some(reason), bytes) => Err(Untrusted {
            reason,
            bytes: bytes.ok(),
        }),
    }
}

#[cfg(windows)]
fn read_trusted(path: &Path) -> Result<Option<Vec<u8>>, Untrusted> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT;
    let file = match fs::OpenOptions::new()
        .read(true)
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(untrusted(diagnostic(
                "policy.error.open",
                &[("error", error.to_string())],
            )))
        }
    };
    let metadata = file.metadata().map_err(|e| {
        untrusted(diagnostic(
            "policy.error.inspect",
            &[("error", e.to_string())],
        ))
    })?;
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(untrusted(msg("policy.error.not_file")));
    }
    // SYSTEM or the Administrators group: a file created by a standard user is owned by
    // that user (ProgramData lets users add files, not change the administrators' ones).
    let owner = crate::identity::windows_acl::owner_sid(&file);
    let problem = match owner.as_deref() {
        Some("S-1-5-18") | Some("S-1-5-32-544") => None,
        Some(other) => Some(diagnostic(
            "policy.error.owner_sid",
            &[("owner", other.to_owned())],
        )),
        None => Some(msg("policy.error.owner_unknown")),
    };
    let bytes = read_limited(file);
    match (problem, bytes) {
        (None, Ok(bytes)) => Ok(Some(bytes)),
        (None, Err(error)) => Err(error),
        (Some(reason), bytes) => Err(Untrusted {
            reason,
            bytes: bytes.ok(),
        }),
    }
}

// ---------------------------------------------------------------------------------------
// CLI: `policy status [--json]` (read-only; the policy is edited by the administrator)
// ---------------------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct StatusView {
    #[serde(flatten)]
    report: PolicyReport,
    #[serde(skip_serializing_if = "Option::is_none")]
    on_change_detecting: Option<OnChangeDetecting>,
    #[serde(skip_serializing_if = "Option::is_none")]
    privileged_audit: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    start_on_boot: Option<bool>,
}

pub(crate) fn status_view() -> serde_json::Value {
    let loaded = load();
    serde_json::to_value(StatusView {
        on_change_detecting: loaded
            .policy
            .as_ref()
            .map(|p| p.on_change_detecting.clone()),
        privileged_audit: loaded.policy.as_ref().map(|p| p.privileged_audit),
        start_on_boot: loaded.policy.as_ref().map(|p| p.start_on_boot),
        report: loaded.report,
    })
    .unwrap_or(serde_json::Value::Null)
}

fn msg(key: &str) -> String {
    baradwatchu_messages::message(key, baradwatchu_messages::configured_language()).to_owned()
}

pub fn run(args: &[OsString]) -> Result<CliOutput, CliError> {
    let json = match args {
        [command] if command == "status" => false,
        [command, flag] if command == "status" && flag == "--json" => true,
        _ => return Err(CliError(msg("policy.usage"))),
    };
    let view = status_view();
    if json {
        return Ok(CliOutput {
            text: crate::requirements::output_json(&view)?,
            code: 0,
        });
    }
    let loaded = load();
    let state = match loaded.report.state {
        PolicyState::Applied => msg("policy.state.applied"),
        PolicyState::Absent => msg("policy.state.absent"),
        PolicyState::Invalid => msg("policy.state.invalid"),
        PolicyState::Untrusted => msg("policy.state.untrusted"),
    };
    let mut text = format!(
        "{}: {}\n{}: {}\n{}: {}\n",
        msg("policy.label.state"),
        state,
        msg("policy.label.path"),
        loaded.report.path,
        msg("policy.label.sha256"),
        loaded.report.sha256.as_deref().unwrap_or("-")
    );
    if let Some(error) = &loaded.report.error {
        text.push_str(&format!("{}: {error}\n", msg("policy.label.error")));
    }
    if let Some(policy) = &loaded.policy {
        text.push_str(&format!(
            "onChangeDetecting: {} ({})\nprivilegedAudit: {}\nstartOnBoot: {}\n",
            policy.on_change_detecting.enabled,
            policy.on_change_detecting.cron_job,
            policy.privileged_audit,
            policy.start_on_boot
        ));
    }
    Ok(CliOutput { text, code: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"{
  "onChangeDetecting": {
    "enabled": true,
    "cronJob": "0 * * * *"
  },
  "privilegedAudit": true,
  "startOnBoot": true
}
"#;

    struct Dir(PathBuf);
    impl Drop for Dir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn private_dir(label: &str) -> Dir {
        let dir = std::env::temp_dir().join(format!(
            "bwu-policy-{label}-{}-{}",
            std::process::id(),
            crate::requirements::now_ms()
        ));
        fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Dir(dir)
    }

    #[cfg(unix)]
    fn me() -> u32 {
        // SAFETY: no preconditions.
        unsafe { libc::geteuid() }
    }

    #[cfg(unix)]
    fn write(path: &Path, text: &str, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::write(path, text).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn the_sample_schema_parses_and_unknown_or_missing_fields_are_refused() {
        let policy = parse(SAMPLE.as_bytes()).unwrap();
        assert!(policy.on_change_detecting.enabled);
        assert_eq!(policy.on_change_detecting.cron_job, "0 * * * *");
        assert!(policy.privileged_audit && policy.start_on_boot);
        assert!(parse(br#"{"onChangeDetecting":{"enabled":true,"cronJob":"0 * * * *"},"privilegedAudit":true,"startOnBoot":true,"remote":true}"#).is_err());
        assert!(parse(br#"{"onChangeDetecting":{"enabled":true,"cronJob":"0 * * * *"},"privilegedAudit":true}"#).is_err());
        assert!(parse(br#"{"onChangeDetecting":{"enabled":"yes","cronJob":"0 * * * *"},"privilegedAudit":true,"startOnBoot":true}"#).is_err());
        let bad_cron = SAMPLE.replace("0 * * * *", "61 * * * *");
        assert!(parse(bad_cron.as_bytes()).unwrap_err().contains("cronJob"));
    }

    #[test]
    fn missing_policy_is_absent_without_hash() {
        let dir = private_dir("absent");
        let loaded = load_at(&dir.0.join(FILE_NAME));
        assert_eq!(loaded.report.state, PolicyState::Absent);
        assert!(loaded.report.sha256.is_none() && loaded.policy.is_none());
        assert!(!loaded.privileged_audit());
    }

    #[cfg(unix)]
    #[test]
    fn trusted_policy_is_applied_and_hashed_from_the_exact_bytes() {
        let dir = private_dir("applied");
        let path = dir.0.join(FILE_NAME);
        write(&path, SAMPLE, 0o644);
        set_test_policy(None, Some(me()));
        let loaded = load_at(&path);
        set_test_policy(None, None);
        assert_eq!(loaded.report.state, PolicyState::Applied, "{loaded:?}");
        assert_eq!(
            loaded.report.sha256.as_deref(),
            Some(sha256_hex(SAMPLE.as_bytes()).as_str())
        );
        assert!(loaded.privileged_audit());
        // One more byte (a trailing newline) is a different policy.
        write(&path, &format!("{SAMPLE}\n"), 0o644);
        set_test_policy(None, Some(me()));
        let changed = load_at(&path);
        set_test_policy(None, None);
        assert_ne!(changed.report.sha256, loaded.report.sha256);
    }

    #[cfg(unix)]
    #[test]
    fn writable_foreign_or_linked_policies_are_untrusted_and_enable_nothing() {
        let dir = private_dir("untrusted");
        let path = dir.0.join(FILE_NAME);
        write(&path, SAMPLE, 0o664);
        set_test_policy(None, Some(me()));
        let writable = load_at(&path);
        assert_eq!(writable.report.state, PolicyState::Untrusted);
        assert!(writable.policy.is_none() && !writable.privileged_audit());
        // The bytes were read: the hash is reported, the state says it is not applied.
        assert_eq!(
            writable.report.sha256.as_deref(),
            Some(sha256_hex(SAMPLE.as_bytes()).as_str())
        );
        write(&path, SAMPLE, 0o644);
        set_test_policy(None, Some(me().wrapping_add(1)));
        let foreign = load_at(&path);
        assert_eq!(foreign.report.state, PolicyState::Untrusted);
        assert!(foreign.report.error.as_deref().unwrap().contains("uid"));
        let link = dir.0.join("link.json");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        set_test_policy(None, Some(me()));
        let linked = load_at(&link);
        assert_eq!(linked.report.state, PolicyState::Untrusted);
        assert!(linked.report.sha256.is_none());
        // A folder writable by others lets anyone swap the file.
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir.0, fs::Permissions::from_mode(0o777)).unwrap();
        }
        let open_folder = load_at(&path);
        set_test_policy(None, None);
        assert_eq!(open_folder.report.state, PolicyState::Untrusted);
        let reason = open_folder.report.error.as_deref().unwrap();
        assert!(reason.contains("0777"), "{reason}");
    }

    /// install-service.sh/.ps1 read `policy status --json`: keep the lines they match.
    #[cfg(unix)]
    #[test]
    fn status_json_exposes_state_and_start_on_boot_for_the_installers() {
        let dir = private_dir("status");
        let path = dir.0.join(FILE_NAME);
        write(
            &path,
            &SAMPLE.replace("\"startOnBoot\": true", "\"startOnBoot\": false"),
            0o644,
        );
        set_test_policy(Some(path.clone()), Some(me()));
        let text = crate::requirements::output_json(&status_view()).unwrap();
        set_test_policy(None, None);
        assert!(text.contains("\n  \"state\": \"APPLIED\""), "{text}");
        assert!(text.contains("\"startOnBoot\": false"), "{text}");
        assert!(text.contains("\"cronJob\": \"0 * * * *\""));
    }

    #[cfg(unix)]
    #[test]
    fn trusted_but_invalid_policy_is_invalid_and_enables_nothing() {
        let dir = private_dir("invalid");
        let path = dir.0.join(FILE_NAME);
        write(&path, "{\"privilegedAudit\":true}", 0o644);
        set_test_policy(None, Some(me()));
        let loaded = load_at(&path);
        set_test_policy(None, None);
        assert_eq!(loaded.report.state, PolicyState::Invalid);
        assert!(loaded.policy.is_none() && !loaded.privileged_audit());
        assert!(loaded.report.sha256.is_some());
    }
}
