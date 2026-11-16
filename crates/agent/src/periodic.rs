//! Barad Policy `onChangeDetecting`: periodic audits scheduled by the Client system service
//! and reported to trusted Servers only when the security state changes.
//!
//! - The schedule comes only from the local policy; a Server cannot start or change it.
//! - The service never audits by itself: it starts the normal engine (`audit --json
//!   --scheduled`) as each registered user, with that user's privileges.
//! - Missed occurrences (machine off, suspended, service stopped) produce one catch-up audit.
//! - Per trusted Server the service keeps the last state the Server confirmed and at most one
//!   pending report: the latest meaningful one. Only an acknowledgement confirms it.
use crate::requirements as req;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub(crate) const STATE_SCHEMA: &str = "baradwatchu.periodic-state.v1";
pub(crate) const CHANGE_REPORT_SCHEMA: &str = "baradwatchu.change-report.v1";
pub(crate) const CHANGE_REPORT_PATH: &str = "/v1/change-reports";
/// Advertised by a Server tunnel acknowledgement that accepts change reports.
pub(crate) const CHANGE_REPORT_FEATURE: &str = "CHANGE_REPORTS";
/// A failed attempt (busy, no session, audit error) is retried at most this often.
pub(crate) const RETRY_MS: u64 = 5 * 60 * 1000;

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct PendingReport {
    pub report_id: String,
    pub state_sha256: String,
    pub report: Value,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ServerSync {
    /// Normalized state the Server acknowledged last.
    #[serde(default)]
    pub confirmed_sha256: Option<String>,
    #[serde(default)]
    pub pending: Option<PendingReport>,
}

/// Persistent scheduler and synchronization state of one registered user.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct UserState {
    pub schema_version: String,
    /// When the last periodic audit was started successfully (anchor of the schedule).
    #[serde(default)]
    pub last_run_unix_ms: Option<u64>,
    #[serde(default)]
    pub retry_after_unix_ms: Option<u64>,
    #[serde(default)]
    pub last_error: Option<String>,
    #[serde(default)]
    pub servers: BTreeMap<String, ServerSync>,
}

impl Default for UserState {
    fn default() -> Self {
        Self {
            schema_version: STATE_SCHEMA.into(),
            last_run_unix_ms: None,
            retry_after_unix_ms: None,
            last_error: None,
            servers: BTreeMap::new(),
        }
    }
}

/// Should an audit start now? The first evaluation (no anchor) runs at once; afterwards an
/// audit is due when the next occurrence after the anchor is not in the future. However many
/// occurrences were missed, this is one audit, and the anchor then moves to `now`.
pub(crate) fn due(state: &UserState, cron: &crate::cron::Cron, now: u64) -> bool {
    due_with(state, now, |after| cron.next_after(after))
}

pub(crate) fn due_with(state: &UserState, now: u64, next: impl Fn(u64) -> Option<u64>) -> bool {
    if state.retry_after_unix_ms.is_some_and(|retry| retry > now) {
        return false;
    }
    match state.last_run_unix_ms {
        None => true,
        // A clock moved backwards leaves a future anchor: run once and re-anchor.
        Some(last) if last > now + 60_000 => true,
        Some(last) => next(last).is_some_and(|occurrence| occurrence <= now),
    }
}

pub(crate) fn record_failure(state: &mut UserState, now: u64, error: &str) {
    state.retry_after_unix_ms = Some(now + RETRY_MS);
    state.last_error = Some(error.chars().take(200).collect());
}

/// After a successful audit: re-anchor the schedule and queue the report for every Server of
/// this user whose confirmed state differs. `servers` are the user's configured Servers.
pub(crate) fn record_audit(
    state: &mut UserState,
    now: u64,
    servers: &[String],
    report: &Value,
    new_report_id: impl Fn() -> String,
) {
    state.last_run_unix_ms = Some(now);
    state.retry_after_unix_ms = None;
    state.last_error = None;
    let report = transmitted_report(report);
    let sha = state_sha256(&report);
    state.servers.retain(|id, _| servers.contains(id));
    for server in servers {
        let sync = state.servers.entry(server.clone()).or_default();
        if sync.confirmed_sha256.as_deref() == Some(sha.as_str()) {
            // Back to what the Server already knows: nothing to send.
            sync.pending = None;
        } else if sync.pending.as_ref().map(|p| &p.state_sha256) != Some(&sha) {
            // The latest meaningful state replaces an older unsent one.
            sync.pending = Some(PendingReport {
                report_id: new_report_id(),
                state_sha256: sha.clone(),
                report: report.clone(),
            });
        }
    }
}

/// The Server stored the report: its state becomes the confirmed one. Acknowledgements of an
/// older, already replaced report confirm nothing.
pub(crate) fn confirm(state: &mut UserState, server: &str, report_id: &str) -> bool {
    let Some(sync) = state.servers.get_mut(server) else {
        return false;
    };
    match sync.pending.take() {
        Some(pending) if pending.report_id == report_id => {
            sync.confirmed_sha256 = Some(pending.state_sha256);
            true
        }
        other => {
            sync.pending = other;
            false
        }
    }
}

/// Report as sent to a Server: local file locations (PDF, text log) stay on the workstation.
pub(crate) fn transmitted_report(report: &Value) -> Value {
    let mut report = report.clone();
    if let Some(object) = report.as_object_mut() {
        object.remove("pdf");
        object.remove("logFile");
    }
    report
}

fn sorted_by(mut items: Vec<Value>, keys: &[&str]) -> Vec<Value> {
    let key = |value: &Value| {
        keys.iter()
            .map(|k| value[*k].to_string())
            .collect::<Vec<_>>()
    };
    items.sort_by_key(key);
    items
}

fn pick(value: &Value, fields: &[&str]) -> Value {
    Value::Object(
        fields
            .iter()
            .map(|field| ((*field).to_owned(), value[*field].clone()))
            .collect(),
    )
}

/// Security-relevant content of a report, without timestamps, file locations, PDF/log data,
/// generated identifiers or free-text details (which carry ages, counters and paths).
pub(crate) fn normalized_state(report: &Value) -> Value {
    let list = |value: &Value| value.as_array().cloned().unwrap_or_default();
    let results = list(&report["results"])
        .iter()
        .map(|result| {
            let mut item = pick(
                result,
                &["id", "status", "complianceStatus", "priority", "summary"],
            );
            item["provenance"] = pick(
                &result["provenance"],
                &[
                    "toolId",
                    "toolVersion",
                    "origin",
                    "expectedSha256",
                    "actualSha256",
                    "integrityStatus",
                    "isOverride",
                    "overrideBuiltinId",
                ],
            );
            item
        })
        .collect();
    let providers = list(&report["extensions"]["providers"])
        .iter()
        .map(|p| {
            pick(
                p,
                &[
                    "requirementId",
                    "providerId",
                    "required",
                    "status",
                    "summary",
                ],
            )
        })
        .collect();
    let disabled = list(&report["extensions"]["disabledRequirements"])
        .iter()
        .map(|d| pick(d, &["id", "priority"]))
        .collect();
    let installation = &report["installation"];
    let files = list(&installation["files"])
        .iter()
        .map(|f| pick(f, &["path", "state", "actualSha256"]))
        .collect();
    json!({
        "results": sorted_by(results, &["id"]),
        "providers": sorted_by(providers, &["requirementId", "providerId"]),
        "disabled": sorted_by(disabled, &["id"]),
        "installation": {
            "status": installation["status"],
            "platform": installation["platform"],
            "manifestSha256": installation["manifestSha256"],
            "files": sorted_by(files, &["path"]),
        },
        "client": pick(&report["client"], &["version", "sha256"]),
        "policy": pick(&report["policy"], &["state", "sha256"]),
    })
}

pub(crate) fn state_sha256(report: &Value) -> String {
    let bytes = serde_json::to_vec(&normalized_state(report)).unwrap_or_default();
    Sha256::digest(&bytes)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

pub(crate) fn new_report_id() -> String {
    format!(
        "auto-{}",
        crate::consent::random_hex(12).unwrap_or_else(|_| format!("{:x}", req::now_ms()))
    )
}

/// Body of `POST /v1/change-reports` on the tunnel.
pub(crate) fn change_report_body(device_id: &str, pending: &PendingReport) -> Value {
    json!({
        "schemaVersion": CHANGE_REPORT_SCHEMA,
        "reportId": pending.report_id,
        "deviceId": device_id,
        "stateSha256": pending.state_sha256,
        "report": pending.report,
    })
}

// ---------------------------------------------------------------------------------------
// Running the audit as the registered user
// ---------------------------------------------------------------------------------------

/// The longest an audit may run (the remote audit limit).
pub(crate) const AUDIT_LIMIT: std::time::Duration = std::time::Duration::from_secs(35 * 60);
const MAX_REPORT: usize = 8 * 1024 * 1024;

/// Reads the child's stdout (bounded) and waits for it with a deadline.
#[cfg(unix)]
fn collect(mut child: std::process::Child) -> Result<Value, String> {
    use std::io::Read;
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return Err("cannot read the audit output".into());
    };
    let reader = std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let _ = stdout.take(MAX_REPORT as u64 + 1).read_to_end(&mut bytes);
        bytes
    });
    let deadline = std::time::Instant::now() + AUDIT_LIMIT + std::time::Duration::from_secs(60);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(200))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err("AUDIT_TIMEOUT".into());
            }
        }
    }
    let bytes = reader.join().map_err(|_| "cannot read the audit output")?;
    if bytes.len() > MAX_REPORT {
        return Err("audit report too large".into());
    }
    parse_report(&bytes)
}

/// The child prints the standard audit report; anything else (busy, error text) is a failure.
pub(crate) fn parse_report(bytes: &[u8]) -> Result<Value, String> {
    let report: Value = serde_json::from_slice(bytes).map_err(|_| {
        let text = String::from_utf8_lossy(bytes);
        let first = text.lines().next().unwrap_or("").trim();
        if first.is_empty() {
            "the audit produced no report (busy or failed)".to_owned()
        } else {
            first.chars().take(200).collect()
        }
    })?;
    if report["schemaVersion"] != "baradwatchu.audit.v1" || !report["results"].is_array() {
        return Err("the audit output is not an audit report".into());
    }
    Ok(report)
}

fn audit_arguments() -> [&'static str; 3] {
    ["audit", "--json", "--scheduled"]
}

/// Linux: a transient systemd unit running as the user, outside the hardened sandbox of the
/// service (that sandbox would hide parts of the system from the checks). systemd gives the
/// unit the user's HOME, USER and primary group; it is not a login session.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn run_audit_as(principal: &crate::ipc::Principal) -> Result<Value, String> {
    use std::process::{Command, Stdio};
    let uid = principal.uid().ok_or("unsupported account")?;
    if uid == 0 {
        return Err("periodic audits never run as root".into());
    }
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let child = Command::new("/usr/bin/systemd-run")
        .args([
            "--quiet",
            "--wait",
            "--pipe",
            "--collect",
            "--service-type=exec",
            &format!("--uid={uid}"),
            "--property=RuntimeMaxSec=2100",
            "--description=BaradWatchU periodic audit (Barad Policy)",
            "--",
        ])
        .arg(exe)
        .args(audit_arguments())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| format!("cannot start systemd-run: {e}"))?;
    collect(child)
}

/// macOS: the launchd daemon (root) starts the agent with the user's uid, gid and groups.
#[cfg(target_os = "macos")]
pub(crate) fn run_audit_as(principal: &crate::ipc::Principal) -> Result<Value, String> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};
    let uid = principal.uid().ok_or("unsupported account")?;
    if uid == 0 {
        return Err("periodic audits never run as root".into());
    }
    // SAFETY: getpwuid_r fills `entry` with pointers into `buffer`, both outliving their use.
    let (name, home, gid) = unsafe {
        let mut entry: libc::passwd = std::mem::zeroed();
        let mut found: *mut libc::passwd = std::ptr::null_mut();
        let mut buffer = vec![0 as libc::c_char; 16 * 1024];
        if libc::getpwuid_r(
            uid,
            &mut entry,
            buffer.as_mut_ptr(),
            buffer.len(),
            &mut found,
        ) != 0
            || found.is_null()
        {
            return Err("unknown user".into());
        }
        (
            std::ffi::CStr::from_ptr(entry.pw_name).to_owned(),
            std::ffi::CStr::from_ptr(entry.pw_dir)
                .to_string_lossy()
                .into_owned(),
            entry.pw_gid,
        )
    };
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let user = name.to_string_lossy().into_owned();
    let mut command = Command::new(exe);
    command
        .args(audit_arguments())
        .env_clear()
        .env("HOME", &home)
        .env("USER", &user)
        .env("LOGNAME", &user)
        .env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")
        .current_dir(&home)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    // SAFETY: initgroups only touches this (forked) process before exec.
    unsafe {
        command.pre_exec(move || {
            if libc::initgroups(name.as_ptr(), gid as _) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    command.gid(gid).uid(uid);
    collect(command.spawn().map_err(|e| e.to_string())?)
}

/// Windows: only while the user has a session on this machine (the token of that session is
/// required to run as the user without a password); otherwise the audit waits (catch-up).
#[cfg(windows)]
pub(crate) fn run_audit_as(principal: &crate::ipc::Principal) -> Result<Value, String> {
    let sid = principal.sid().ok_or("unsupported account")?;
    if sid == "S-1-5-18" {
        return Err("periodic audits never run as SYSTEM".into());
    }
    windows_session::run_as_session_user(sid, &audit_arguments()).and_then(|bytes| {
        if bytes.len() > MAX_REPORT {
            Err("audit report too large".into())
        } else {
            parse_report(&bytes)
        }
    })
}

#[cfg(windows)]
mod windows_session {
    //! WTSQueryUserToken + CreateProcessAsUserW. Compiled for Windows; see MEMORY for its
    //! verification state.
    use std::{os::windows::ffi::OsStrExt, ptr};
    use windows_sys::Win32::{
        Foundation::{
            CloseHandle, SetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
        },
        Security::{
            Authorization::ConvertSidToStringSidW, GetTokenInformation, TokenUser,
            SECURITY_ATTRIBUTES, TOKEN_USER,
        },
        Storage::FileSystem::ReadFile,
        System::{
            Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock},
            Pipes::CreatePipe,
            RemoteDesktop::{
                WTSActive, WTSEnumerateSessionsW, WTSFreeMemory, WTSQueryUserToken,
                WTS_CURRENT_SERVER_HANDLE, WTS_SESSION_INFOW,
            },
            Threading::{
                CreateProcessAsUserW, TerminateProcess, WaitForSingleObject, CREATE_NO_WINDOW,
                CREATE_UNICODE_ENVIRONMENT, PROCESS_INFORMATION, STARTF_USESTDHANDLES,
                STARTUPINFOW,
            },
        },
    };

    struct Owned(HANDLE);
    impl Drop for Owned {
        fn drop(&mut self) {
            if !self.0.is_null() {
                // SAFETY: the handle is owned and closed once.
                unsafe { CloseHandle(self.0) };
            }
        }
    }

    unsafe fn token_sid(token: HANDLE) -> Option<String> {
        let mut needed = 0u32;
        GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut needed);
        let mut buffer = vec![0u8; needed as usize];
        if GetTokenInformation(
            token,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            needed,
            &mut needed,
        ) == 0
        {
            return None;
        }
        let user = &*(buffer.as_ptr() as *const TOKEN_USER);
        let mut text: *mut u16 = ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut text) == 0 {
            return None;
        }
        let length = (0..).take_while(|&i| *text.add(i) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(text, length));
        LocalFree(text.cast());
        Some(sid)
    }

    /// Token of an active session of `sid`.
    unsafe fn session_token(sid: &str) -> Option<Owned> {
        let mut sessions: *mut WTS_SESSION_INFOW = ptr::null_mut();
        let mut count = 0u32;
        if WTSEnumerateSessionsW(WTS_CURRENT_SERVER_HANDLE, 0, 1, &mut sessions, &mut count) == 0 {
            return None;
        }
        let mut found = None;
        for session in std::slice::from_raw_parts(sessions, count as usize) {
            if session.State != WTSActive {
                continue;
            }
            let mut token: HANDLE = ptr::null_mut();
            if WTSQueryUserToken(session.SessionId, &mut token) == 0 {
                continue;
            }
            let token = Owned(token);
            if token_sid(token.0).as_deref() == Some(sid) {
                found = Some(token);
                break;
            }
        }
        WTSFreeMemory(sessions.cast());
        found
    }

    pub(super) fn run_as_session_user(sid: &str, args: &[&str]) -> Result<Vec<u8>, String> {
        let exe = std::env::current_exe().map_err(|e| e.to_string())?;
        let mut command_line: Vec<u16> = std::iter::once('"' as u16)
            .chain(exe.as_os_str().encode_wide())
            .chain("\"".encode_utf16())
            .collect();
        for arg in args {
            command_line.push(' ' as u16);
            command_line.extend(arg.encode_utf16());
        }
        command_line.push(0);
        // SAFETY: every handle is owned by an `Owned` guard; buffers outlive the calls.
        unsafe {
            let token = session_token(sid).ok_or("NO_USER_SESSION")?;
            let attributes = SECURITY_ATTRIBUTES {
                nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
                lpSecurityDescriptor: ptr::null_mut(),
                bInheritHandle: 1,
            };
            let (mut read, mut write): (HANDLE, HANDLE) = (ptr::null_mut(), ptr::null_mut());
            if CreatePipe(&mut read, &mut write, &attributes, 0) == 0 {
                return Err("cannot create the output pipe".into());
            }
            let (read, write) = (Owned(read), Owned(write));
            SetHandleInformation(read.0, HANDLE_FLAG_INHERIT, 0);
            let mut environment: *mut core::ffi::c_void = ptr::null_mut();
            if CreateEnvironmentBlock(&mut environment, token.0, 0) == 0 {
                return Err("cannot build the user environment".into());
            }
            let mut startup: STARTUPINFOW = std::mem::zeroed();
            startup.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
            startup.dwFlags = STARTF_USESTDHANDLES;
            startup.hStdOutput = write.0;
            startup.hStdError = ptr::null_mut();
            startup.hStdInput = ptr::null_mut();
            let mut info: PROCESS_INFORMATION = std::mem::zeroed();
            let created = CreateProcessAsUserW(
                token.0,
                ptr::null(),
                command_line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                1,
                CREATE_NO_WINDOW | CREATE_UNICODE_ENVIRONMENT,
                environment,
                ptr::null(),
                &startup,
                &mut info,
            );
            DestroyEnvironmentBlock(environment);
            if created == 0 {
                return Err(format!(
                    "cannot start the audit as the user: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let process = Owned(info.hProcess);
            drop(Owned(info.hThread));
            drop(write);
            let reader_handle = read.0 as usize;
            let reader = std::thread::spawn(move || {
                let mut bytes = Vec::new();
                let mut chunk = [0u8; 65536];
                loop {
                    let mut got = 0u32;
                    let ok = ReadFile(
                        reader_handle as HANDLE,
                        chunk.as_mut_ptr(),
                        chunk.len() as u32,
                        &mut got,
                        ptr::null_mut(),
                    );
                    if ok == 0 || got == 0 || bytes.len() > super::MAX_REPORT {
                        break;
                    }
                    bytes.extend_from_slice(&chunk[..got as usize]);
                }
                bytes
            });
            let limit = (super::AUDIT_LIMIT.as_millis() as u32).saturating_add(60_000);
            if WaitForSingleObject(process.0, limit) != WAIT_OBJECT_0 {
                TerminateProcess(process.0, 1);
                WaitForSingleObject(process.0, 5000);
            }
            let bytes = reader.join().map_err(|_| "cannot read the audit output")?;
            drop(read);
            Ok(bytes)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    fn report(status: &str) -> Value {
        json!({
            "schemaVersion": "baradwatchu.audit.v1",
            "completedAtUnixMs": 1,
            "initiator": {"origin": "SCHEDULED"},
            "client": {"version": "0.0.1", "sha256": "a".repeat(64)},
            "policy": {"state": "APPLIED", "path": "/etc/baradwatchu/barad-policy.json", "sha256": "b".repeat(64)},
            "pdf": {"status": "GENERATED", "path": "/home/u/.cache/x.pdf"},
            "logFile": "/home/u/.cache/x.log",
            "installation": {"status": "VERIFIED", "platform": "linux", "manifestSha256": "c".repeat(64), "verifiedFiles": 1,
                "files": [{"requirementId": "REQ-001", "path": "catalog/checks/REQ-001/check.sh", "expectedSha256": "d".repeat(64), "actualSha256": "d".repeat(64), "state": "VERIFIED"}]},
            "extensions": {"disabledRequirements": [], "providers": [
                {"requirementId": "REQ-002", "providerId": "clamav", "required": false, "status": "PASS", "summary": "ok", "details": ["signatures 1 day old"]}]},
            "results": [
                {"id": "REQ-002", "name": "AV", "description": "", "priority": "HIGHEST", "status": "PASS", "summary": "ok", "details": ["age 1 day"], "completedAtUnixMs": 5},
                {"id": "REQ-001", "name": "Updates", "description": "", "priority": "HIGH", "status": status, "summary": "updates", "details": [], "completedAtUnixMs": 6,
                 "provenance": {"toolId": "REQ-001", "origin": "BUILTIN", "toolPath": "/tmp/x", "expectedSha256": "d".repeat(64), "actualSha256": "d".repeat(64), "integrityStatus": "VERIFIED", "integrityScope": "x", "isOverride": false}}
            ]
        })
    }

    fn ids() -> impl Fn() -> String {
        let next = Cell::new(0);
        move || {
            next.set(next.get() + 1);
            format!("auto-{}", next.get())
        }
    }

    #[test]
    fn volatile_data_does_not_change_the_state_but_security_data_does() {
        let base = state_sha256(&report("PASS"));
        let mut volatile = report("PASS");
        volatile["completedAtUnixMs"] = json!(999);
        volatile["results"][0]["completedAtUnixMs"] = json!(999);
        volatile["results"][0]["details"] = json!(["age 2 days"]);
        volatile["results"][1]["provenance"]["toolPath"] = json!("/tmp/other");
        volatile["pdf"] = json!({"status": "FAILED"});
        volatile["logFile"] = Value::Null;
        volatile["extensions"]["providers"][0]["details"] = json!(["changed"]);
        volatile["policy"]["path"] = json!("/elsewhere");
        // Order of results is not meaningful.
        volatile["results"] = json!([
            volatile["results"][1].clone(),
            volatile["results"][0].clone()
        ]);
        assert_eq!(state_sha256(&volatile), base);
        assert_ne!(state_sha256(&report("FAIL")), base);
        let mut provider = report("PASS");
        provider["extensions"]["providers"][0]["status"] = json!("FAIL");
        assert_ne!(state_sha256(&provider), base);
        let mut evidence = report("PASS");
        evidence["results"][0]["summary"] = json!("signatures too old");
        assert_ne!(state_sha256(&evidence), base);
        let mut integrity = report("PASS");
        integrity["installation"]["status"] = json!("MISMATCH");
        integrity["installation"]["files"][0]["state"] = json!("MODIFIED");
        assert_ne!(state_sha256(&integrity), base);
        let mut policy = report("PASS");
        policy["policy"]["sha256"] = json!("e".repeat(64));
        assert_ne!(state_sha256(&policy), base);
        let mut policy_state = report("PASS");
        policy_state["policy"]["state"] = json!("UNTRUSTED");
        assert_ne!(state_sha256(&policy_state), base);
    }

    #[test]
    fn first_audit_is_sent_identical_states_are_suppressed_and_changes_replace_pending() {
        let servers = vec!["SRV-A".to_owned()];
        let new_id = ids();
        let mut state = UserState::default();
        record_audit(&mut state, 10, &servers, &report("PASS"), &new_id);
        let first = state.servers["SRV-A"].pending.clone().unwrap();
        assert_eq!(first.report_id, "auto-1");
        // Local paths never leave the workstation.
        assert!(first.report.get("pdf").is_none() && first.report.get("logFile").is_none());
        // Same state again before the acknowledgement: still the same pending report.
        record_audit(&mut state, 20, &servers, &report("PASS"), &new_id);
        assert_eq!(
            state.servers["SRV-A"].pending.as_ref().unwrap().report_id,
            "auto-1"
        );
        assert!(confirm(&mut state, "SRV-A", "auto-1"));
        assert!(state.servers["SRV-A"].pending.is_none());
        // Identical state after confirmation: nothing to send.
        record_audit(&mut state, 30, &servers, &report("PASS"), &new_id);
        assert!(state.servers["SRV-A"].pending.is_none());
        // A change is queued; a newer change replaces it while the Server is unreachable.
        record_audit(&mut state, 40, &servers, &report("FAIL"), &new_id);
        assert_eq!(
            state.servers["SRV-A"].pending.as_ref().unwrap().report_id,
            "auto-2"
        );
        record_audit(&mut state, 50, &servers, &report("WARN"), &new_id);
        assert_eq!(
            state.servers["SRV-A"].pending.as_ref().unwrap().report_id,
            "auto-3"
        );
        // A late acknowledgement of the replaced report confirms nothing.
        assert!(!confirm(&mut state, "SRV-A", "auto-2"));
        assert!(state.servers["SRV-A"].pending.is_some());
        // Back to the confirmed state before reconnecting: nothing left to send.
        record_audit(&mut state, 60, &servers, &report("PASS"), &new_id);
        assert!(state.servers["SRV-A"].pending.is_none());
        // Servers no longer configured are forgotten; new ones get the current state.
        record_audit(
            &mut state,
            70,
            &["SRV-B".to_owned()],
            &report("PASS"),
            &new_id,
        );
        assert!(!state.servers.contains_key("SRV-A"));
        assert!(state.servers["SRV-B"].pending.is_some());
    }

    #[test]
    fn failed_transmission_keeps_the_report_pending_until_acknowledged() {
        let mut state = UserState::default();
        record_audit(&mut state, 1, &["SRV-A".into()], &report("PASS"), ids());
        // No acknowledgement (disconnected): it survives a restart of the service.
        let saved = serde_json::to_vec(&state).unwrap();
        let mut restored: UserState = serde_json::from_slice(&saved).unwrap();
        assert_eq!(restored, state);
        assert!(!confirm(&mut restored, "SRV-X", "auto-1"));
        assert!(restored.servers["SRV-A"].confirmed_sha256.is_none());
        assert!(confirm(&mut restored, "SRV-A", "auto-1"));
        assert!(restored.servers["SRV-A"].confirmed_sha256.is_some());
    }

    #[test]
    fn schedule_runs_first_then_on_occurrence_with_a_single_catch_up() {
        let cron = crate::cron::Cron::parse("0 * * * *").unwrap();
        let next = |after| cron.next_after_with(after, crate::cron::utc_fields);
        let hour = 3_600_000u64;
        let start = 1_794_651_600_000u64; // 10:20 UTC
        let mut state = UserState::default();
        assert!(due_with(&state, start, next));
        record_audit(&mut state, start, &[], &report("PASS"), ids());
        assert!(!due_with(&state, start + 60_000, next));
        assert!(!due_with(&state, start + 39 * 60_000, next));
        assert!(due_with(&state, start + 40 * 60_000, next)); // 11:00
                                                              // Powered off for two days: one audit when the service starts, then normal schedule.
        let resumed = start + 48 * hour + 5 * 60_000;
        assert!(due_with(&state, resumed, next));
        record_audit(&mut state, resumed, &[], &report("PASS"), ids());
        assert!(!due_with(&state, resumed + 60_000, next));
        assert!(due_with(&state, resumed + 35 * 60_000, next));
        // Failure: no retry storm, one retry after the back-off.
        record_failure(&mut state, resumed + 35 * 60_000, "busy");
        assert!(!due_with(&state, resumed + 36 * 60_000, next));
        assert!(due_with(&state, resumed + 35 * 60_000 + RETRY_MS, next));
        // Clock moved back far before the anchor: run once and re-anchor.
        assert!(due_with(
            &UserState {
                last_run_unix_ms: Some(start + 100 * hour),
                ..UserState::default()
            },
            start,
            next
        ));
    }

    #[test]
    fn only_a_complete_audit_report_is_accepted_from_the_child() {
        assert!(parse_report(br#"{"schemaVersion":"baradwatchu.audit.v1","results":[]}"#).is_ok());
        assert!(parse_report(b"").unwrap_err().contains("no report"));
        assert_eq!(
            parse_report(b"Error: Another audit is in progress\n").unwrap_err(),
            "Error: Another audit is in progress"
        );
        assert!(parse_report(br#"{"schemaVersion":"other","results":[]}"#).is_err());
    }
}
