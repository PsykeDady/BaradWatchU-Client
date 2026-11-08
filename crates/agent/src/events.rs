//! Application events and notification preferences.
//!
//! The agent records *what happened* (audit outcomes, consent requests) in a bounded local
//! log; the tray companion decides whether to show a native notification and the dashboard
//! shows the history. Nothing here talks to the network or depends on the tray running.
use crate::requirements::{
    self as req, AuditReport, CliError, CliOutput, IntegrityStatus, ResultStatus,
    INTEGRITY_GATE_SUMMARY,
};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io,
    path::{Path, PathBuf},
};

const EVENTS_FILE: &str = "events.jsonl";
const EVENTS_LOCK: &str = ".events.lock";
const KEEP_EVENTS: usize = 200;
const MAX_EVENTS_FILE: u64 = 1024 * 1024;
const PREFERENCES_SCHEMA: &str = "baradwatchu.notifications.v1";
const SNAPSHOT_SCHEMA: &str = "baradwatchu.companion-state.v1";
/// Events returned per snapshot: the tray coalesces bursts, so a backlog is never replayed.
const SNAPSHOT_EVENTS: usize = 20;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum EventKind {
    AuditCompleted,
    AuditAnomalies,
    AuditError,
    IntegrityIssue,
    ConsentRequested,
    ConsentAccepted,
    ConsentRejected,
    ConsentExpired,
}

/// `INFO` events are the "informative" class users may silence; `ACTION` needs a decision.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Severity {
    Info,
    Warning,
    Critical,
    Action,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Event {
    pub id: u64,
    pub at_unix_ms: u64,
    pub kind: EventKind,
    pub severity: Severity,
    pub title: String,
    pub body: String,
    /// Same anomalies as the previous audit: shown only if informative notifications are on.
    #[serde(default)]
    pub repeated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audit_completed_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
}

pub(crate) struct NewEvent {
    pub kind: EventKind,
    pub severity: Severity,
    pub title: String,
    pub body: String,
    pub audit_completed_at_unix_ms: Option<u64>,
    pub request_id: Option<String>,
    pub fingerprint: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NotificationPreferences {
    #[serde(default = "preferences_schema")]
    pub schema_version: String,
    /// Master switch for audit/integrity/communication notifications. Consent requests are
    /// never silenced: they open the dedicated consent window instead.
    pub enabled: bool,
    /// Informative notifications: clean audit, repeated anomalies, consent outcomes.
    pub informative: bool,
}

fn preferences_schema() -> String {
    PREFERENCES_SCHEMA.into()
}

impl Default for NotificationPreferences {
    fn default() -> Self {
        Self {
            schema_version: PREFERENCES_SCHEMA.into(),
            enabled: true,
            informative: true,
        }
    }
}

/// Holds an exclusive advisory lock on `dir/name` for the guard's lifetime (Unix `flock`).
pub(crate) struct DirLock(#[allow(dead_code)] File);

pub(crate) fn lock_dir(dir: &Path, name: &str) -> Result<DirLock, CliError> {
    req::ensure_private_dir(dir)?;
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    let file = options
        .open(dir.join(name))
        .map_err(|_| CliError("Cannot open local lock file".into()))?;
    #[cfg(unix)]
    {
        use std::os::unix::io::AsRawFd;
        // SAFETY: valid descriptor owned by `file`; the lock is released when it is closed.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(CliError("Cannot lock local data".into()));
        }
    }
    Ok(DirLock(file))
}

fn events_path() -> Result<PathBuf, CliError> {
    Ok(req::state_home()?.join(EVENTS_FILE))
}

/// Reads the bounded event log; malformed lines are skipped rather than failing the caller.
pub fn read_events() -> Result<Vec<Event>, CliError> {
    read_events_at(&events_path()?)
}

fn read_events_at(path: &Path) -> Result<Vec<Event>, CliError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file() || metadata.file_type().is_symlink() {
                return Err(CliError("Event log is unsafe".into()));
            }
            if metadata.len() > MAX_EVENTS_FILE {
                return Err(CliError("Event log is too large".into()));
            }
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(_) => return Err(CliError("Cannot inspect event log".into())),
    }
    let text = fs::read_to_string(path).map_err(|_| CliError("Cannot read event log".into()))?;
    Ok(text
        .lines()
        .filter_map(|line| serde_json::from_str::<Event>(line).ok())
        .collect())
}

pub(crate) fn append_event(new: NewEvent) -> Result<Event, CliError> {
    let dir = req::state_home()?;
    let _lock = lock_dir(&dir, EVENTS_LOCK)?;
    let path = dir.join(EVENTS_FILE);
    let mut events = read_events_at(&path).unwrap_or_default();
    let last_id = events.last().map_or(0, |event| event.id);
    let now = req::now_ms();
    let event = Event {
        // Monotonic even if the clock goes backwards; doubles as a millisecond timestamp.
        id: now.max(last_id + 1),
        at_unix_ms: now,
        kind: new.kind,
        severity: new.severity,
        title: new.title,
        body: new.body,
        repeated: false,
        audit_completed_at_unix_ms: new.audit_completed_at_unix_ms,
        request_id: new.request_id,
        fingerprint: new.fingerprint,
    };
    let mut event = event;
    if let Some(fingerprint) = &event.fingerprint {
        event.repeated = events
            .iter()
            .rev()
            .find(|previous| previous.audit_completed_at_unix_ms.is_some())
            .is_some_and(|previous| {
                previous.kind == event.kind && previous.fingerprint.as_ref() == Some(fingerprint)
            });
    }
    events.push(event.clone());
    let start = events.len().saturating_sub(KEEP_EVENTS);
    let mut text = String::new();
    for item in &events[start..] {
        text.push_str(
            &serde_json::to_string(item).map_err(|_| CliError("Cannot encode event".into()))?,
        );
        text.push('\n');
    }
    req::atomic_text(&path, &text)?;
    Ok(event)
}

/// Counts used by the tray tooltip and events; PASS is never presented as certification.
#[derive(Clone, Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditDigest {
    pub completed_at_unix_ms: u64,
    pub overall_status: String,
    pub pass: usize,
    pub fail: usize,
    pub warn: usize,
    pub error: usize,
    pub other: usize,
    /// Controls blocked by the SHA-256 gate (not executed).
    pub integrity_issues: Vec<String>,
    /// Execution errors other than integrity (configuration, timeout, invalid output…).
    pub execution_errors: Vec<String>,
    pub anomalies: Vec<String>,
    /// Custom checks: their PASS is the tool's own claim, kept distinct from builtins.
    pub custom_checks: usize,
    pub custom_not_pass: usize,
}

pub(crate) fn digest(report: &AuditReport) -> AuditDigest {
    let entry = req::history_entry(report);
    let mut digest = AuditDigest {
        completed_at_unix_ms: report.completed_at_unix_ms,
        overall_status: entry.overall_status,
        pass: entry.pass,
        fail: entry.fail,
        warn: entry.warn,
        error: entry.error,
        other: entry.other,
        ..AuditDigest::default()
    };
    for result in &report.results {
        let integrity_blocked = result.status == ResultStatus::Error
            && (result.summary == INTEGRITY_GATE_SUMMARY
                || result
                    .provenance
                    .as_ref()
                    .is_some_and(|p| p.integrity_status == IntegrityStatus::Mismatch));
        match result.status {
            ResultStatus::Error if integrity_blocked => {
                digest.integrity_issues.push(result.id.clone())
            }
            ResultStatus::Error => digest.execution_errors.push(result.id.clone()),
            ResultStatus::Fail | ResultStatus::Warn => digest
                .anomalies
                .push(format!("{}:{}", result.id, result.status)),
            _ => {}
        }
        if result
            .provenance
            .as_ref()
            .is_some_and(|p| p.origin == req::ControlOrigin::Custom)
        {
            digest.custom_checks += 1;
            if result.status != ResultStatus::Pass {
                digest.custom_not_pass += 1;
            }
        }
    }
    digest
}

fn short_list(items: &[String]) -> String {
    let mut text = items.iter().take(5).cloned().collect::<Vec<_>>().join(", ");
    if items.len() > 5 {
        text.push_str(&format!(" e altri {}", items.len() - 5));
    }
    text
}

/// One event per audit, classified by its most serious aspect, so an audit never produces
/// a burst of notifications.
pub(crate) fn audit_event(report: &AuditReport) -> NewEvent {
    let d = digest(report);
    let counts = format!(
        "PASS {} · FAIL {} · WARN {} · ERROR {}",
        d.pass, d.fail, d.warn, d.error
    );
    let mut fingerprint = d
        .integrity_issues
        .iter()
        .map(|id| format!("{id}:INTEGRITY"))
        .chain(d.execution_errors.iter().map(|id| format!("{id}:ERROR")))
        .chain(d.anomalies.iter().cloned())
        .collect::<Vec<_>>();
    fingerprint.sort();
    let (kind, severity, title, body) = if !d.integrity_issues.is_empty() {
        (
            EventKind::IntegrityIssue,
            Severity::Critical,
            "Audit: problema di integrità".to_owned(),
            format!(
                "Non eseguiti perché lo SHA-256 del tool non corrisponde: {}. {counts}.",
                short_list(&d.integrity_issues)
            ),
        )
    } else if !d.execution_errors.is_empty() {
        (
            EventKind::AuditError,
            Severity::Critical,
            "Audit: errori di esecuzione".to_owned(),
            format!(
                "Controlli in errore: {}. {counts}.",
                short_list(&d.execution_errors)
            ),
        )
    } else if !d.anomalies.is_empty() {
        (
            EventKind::AuditAnomalies,
            Severity::Warning,
            "Audit con anomalie".to_owned(),
            format!("{counts}. Da verificare: {}.", short_list(&d.anomalies)),
        )
    } else {
        (
            EventKind::AuditCompleted,
            Severity::Info,
            "Audit completato".to_owned(),
            format!("{counts}. Esito dei controlli locali, non una certificazione di sicurezza."),
        )
    };
    NewEvent {
        kind,
        severity,
        title,
        body,
        audit_completed_at_unix_ms: Some(report.completed_at_unix_ms),
        request_id: None,
        fingerprint: (!fingerprint.is_empty()).then(|| fingerprint.join(",")),
    }
}

pub(crate) fn record_audit(report: &AuditReport) -> Result<Event, CliError> {
    append_event(audit_event(report))
}

fn preferences_path() -> Result<PathBuf, CliError> {
    Ok(req::state_dir()?.join("notifications.json"))
}

pub fn load_preferences() -> Result<NotificationPreferences, CliError> {
    let path = preferences_path()?;
    match fs::symlink_metadata(&path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(CliError("Notification preferences file is unsafe".into())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(NotificationPreferences::default())
        }
        Err(_) => return Err(CliError("Cannot inspect notification preferences".into())),
    }
    let text = fs::read_to_string(&path)
        .map_err(|_| CliError("Cannot read notification preferences".into()))?;
    let preferences: NotificationPreferences = serde_json::from_str(&text)
        .map_err(|_| CliError("Notification preferences JSON is invalid".into()))?;
    if preferences.schema_version != PREFERENCES_SCHEMA {
        return Err(CliError("Unsupported notification preferences".into()));
    }
    Ok(preferences)
}

pub fn save_preferences(preferences: &NotificationPreferences) -> Result<(), CliError> {
    let dir = req::state_dir()?;
    req::ensure_private_dir(&dir)?;
    let mut value = preferences.clone();
    value.schema_version = PREFERENCES_SCHEMA.into();
    req::atomic_json(&dir.join("notifications.json"), &value)
}

/// Linux: whether this user's tray companion holds its lock (pid written by the tray).
/// `None` when it cannot be determined on this platform.
pub fn tray_running() -> Option<bool> {
    if !cfg!(target_os = "linux") {
        return None;
    }
    let path = req::runtime_dir().ok()?.join("tray.lock");
    let Ok(text) = fs::read_to_string(path) else {
        return Some(false);
    };
    let Ok(pid) = text.trim().parse::<u32>() else {
        return Some(false);
    };
    Some(
        fs::read_to_string(format!("/proc/{pid}/comm"))
            .is_ok_and(|comm| comm.trim_end() == "baradwatchu-tra"),
    )
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Snapshot {
    schema_version: &'static str,
    agent_version: &'static str,
    latest_event_id: u64,
    events: Vec<Event>,
    preferences: NotificationPreferences,
    pending_consents: Vec<crate::consent::ConsentView>,
    last_audit: Option<AuditDigest>,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_audit_error: Option<String>,
}

/// State polled by the tray companion: one cheap call, no catalog scan, no tool execution.
pub fn snapshot_json(after: Option<u64>) -> Result<String, CliError> {
    let events = read_events()?;
    let latest_event_id = events.last().map_or(0, |event| event.id);
    let mut new_events = match after {
        Some(after) => events
            .into_iter()
            .filter(|event| event.id > after)
            .collect::<Vec<_>>(),
        None => vec![],
    };
    let skip = new_events.len().saturating_sub(SNAPSHOT_EVENTS);
    new_events.drain(..skip);
    let (last_audit, last_audit_error) = match req::load_last_audit() {
        Ok(report) => (report.as_ref().map(digest), None),
        Err(error) => (None, Some(error.0)),
    };
    req::output_json(&Snapshot {
        schema_version: SNAPSHOT_SCHEMA,
        agent_version: env!("CARGO_PKG_VERSION"),
        latest_event_id,
        events: new_events,
        preferences: load_preferences()?,
        pending_consents: crate::consent::pending_views()?,
        last_audit,
        last_audit_error,
    })
}

/// Dashboard view: preferences, recent events (newest first), consent requests, tray state.
pub(crate) fn dashboard_notifications_json() -> Result<String, CliError> {
    let mut events = read_events()?;
    events.reverse();
    events.truncate(50);
    req::output_json(&serde_json::json!({
        "schemaVersion": "baradwatchu.notifications-view.v1",
        "preferences": load_preferences()?,
        "events": events,
        "consents": crate::consent::all_views()?,
        "trayRunning": tray_running(),
    }))
}

pub(crate) fn dashboard_update_preferences(text: &str) -> Result<String, CliError> {
    let preferences: NotificationPreferences = serde_json::from_str(text)
        .map_err(|_| CliError("Preferenze di notifica non valide".into()))?;
    if preferences.schema_version != PREFERENCES_SCHEMA {
        return Err(CliError("Preferenze di notifica non supportate".into()));
    }
    save_preferences(&preferences)?;
    dashboard_notifications_json()
}

const NOTIFICATIONS_USAGE: &str =
    "Usage: notifications [--json] | notifications set enabled|informative on|off";
const EVENTS_USAGE: &str = "Usage: events --json [--after ID]";

pub fn run_events(args: &[OsString]) -> Result<CliOutput, CliError> {
    let after = match args {
        [flag] if flag == "--json" => None,
        [flag, option, value] if flag == "--json" && option == "--after" => Some(
            value
                .to_str()
                .and_then(|v| v.parse::<u64>().ok())
                .ok_or_else(|| CliError(EVENTS_USAGE.into()))?,
        ),
        _ => return Err(CliError(EVENTS_USAGE.into())),
    };
    Ok(CliOutput {
        text: snapshot_json(after)?,
        code: 0,
    })
}

pub fn run_notifications(args: &[OsString]) -> Result<CliOutput, CliError> {
    let text = |value: &OsString| value.to_str().unwrap_or("").to_owned();
    match args {
        [] => {
            let preferences = load_preferences()?;
            let on = |value: bool| if value { "attive" } else { "disattivate" };
            let mut text = format!(
                "Notifiche desktop: {}\nNotifiche informative: {}\n",
                on(preferences.enabled),
                on(preferences.informative)
            );
            let events = read_events()?;
            if events.is_empty() {
                text.push_str("Nessun evento registrato.\n");
            } else {
                text.push_str("\nEventi recenti:\n");
                for event in events.iter().rev().take(10) {
                    text.push_str(&format!(
                        "  {} [{:?}] {}: {}\n",
                        event.id, event.severity, event.title, event.body
                    ));
                }
            }
            Ok(CliOutput { text, code: 0 })
        }
        [flag] if flag == "--json" => Ok(CliOutput {
            text: dashboard_notifications_json()?,
            code: 0,
        }),
        [command, key, value] if command == "set" => {
            let enabled = match text(value).as_str() {
                "on" => true,
                "off" => false,
                _ => return Err(CliError(NOTIFICATIONS_USAGE.into())),
            };
            let mut preferences = load_preferences()?;
            match text(key).as_str() {
                "enabled" => preferences.enabled = enabled,
                "informative" => preferences.informative = enabled,
                _ => return Err(CliError(NOTIFICATIONS_USAGE.into())),
            }
            save_preferences(&preferences)?;
            Ok(CliOutput {
                text: format!("Preferenza {} impostata a {}.\n", text(key), text(value)),
                code: 0,
            })
        }
        _ => Err(CliError(NOTIFICATIONS_USAGE.into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requirements::{AuditReport, Priority, ResultRecord, TestEnv};

    fn result(id: &str, status: ResultStatus, summary: &str) -> ResultRecord {
        ResultRecord {
            id: id.into(),
            name: id.into(),
            priority: Priority::High,
            status,
            compliance_status: Some(status),
            summary: summary.into(),
            details: vec![],
            completed_at_unix_ms: 1,
            provenance: None,
        }
    }

    fn report(stamp: u64, results: Vec<ResultRecord>) -> AuditReport {
        AuditReport {
            schema_version: "baradwatchu.audit.v1".into(),
            completed_at_unix_ms: stamp,
            results,
            log_file: None,
        }
    }

    #[test]
    fn one_event_per_audit_classified_by_most_serious_aspect() {
        let clean = audit_event(&report(
            1,
            vec![result("REQ-001", ResultStatus::Pass, "ok")],
        ));
        assert_eq!(clean.kind, EventKind::AuditCompleted);
        assert_eq!(clean.severity, Severity::Info);
        assert!(clean.body.contains("non una certificazione"));
        let anomalies = audit_event(&report(
            2,
            vec![
                result("REQ-001", ResultStatus::Fail, "x"),
                result("REQ-002", ResultStatus::Warn, "y"),
            ],
        ));
        assert_eq!(anomalies.kind, EventKind::AuditAnomalies);
        let error = audit_event(&report(
            3,
            vec![
                result("REQ-001", ResultStatus::Fail, "x"),
                result("REQ-003", ResultStatus::Error, "timeout"),
            ],
        ));
        assert_eq!(error.kind, EventKind::AuditError);
        let integrity = audit_event(&report(
            4,
            vec![
                result("REQ-003", ResultStatus::Error, "timeout"),
                result("CUSTOM-001", ResultStatus::Error, INTEGRITY_GATE_SUMMARY),
            ],
        ));
        assert_eq!(integrity.kind, EventKind::IntegrityIssue);
        assert_eq!(integrity.severity, Severity::Critical);
        assert!(integrity.body.contains("CUSTOM-001"));
    }

    #[test]
    fn repeated_anomalies_are_marked_and_log_is_bounded() {
        let _env = TestEnv::new("events-log");
        let failing = report(10, vec![result("REQ-001", ResultStatus::Fail, "x")]);
        let first = record_audit(&failing).unwrap();
        let second = record_audit(&failing).unwrap();
        assert!(!first.repeated);
        assert!(
            second.repeated,
            "same anomaly set must be flagged as repeated"
        );
        assert!(second.id > first.id);
        let different = report(11, vec![result("REQ-002", ResultStatus::Fail, "x")]);
        assert!(!record_audit(&different).unwrap().repeated);
        for _ in 0..(KEEP_EVENTS + 5) {
            record_audit(&failing).unwrap();
        }
        let events = read_events().unwrap();
        assert_eq!(events.len(), KEEP_EVENTS);
        assert!(events.windows(2).all(|pair| pair[0].id < pair[1].id));
    }

    #[test]
    fn snapshot_returns_only_events_after_cursor() {
        let _env = TestEnv::new("events-snapshot");
        let first = record_audit(&report(1, vec![])).unwrap();
        let value: serde_json::Value = serde_json::from_str(&snapshot_json(None).unwrap()).unwrap();
        assert_eq!(value["latestEventId"], first.id);
        assert_eq!(value["events"].as_array().unwrap().len(), 0);
        assert_eq!(value["preferences"]["enabled"], true);
        let second = record_audit(&report(2, vec![])).unwrap();
        let value: serde_json::Value =
            serde_json::from_str(&snapshot_json(Some(first.id)).unwrap()).unwrap();
        let events = value["events"].as_array().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0]["id"], second.id);
    }

    #[test]
    fn preferences_round_trip_and_reject_unknown_fields() {
        let _env = TestEnv::new("events-preferences");
        assert_eq!(
            load_preferences().unwrap(),
            NotificationPreferences::default()
        );
        run_notifications(&["set", "informative", "off"].map(OsString::from)).unwrap();
        let preferences = load_preferences().unwrap();
        assert!(preferences.enabled && !preferences.informative);
        assert!(dashboard_update_preferences(r#"{"enabled":false,"informative":true}"#).is_ok());
        assert!(!load_preferences().unwrap().enabled);
        assert!(
            dashboard_update_preferences(r#"{"enabled":true,"informative":true,"x":1}"#).is_err()
        );
        assert!(run_notifications(&["set", "enabled", "maybe"].map(OsString::from)).is_err());
    }
}
