//! Local model of consent requests.
//!
//! Sources: `LOCAL_SIMULATION` (M7, nothing is sent anywhere) and, from Milestone 2,
//! `REMOTE_SERVER`: an audit request from a Server authenticated by mutual TLS and present
//! in the trust store (`remote.rs`). For remote requests `serverId` is the derived
//! `SRV-…` ID, `accountName` the name the user gave the Server at import time, `accountId`
//! its key fingerprint and `declaredDevice` this Client's Device ID. Rules:
//! - consent refers to one identified request (`requestId`) and is never a standing grant;
//! - only an explicit Accept authorizes; Reject, timeout, a closed window or a notification
//!   that was merely shown never authorize anything;
//! - a request past `expiresAtUnixMs` becomes `EXPIRED` and can no longer be accepted.
use crate::events::{self, EventKind, NewEvent, Severity};
use crate::requirements::{self as req, CliError, CliOutput};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    fs, io,
    path::{Path, PathBuf},
};

const SCHEMA: &str = "baradwatchu.consent-request.v1";
const DIR: &str = "consent";
const LOCK: &str = ".consent.lock";
const DEFAULT_TTL_SECONDS: u64 = 120;
const MIN_TTL_SECONDS: u64 = 10;
const MAX_TTL_SECONDS: u64 = 3600;
const KEEP_CLOSED: usize = 50;
const MAX_TEXT: usize = 128;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsentOperation {
    AuditReport,
}

/// Where the request came from. `RemoteServer` is only created by the user agent for a
/// Server whose key it verified against its own trust store.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsentSource {
    LocalSimulation,
    RemoteServer,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ConsentState {
    Pending,
    Accepted,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DecisionChannel {
    /// The tray companion's dedicated consent window.
    ConsentWindow,
    /// Accept/Reject buttons of the tray's desktop notification (Windows toast).
    Notification,
    /// Notifications tab of the local dashboard (session-token authenticated).
    Dashboard,
    Cli,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentRequest {
    pub schema_version: String,
    pub request_id: String,
    pub server_id: String,
    pub account_name: String,
    pub account_id: String,
    pub declared_device: String,
    pub operation: ConsentOperation,
    pub source: ConsentSource,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<crate::remote::Requester>,
    pub created_at_unix_ms: u64,
    pub expires_at_unix_ms: u64,
    pub state: ConsentState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_via: Option<DecisionChannel>,
}

/// Request plus the user-facing wording, so every interface shows the same text.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConsentView {
    #[serde(flatten)]
    pub request: ConsentRequest,
    pub prompt: String,
    pub effect: String,
    pub remaining_seconds: u64,
}

pub struct SimulationParams {
    pub server_id: String,
    pub account_name: String,
    pub account_id: String,
    pub declared_device: String,
    pub ttl_seconds: u64,
}

impl Default for SimulationParams {
    fn default() -> Self {
        Self {
            server_id: "SIM-SERVER-01".into(),
            account_name: "Operatore di prova".into(),
            account_id: "SIM-ACCOUNT-01".into(),
            declared_device: "Dispositivo simulato".into(),
            ttl_seconds: DEFAULT_TTL_SECONDS,
        }
    }
}

fn consent_dir() -> Result<PathBuf, CliError> {
    Ok(req::state_home()?.join(DIR))
}

fn valid_request_id(id: &str) -> bool {
    id.len() == 32 && id.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// Display fields reach a security decision dialog: refuse control and bidi-override
/// characters that could disguise who is asking.
fn clean_text(label: &str, value: &str) -> Result<String, CliError> {
    let value = value.trim();
    let spoofing = |c: char| {
        c.is_control()
            || matches!(c, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}')
    };
    if value.is_empty() || value.chars().count() > MAX_TEXT || value.chars().any(spoofing) {
        return Err(CliError(format!(
            "{label}: testo non valido (1-{MAX_TEXT} caratteri, senza caratteri di controllo)"
        )));
    }
    Ok(value.to_owned())
}

pub(crate) fn random_hex(bytes: usize) -> Result<String, CliError> {
    let mut buffer = vec![0u8; bytes];
    getrandom::fill(&mut buffer)
        .map_err(|_| CliError("Cannot generate a random identifier".into()))?;
    Ok(buffer.iter().map(|b| format!("{b:02x}")).collect())
}

pub fn prompt(request: &ConsentRequest) -> String {
    let language = baradwatchu_messages::configured_language();
    let simulated = request.source == ConsentSource::LocalSimulation;
    let mut text = String::new();
    if simulated {
        text.push_str(baradwatchu_messages::message("consent.simulated", language));
        text.push_str("\n\n");
    }
    let template = if request.source == ConsentSource::RemoteServer {
        if request.requester.is_some() {
            "consent.prompt_remote_operator"
        } else {
            "consent.prompt_remote"
        }
    } else {
        "consent.prompt"
    };
    text.push_str(
        &baradwatchu_messages::message(template, language)
            .replace(
                "{operator}",
                request
                    .requester
                    .as_ref()
                    .map(|r| r.operator_display_name.as_str())
                    .unwrap_or(""),
            )
            .replace(
                "{server_name}",
                request
                    .requester
                    .as_ref()
                    .and_then(|r| r.server_display_name.as_deref())
                    .unwrap_or(&request.account_name),
            )
            .replace("{server}", &request.server_id)
            .replace("{account}", &request.account_name)
            .replace("{account_id}", &request.account_id)
            .replace("{device}", &request.declared_device),
    );
    text.push_str("\n\n");
    text.push_str(baradwatchu_messages::message(
        if simulated {
            "consent.reject_simulated"
        } else {
            "consent.reject"
        },
        language,
    ));
    text.push_str("\n\n");
    text.push_str(
        &baradwatchu_messages::message("consent.request", language)
            .replace("{id}", &request.request_id),
    );
    text
}

fn effect(request: &ConsentRequest) -> String {
    let key = match request.state {
        ConsentState::Pending => "consent.effect.pending",
        ConsentState::Accepted => "consent.effect.accepted",
        ConsentState::Rejected => "consent.effect.rejected",
        ConsentState::Expired => "consent.effect.expired",
    };
    baradwatchu_messages::message(key, baradwatchu_messages::configured_language()).into()
}

fn view(request: ConsentRequest, now: u64) -> ConsentView {
    ConsentView {
        prompt: prompt(&request),
        effect: effect(&request),
        remaining_seconds: if request.state == ConsentState::Pending {
            request.expires_at_unix_ms.saturating_sub(now) / 1000
        } else {
            0
        },
        request,
    }
}

fn read_request(path: &Path) -> Option<ConsentRequest> {
    let metadata = fs::symlink_metadata(path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return None;
    }
    let request: ConsentRequest = serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
    let stem = path.file_stem()?.to_str()?;
    (request.schema_version == SCHEMA
        && valid_request_id(&request.request_id)
        && request.request_id == stem)
        .then_some(request)
}

fn save(dir: &Path, request: &ConsentRequest) -> Result<(), CliError> {
    req::atomic_json(&dir.join(format!("{}.json", request.request_id)), request)
}

fn close_event(request: &ConsentRequest) -> NewEvent {
    let language = baradwatchu_messages::configured_language();
    let (kind, title) = match request.state {
        ConsentState::Accepted => (
            EventKind::ConsentAccepted,
            baradwatchu_messages::message("consent.title.accepted", language),
        ),
        ConsentState::Rejected => (
            EventKind::ConsentRejected,
            baradwatchu_messages::message("consent.title.rejected", language),
        ),
        _ => (
            EventKind::ConsentExpired,
            baradwatchu_messages::message("consent.title.expired", language),
        ),
    };
    NewEvent {
        kind,
        severity: Severity::Info,
        title: title.into(),
        body: baradwatchu_messages::message("consent.event_body", language)
            .replace("{server}", &request.server_id)
            .replace("{account}", &request.account_name)
            .replace("{id}", &request.request_id[..8])
            .replace("{effect}", &effect(request)),
        audit_completed_at_unix_ms: None,
        request_id: Some(request.request_id.clone()),
        fingerprint: None,
    }
}

/// Loads every request under the lock, expiring overdue ones (persisted, with an event)
/// and pruning old closed requests. Newest first.
fn load_all(dir: &Path) -> Result<Vec<ConsentRequest>, CliError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(vec![]),
        Err(_) => return Err(CliError("Cannot read consent requests".into())),
    };
    let now = req::now_ms();
    let mut requests = vec![];
    for path in entries.filter_map(Result::ok).map(|entry| entry.path()) {
        if path.extension().map_or(true, |ext| ext != "json") {
            continue;
        }
        let Some(mut request) = read_request(&path) else {
            continue;
        };
        if request.state == ConsentState::Pending && now >= request.expires_at_unix_ms {
            request.state = ConsentState::Expired;
            request.decided_at_unix_ms = Some(now);
            save(dir, &request)?;
            let _ = events::append_event(close_event(&request));
        }
        requests.push(request);
    }
    requests.sort_by_key(|request| std::cmp::Reverse(request.created_at_unix_ms));
    let mut closed = 0;
    requests.retain(|request| {
        if request.state == ConsentState::Pending {
            return true;
        }
        closed += 1;
        if closed <= KEEP_CLOSED {
            return true;
        }
        let _ = fs::remove_file(dir.join(format!("{}.json", request.request_id)));
        false
    });
    Ok(requests)
}

fn locked<T>(task: impl FnOnce(&Path) -> Result<T, CliError>) -> Result<T, CliError> {
    let dir = consent_dir()?;
    let _lock = events::lock_dir(&dir, LOCK)?;
    task(&dir)
}

pub fn all_views() -> Result<Vec<ConsentView>, CliError> {
    let now = req::now_ms();
    locked(|dir| Ok(load_all(dir)?.into_iter().map(|r| view(r, now)).collect()))
}

pub fn pending_views() -> Result<Vec<ConsentView>, CliError> {
    Ok(all_views()?
        .into_iter()
        .filter(|v| v.request.state == ConsentState::Pending)
        .collect())
}

pub fn create_simulated(params: SimulationParams) -> Result<ConsentView, CliError> {
    let language = baradwatchu_messages::configured_language();
    if !(MIN_TTL_SECONDS..=MAX_TTL_SECONDS).contains(&params.ttl_seconds) {
        return Err(CliError(format!(
            "La scadenza deve essere tra {MIN_TTL_SECONDS} e {MAX_TTL_SECONDS} secondi"
        )));
    }
    let now = req::now_ms();
    let request = ConsentRequest {
        schema_version: SCHEMA.into(),
        request_id: random_hex(16)?,
        server_id: clean_text("Server", &params.server_id)?,
        account_name: clean_text("Account", &params.account_name)?,
        account_id: clean_text("ID account", &params.account_id)?,
        declared_device: clean_text("Dispositivo", &params.declared_device)?,
        operation: ConsentOperation::AuditReport,
        source: ConsentSource::LocalSimulation,
        requester: None,
        created_at_unix_ms: now,
        expires_at_unix_ms: now + params.ttl_seconds * 1000,
        state: ConsentState::Pending,
        decided_at_unix_ms: None,
        decided_via: None,
    };
    locked(|dir| save(dir, &request))?;
    let _ = events::append_event(NewEvent {
        kind: EventKind::ConsentRequested,
        severity: Severity::Action,
        title: baradwatchu_messages::message("consent.simulated_title", language).into(),
        body: baradwatchu_messages::message("consent.simulated_body", language)
            .replace("{server}", &request.server_id)
            .replace("{account}", &request.account_name)
            .replace("{seconds}", &params.ttl_seconds.to_string()),
        audit_completed_at_unix_ms: None,
        request_id: Some(request.request_id.clone()),
        fingerprint: None,
    });
    Ok(view(request, now))
}

/// Records an explicit decision for exactly one pending, unexpired request.
pub fn decide(id: &str, accept: bool, via: DecisionChannel) -> Result<ConsentView, CliError> {
    if !valid_request_id(id) {
        return Err(CliError("Identificativo di richiesta non valido".into()));
    }
    let request = locked(|dir| {
        // load_all expires overdue requests first, so a late Accept is refused below.
        let mut request = load_all(dir)?
            .into_iter()
            .find(|r| r.request_id == id)
            .ok_or_else(|| CliError("Richiesta di consenso non trovata".into()))?;
        match request.state {
            ConsentState::Pending => {}
            ConsentState::Expired => {
                return Err(CliError(
                    "Richiesta scaduta: nessuna autorizzazione è stata concessa".into(),
                ))
            }
            _ => return Err(CliError("Richiesta già decisa".into())),
        }
        request.state = if accept {
            ConsentState::Accepted
        } else {
            ConsentState::Rejected
        };
        request.decided_at_unix_ms = Some(req::now_ms());
        request.decided_via = Some(via);
        save(dir, &request)?;
        Ok(request)
    })?;
    let _ = events::append_event(close_event(&request));
    Ok(view(request, req::now_ms()))
}

/// Expires every pending request (identity reset): no request presented before the reset
/// can still be accepted. Returns how many requests were closed.
pub(crate) fn expire_pending() -> Result<usize, CliError> {
    expire_where(|_| true)
}

/// Revocation (`Some(server ID)`) or `trust clear` (`None`): pending remote requests of
/// the affected Servers can no longer be accepted.
pub(crate) fn expire_remote_pending(server_id: Option<&str>) -> Result<usize, CliError> {
    expire_where(|request| {
        request.source == ConsentSource::RemoteServer
            && server_id.map_or(true, |id| request.server_id.eq_ignore_ascii_case(id))
    })
}

/// Withdraws one pending request (remote request abandoned: service gone, Server revoked).
pub(crate) fn expire_request(id: &str) -> Result<usize, CliError> {
    expire_where(|request| request.request_id == id)
}

/// Current state of one request (overdue requests are expired first). None if unknown.
pub(crate) fn state_of(id: &str) -> Result<Option<ConsentState>, CliError> {
    locked(|dir| {
        Ok(load_all(dir)?
            .into_iter()
            .find(|request| request.request_id == id)
            .map(|request| request.state))
    })
}

/// Milestone 2: consent request for an audit asked by a verified, trusted Server. The
/// 120-second timer starts now, when the request becomes visible to the user.
pub(crate) fn create_remote(
    server: &crate::identity::TrustedServer,
    device_id: &str,
    requester: Option<&crate::remote::Requester>,
) -> Result<ConsentView, CliError> {
    if requester.is_some_and(|r| !r.valid()) {
        return Err(CliError("Invalid requester metadata".into()));
    }
    let language = baradwatchu_messages::configured_language();
    let now = req::now_ms();
    let request = ConsentRequest {
        schema_version: SCHEMA.into(),
        request_id: random_hex(16)?,
        server_id: clean_text("Server", &server.server_id)?,
        account_name: clean_text("Server", &server.name)?,
        account_id: clean_text("Fingerprint", &server.fingerprint)?,
        declared_device: clean_text("Device", device_id)?,
        operation: ConsentOperation::AuditReport,
        source: ConsentSource::RemoteServer,
        requester: requester.cloned(),
        created_at_unix_ms: now,
        expires_at_unix_ms: now + DEFAULT_TTL_SECONDS * 1000,
        state: ConsentState::Pending,
        decided_at_unix_ms: None,
        decided_via: None,
    };
    locked(|dir| save(dir, &request))?;
    let _ = events::append_event(NewEvent {
        kind: EventKind::ConsentRequested,
        severity: Severity::Action,
        title: baradwatchu_messages::message("consent.remote_title", language).into(),
        body: baradwatchu_messages::message("consent.remote_body", language)
            .replace("{server}", &request.server_id)
            .replace("{account}", &request.account_name)
            .replace("{seconds}", &DEFAULT_TTL_SECONDS.to_string()),
        audit_completed_at_unix_ms: None,
        request_id: Some(request.request_id.clone()),
        fingerprint: None,
    });
    Ok(view(request, now))
}

fn expire_where(matches: impl Fn(&ConsentRequest) -> bool) -> Result<usize, CliError> {
    let closed = locked(|dir| {
        let now = req::now_ms();
        let mut closed = vec![];
        for mut request in load_all(dir)? {
            if request.state == ConsentState::Pending && matches(&request) {
                request.state = ConsentState::Expired;
                request.decided_at_unix_ms = Some(now);
                save(dir, &request)?;
                closed.push(request);
            }
        }
        Ok(closed)
    })?;
    for request in &closed {
        let _ = events::append_event(close_event(request));
    }
    Ok(closed.len())
}

pub(crate) fn dashboard_simulate(text: &str) -> Result<String, CliError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Body {
        ttl_seconds: Option<u64>,
    }
    let body: Body = serde_json::from_str(if text.trim().is_empty() { "{}" } else { text })
        .map_err(|_| CliError("Richiesta di simulazione non valida".into()))?;
    let mut params = SimulationParams::default();
    if let Some(ttl) = body.ttl_seconds {
        params.ttl_seconds = ttl;
    }
    create_simulated(params)?;
    events::dashboard_notifications_json()
}

/// Explicit Accept/Reject of one pending request from the dashboard's Notifications tab.
/// Body exactly `{"requestId": "<32 hex>", "accept": true|false}`; the same single-use,
/// unexpired-request rules as every other channel apply.
pub(crate) fn dashboard_decide(text: &str) -> Result<String, CliError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Body {
        request_id: String,
        accept: bool,
    }
    let body: Body = serde_json::from_str(text)
        .map_err(|_| CliError("Richiesta di decisione non valida".into()))?;
    decide(&body.request_id, body.accept, DecisionChannel::Dashboard)?;
    events::dashboard_notifications_json()
}

fn usage() -> &'static str {
    baradwatchu_messages::message("consent.usage", baradwatchu_messages::configured_language())
}

fn human(view: &ConsentView) -> String {
    let language = baradwatchu_messages::configured_language();
    let state = baradwatchu_messages::message(
        match view.request.state {
            ConsentState::Pending => "consent.state.pending",
            ConsentState::Accepted => "consent.state.accepted",
            ConsentState::Rejected => "consent.state.rejected",
            ConsentState::Expired => "consent.state.expired",
        },
        language,
    );
    let expires = if view.request.state == ConsentState::Pending {
        baradwatchu_messages::message("consent.cli_expires", language)
            .replace("{seconds}", &view.remaining_seconds.to_string())
    } else {
        String::new()
    };
    baradwatchu_messages::message("consent.cli_row", language)
        .replace("{id}", &view.request.request_id)
        .replace("{state}", state)
        .replace("{server}", &view.request.server_id)
        .replace("{account}", &view.request.account_name)
        .replace("{account_id}", &view.request.account_id)
        .replace("{device}", &view.request.declared_device)
        .replace("{expires}", &expires)
}

pub fn run(args: &[OsString]) -> Result<CliOutput, CliError> {
    let text = |value: &OsString| {
        value
            .to_str()
            .map(str::to_owned)
            .ok_or_else(|| CliError(usage().into()))
    };
    match args {
        [command, options @ ..] if command == "simulate" => {
            let mut params = SimulationParams::default();
            let mut seen = Vec::new();
            for pair in options.chunks(2) {
                let [key, value] = pair else {
                    return Err(CliError(usage().into()));
                };
                let key = text(key)?;
                if seen.contains(&key) {
                    return Err(CliError(usage().into()));
                }
                let value = text(value)?;
                match key.as_str() {
                    "--server" => params.server_id = value,
                    "--account" => params.account_name = value,
                    "--account-id" => params.account_id = value,
                    "--device" => params.declared_device = value,
                    "--ttl" => {
                        params.ttl_seconds = value.parse().map_err(|_| CliError(usage().into()))?
                    }
                    _ => return Err(CliError(usage().into())),
                }
                seen.push(key);
            }
            let view = create_simulated(params)?;
            let language = baradwatchu_messages::configured_language();
            Ok(CliOutput {
                text: baradwatchu_messages::message("consent.simulate.created", language)
                    .replace("{id}", &view.request.request_id)
                    .replace("{seconds}", &view.remaining_seconds.to_string())
                    + "\n",
                code: 0,
            })
        }
        [command] if command == "list" => {
            let views = all_views()?;
            let text = if views.is_empty() {
                format!(
                    "{}\n",
                    baradwatchu_messages::message(
                        "consent.none",
                        baradwatchu_messages::configured_language()
                    )
                )
            } else {
                views.iter().map(human).collect()
            };
            Ok(CliOutput { text, code: 0 })
        }
        [command, flag] if command == "list" && flag == "--json" => Ok(CliOutput {
            text: req::output_json(&all_views()?)?,
            code: 0,
        }),
        [command, id, via @ ..] if command == "accept" || command == "reject" => {
            let channel = match via {
                [] => DecisionChannel::Cli,
                [flag, value] if flag == "--via" && value == "window" => {
                    DecisionChannel::ConsentWindow
                }
                [flag, value] if flag == "--via" && value == "notification" => {
                    DecisionChannel::Notification
                }
                _ => return Err(CliError(usage().into())),
            };
            let view = decide(&text(id)?, command == "accept", channel)?;
            Ok(CliOutput {
                text: format!("{}\n", view.effect),
                code: 0,
            })
        }
        _ => Err(CliError(usage().into())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::requirements::TestEnv;

    fn simulate(ttl: u64) -> ConsentView {
        create_simulated(SimulationParams {
            ttl_seconds: ttl,
            ..SimulationParams::default()
        })
        .unwrap()
    }

    #[test]
    fn simulated_request_carries_identity_operation_and_expiry() {
        let _env = TestEnv::new("consent-model");
        let view = simulate(60);
        let request = &view.request;
        assert!(valid_request_id(&request.request_id));
        assert_eq!(request.operation, ConsentOperation::AuditReport);
        assert_eq!(request.source, ConsentSource::LocalSimulation);
        assert_eq!(request.state, ConsentState::Pending);
        assert_eq!(
            request.expires_at_unix_ms - request.created_at_unix_ms,
            60_000
        );
        assert!(view.prompt.contains("SIM-SERVER-01"));
        assert!(view.prompt.contains("Vuoi autorizzare questa richiesta?"));
        assert!(view.prompt.contains("SIMULAZIONE"));
        assert_eq!(pending_views().unwrap().len(), 1);
        let events = events::read_events().unwrap();
        assert_eq!(events.last().unwrap().kind, EventKind::ConsentRequested);
        assert_eq!(events.last().unwrap().severity, Severity::Action);
    }

    fn remote_server(id: &str) -> crate::identity::TrustedServer {
        crate::identity::TrustedServer {
            server_id: id.into(),
            name: "Server Test".into(),
            algorithm: "Ed25519".into(),
            public_key: "AAAA".into(),
            fingerprint: format!("SHA256:{}", "a".repeat(64)),
            imported_at_unix_ms: 1,
            status: crate::identity::TrustStatus::Trusted,
            revoked_at_unix_ms: None,
        }
    }

    #[test]
    fn remote_requests_last_120_seconds_and_name_the_server() {
        let _env = TestEnv::new("consent-remote");
        let view = create_remote(&remote_server("SRV-AAAA-BBBB-CCCC-DDDD"), "BWU-1", None).unwrap();
        let request = &view.request;
        assert_eq!(request.source, ConsentSource::RemoteServer);
        assert_eq!(
            request.expires_at_unix_ms - request.created_at_unix_ms,
            120_000
        );
        assert!(
            view.prompt.contains("Server Test") && view.prompt.contains("SRV-AAAA-BBBB-CCCC-DDDD")
        );
        assert!(view.prompt.contains(&"a".repeat(64)) && !view.prompt.contains("SIMULAZIONE"));
        // Revoking another Server leaves it; revoking this one withdraws it.
        assert_eq!(expire_remote_pending(Some("SRV-OTHER")).unwrap(), 0);
        let simulated = simulate(60);
        assert_eq!(
            expire_remote_pending(Some("srv-aaaa-bbbb-cccc-dddd")).unwrap(),
            1
        );
        assert_eq!(
            state_of(&request.request_id).unwrap(),
            Some(ConsentState::Expired)
        );
        assert!(decide(&request.request_id, true, DecisionChannel::ConsentWindow).is_err());
        // Simulations are not remote requests.
        assert_eq!(expire_remote_pending(None).unwrap(), 0);
        assert_eq!(
            state_of(&simulated.request.request_id).unwrap(),
            Some(ConsentState::Pending)
        );
        assert_eq!(expire_request(&simulated.request.request_id).unwrap(), 1);
        assert_eq!(state_of("0".repeat(32).as_str()).unwrap(), None);
    }

    #[test]
    fn accept_and_reject_apply_once_to_one_request() {
        let _env = TestEnv::new("consent-decide");
        let first = simulate(60).request.request_id;
        let second = simulate(60).request.request_id;
        let accepted = decide(&first, true, DecisionChannel::ConsentWindow).unwrap();
        assert_eq!(accepted.request.state, ConsentState::Accepted);
        assert_eq!(
            accepted.request.decided_via,
            Some(DecisionChannel::ConsentWindow)
        );
        // Accepting one request does not touch any other request.
        let pending = pending_views().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request.request_id, second);
        assert!(
            decide(&first, false, DecisionChannel::Cli).is_err(),
            "no second decision"
        );
        let rejected = decide(&second, false, DecisionChannel::Cli).unwrap();
        assert_eq!(rejected.request.state, ConsentState::Rejected);
        assert!(pending_views().unwrap().is_empty());
    }

    #[test]
    fn timeout_never_authorizes_and_late_accept_is_refused() {
        let _env = TestEnv::new("consent-timeout");
        let id = simulate(10).request.request_id;
        // Age the stored request past its deadline instead of sleeping.
        let dir = consent_dir().unwrap();
        let path = dir.join(format!("{id}.json"));
        let mut request = read_request(&path).unwrap();
        request.expires_at_unix_ms = req::now_ms() - 1;
        save(&dir, &request).unwrap();
        let error = decide(&id, true, DecisionChannel::ConsentWindow).unwrap_err();
        assert!(error.0.contains("scaduta"));
        let all = all_views().unwrap();
        assert_eq!(all[0].request.state, ConsentState::Expired);
        assert!(all[0].effect.contains("nessuna autorizzazione"));
        assert!(events::read_events()
            .unwrap()
            .iter()
            .any(|e| e.kind == EventKind::ConsentExpired));
    }

    #[test]
    fn nothing_is_authorized_without_an_explicit_accept() {
        let _env = TestEnv::new("consent-no-auto");
        simulate(60);
        simulate(60);
        // Reading, listing and snapshotting (what the tray and dashboard do) never decide.
        for _ in 0..3 {
            all_views().unwrap();
            events::snapshot_json(Some(0)).unwrap();
            events::dashboard_notifications_json().unwrap();
        }
        assert!(all_views()
            .unwrap()
            .iter()
            .all(|v| v.request.state == ConsentState::Pending));
    }

    #[test]
    fn rejects_bad_input() {
        let _env = TestEnv::new("consent-input");
        assert!(create_simulated(SimulationParams {
            ttl_seconds: 5,
            ..SimulationParams::default()
        })
        .is_err());
        assert!(create_simulated(SimulationParams {
            server_id: "evil\u{202e}gro".into(),
            ..SimulationParams::default()
        })
        .is_err());
        assert!(decide("../../etc/passwd", true, DecisionChannel::Cli).is_err());
        assert!(run(&["simulate", "--ttl"].map(OsString::from)).is_err());
        assert!(run(&["accept", "0123", "--via", "dashboard"].map(OsString::from)).is_err());
        assert!(dashboard_simulate(r#"{"ttlSeconds":30,"accept":true}"#).is_err());
    }

    #[test]
    fn dashboard_and_notification_decide_exactly_one_request() {
        let _env = TestEnv::new("consent-dashboard");
        let first = simulate(60).request.request_id;
        let second = simulate(60).request.request_id;
        // Only the exact body is accepted; nothing is decided by a malformed one.
        for bad in [
            "{}",
            r#"{"requestId":"x","accept":true}"#,
            &format!(r#"{{"requestId":"{first}","accept":"yes"}}"#),
            &format!(r#"{{"requestId":"{first}","accept":true,"all":true}}"#),
        ] {
            assert!(dashboard_decide(bad).is_err(), "{bad}");
        }
        assert_eq!(pending_views().unwrap().len(), 2);
        dashboard_decide(&format!(r#"{{"requestId":"{first}","accept":true}}"#)).unwrap();
        let views = all_views().unwrap();
        let decided = views
            .iter()
            .find(|v| v.request.request_id == first)
            .unwrap();
        assert_eq!(decided.request.state, ConsentState::Accepted);
        assert_eq!(
            decided.request.decided_via,
            Some(DecisionChannel::Dashboard)
        );
        // Already decided: a second click (dashboard or notification) changes nothing.
        assert!(dashboard_decide(&format!(r#"{{"requestId":"{first}","accept":false}}"#)).is_err());
        let rejected =
            run(&["reject", second.as_str(), "--via", "notification"].map(OsString::from)).unwrap();
        assert_eq!(rejected.code, 0);
        let views = all_views().unwrap();
        let second_view = views
            .iter()
            .find(|v| v.request.request_id == second)
            .unwrap();
        assert_eq!(second_view.request.state, ConsentState::Rejected);
        assert_eq!(
            second_view.request.decided_via,
            Some(DecisionChannel::Notification)
        );
    }
}
