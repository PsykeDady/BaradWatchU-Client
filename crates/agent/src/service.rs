//! Milestone 2 system service (`baradwatchu-agent service run`): always-on component that
//! opens mutual TLS connections for registered users and relays authorized requests to their
//! agent. It never runs an audit, never writes in a user's folders, never chooses a user:
//! - a user *registers* their own identity folder over the local IPC (the OS tells the
//!   service who they are; every file must belong to them);
//! - the service connects to each enabled trusted Server with that user's Ed25519 key;
//! - requests are relayed to the user's linked agent (`remote link`, started by the tray);
//!   with no linked agent the answer is `UNAVAILABLE`, while busy it is `BUSY`.
//!
//! Data (`BARADWATCHU_SERVICE_DIR` or the platform default, system-only):
//! `users/<principal>.json`
//! (registrations), `requests/<job>.json` (request records without results, for duplicate
//! and replay detection across restarts). Results stay in memory only.
use crate::identity::{self, TrustedServer};
use crate::ipc::{
    self, Intent, JobServer, JobState, Principal, ServerConnectionStatus, ServiceStatus, ToAgent,
    ToService,
};
use crate::remote::{self, AuditRequest, AuditResult, RequestStatus};
use crate::requirements::{self as req, CliError, CliOutput};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::{self, Read, Write},
    net::{Shutdown, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::{Duration, Instant},
};

const REGISTRATION_SCHEMA: &str = "baradwatchu.service-registration.v1";
const RECORD_SCHEMA: &str = "baradwatchu.remote-request-record.v1";
/// Request records (duplicate and replay protection) outlive the accepted clock skew.
const RETENTION_MS: u64 = 24 * 3600 * 1000;
const RESULT_RETENTION_MS: u64 = 3600 * 1000;
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(15);
const CONSENT_GRACE_MS: u64 = 15_000;
const RUN_LIMIT_MS: u64 = 35 * 60 * 1000;
const PING_EVERY: Duration = Duration::from_secs(3);
const MAX_RESULT: usize = 8 * 1024 * 1024;
const TUNNEL_SCHEMA: &str = "baradwatchu.tunnel.v1";
const MAX_TUNNEL_FRAME: usize = 9 * 1024 * 1024;
#[cfg(windows)]
pub(crate) const WINDOWS_SERVICE_NAME: &str = "BaradWatchU";

// ---------------------------------------------------------------------------------------
// Persistent data
// ---------------------------------------------------------------------------------------

pub(crate) fn service_dir() -> PathBuf {
    if let Some(dir) = std::env::var_os("BARADWATCHU_SERVICE_DIR").filter(|v| !v.is_empty()) {
        return dir.into();
    }
    if cfg!(windows) {
        let base = std::env::var_os("ProgramData").unwrap_or_else(|| r"C:\ProgramData".into());
        PathBuf::from(base).join("BaradWatchU").join("service")
    } else if cfg!(target_os = "macos") {
        "/Library/Application Support/BaradWatchU/service".into()
    } else {
        "/var/lib/baradwatchu".into()
    }
}

fn private_dir(path: &Path) -> Result<(), CliError> {
    req::ensure_private_dir(path)?;
    #[cfg(windows)]
    identity::windows_acl::restrict_to_system(path)?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Registration {
    schema_version: String,
    principal: Principal,
    device_id: String,
    #[serde(default)]
    name: String,
    identity_dir: String,
    registered_at_unix_ms: u64,
    #[serde(default)]
    connections: Vec<ConnectionConfig>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ConnectionConfig {
    server_id: String,
    endpoint: String,
    enabled: bool,
    generation: u64,
}

#[derive(Clone, Debug)]
struct ConnectionRuntime {
    generation: u64,
    connected: bool,
    error: Option<String>,
    socket: Option<Arc<TcpStream>>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct TunnelRequest {
    schema_version: String,
    sequence: u64,
    method: String,
    path: String,
    body: Option<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct TunnelReply {
    schema_version: &'static str,
    sequence: u64,
    code: u16,
    body: serde_json::Value,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Record {
    schema_version: String,
    job_id: String,
    request_id: String,
    server_id: String,
    server_key: String,
    principal: Principal,
    device_id: String,
    state: JobState,
    created_at_unix_ms: u64,
    updated_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consent_expires_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    running_since_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason: Option<String>,
}

struct Job {
    record: Record,
    /// The user agent has answered the dispatch (until then the request is not public).
    answered: bool,
    result: Option<Arc<Vec<u8>>>,
}

impl Job {
    fn active(&self) -> bool {
        !self.answered || !self.record.state.is_terminal()
    }
}

struct Link {
    writer: ipc::Stream,
    serial: u64,
}

struct Shared {
    dir: PathBuf,
    registrations: Mutex<Vec<Registration>>,
    links: Mutex<HashMap<Principal, Link>>,
    jobs: Mutex<HashMap<String, Job>>,
    changed: Condvar,
    connections: Mutex<HashMap<String, ConnectionRuntime>>,
    serial: AtomicUsize,
}

impl std::fmt::Debug for Shared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Shared").finish_non_exhaustive()
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl Shared {
    fn users_dir(&self) -> PathBuf {
        self.dir.join("users")
    }

    fn requests_dir(&self) -> PathBuf {
        self.dir.join("requests")
    }

    fn persist(&self, record: &Record) {
        let _ = req::atomic_json(
            &self.requests_dir().join(format!("{}.json", record.job_id)),
            record,
        );
    }

    fn load(dir: PathBuf) -> Result<Arc<Self>, CliError> {
        private_dir(&dir)?;
        let shared = Self {
            dir,
            registrations: Mutex::new(vec![]),
            links: Mutex::new(HashMap::new()),
            jobs: Mutex::new(HashMap::new()),
            changed: Condvar::new(),
            connections: Mutex::new(HashMap::new()),
            serial: AtomicUsize::new(1),
        };
        private_dir(&shared.users_dir())?;
        private_dir(&shared.requests_dir())?;
        let mut registrations = vec![];
        for path in json_files(&shared.users_dir()) {
            let parsed = fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Registration>(&bytes).ok());
            match parsed {
                Some(r) if r.schema_version == REGISTRATION_SCHEMA => registrations.push(r),
                _ => {}
            }
        }
        *lock(&shared.registrations) = registrations;
        let now = req::now_ms();
        let mut jobs = HashMap::new();
        for path in json_files(&shared.requests_dir()) {
            let Some(mut record) = fs::read(&path)
                .ok()
                .and_then(|bytes| serde_json::from_slice::<Record>(&bytes).ok())
                .filter(|r| r.schema_version == RECORD_SCHEMA)
            else {
                let _ = fs::remove_file(&path);
                continue;
            };
            if now.saturating_sub(record.created_at_unix_ms) > RETENTION_MS {
                let _ = fs::remove_file(&path);
                continue;
            }
            if !record.state.is_terminal() {
                // Nobody follows it any more: never resumed, never executed later.
                record.state = JobState::Failed;
                record.reason = Some("SERVICE_RESTARTED".into());
                record.updated_at_unix_ms = now;
                shared.persist(&record);
            }
            jobs.insert(
                record.job_id.clone(),
                Job {
                    record,
                    answered: true,
                    result: None,
                },
            );
        }
        *lock(&shared.jobs) = jobs;
        Ok(Arc::new(shared))
    }

    fn status_for(&self, principal: &Principal) -> ServiceStatus {
        // One lock at a time (create_request holds jobs → links): no nested guards here.
        let registration = lock(&self.registrations)
            .iter()
            .find(|r| &r.principal == principal)
            .cloned();
        let registration_problem = registration.as_ref().and_then(|r| {
            match identity::load_for_service(Path::new(&r.identity_dir), principal) {
                Ok(identity) if identity.device_id == r.device_id => None,
                Ok(_) => {
                    Some("The registered identity was replaced: run remote enable again".into())
                }
                Err(problem) => Some(problem),
            }
        });
        let session_linked = lock(&self.links).contains_key(principal);
        let request_in_progress = lock(&self.jobs)
            .values()
            .any(|job| &job.record.principal == principal && job.active());
        ServiceStatus {
            version: env!("CARGO_PKG_VERSION").into(),
            registered: registration.is_some(),
            registered_device_id: registration.as_ref().map(|r| r.device_id.clone()),
            registration_problem,
            session_linked,
            request_in_progress,
            connections: registration.as_ref().map_or_else(Vec::new, |registration| {
                registration
                    .connections
                    .iter()
                    .map(|config| {
                        let runtime = lock(&self.connections)
                            .get(&connection_key(principal, &config.server_id))
                            .cloned();
                        ServerConnectionStatus {
                            server_id: config.server_id.clone(),
                            endpoint: config.endpoint.clone(),
                            enabled: config.enabled,
                            connected: runtime.as_ref().is_some_and(|runtime| {
                                runtime.generation == config.generation && runtime.connected
                            }),
                            error: runtime
                                .filter(|runtime| runtime.generation == config.generation)
                                .and_then(|runtime| runtime.error),
                        }
                    })
                    .collect()
            }),
        }
    }
}

fn json_files(dir: &Path) -> Vec<PathBuf> {
    fs::read_dir(dir)
        .map(|entries| {
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
                .collect()
        })
        .unwrap_or_default()
}

fn connection_key(principal: &Principal, server_id: &str) -> String {
    format!("{}:{server_id}", principal.0)
}

fn valid_server_endpoint(endpoint: &str) -> bool {
    if endpoint.len() > 300
        || endpoint
            .bytes()
            .any(|b| b.is_ascii_whitespace() || b == b'/' || b == b'@')
    {
        return false;
    }
    let Some((host, port)) = endpoint.rsplit_once(':') else {
        return false;
    };
    let valid_host = if host.starts_with('[') && host.ends_with(']') {
        host[1..host.len() - 1]
            .parse::<std::net::Ipv6Addr>()
            .is_ok()
    } else {
        !host.is_empty()
            && host.len() <= 253
            && host
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
    };
    valid_host && port.parse::<u16>().is_ok_and(|port| port != 0)
}

fn connection_action(
    shared: &Shared,
    peer: &Principal,
    server_id: Option<String>,
    endpoint: Option<String>,
    action: Option<String>,
) -> ToAgent {
    let Some(server_id) = server_id else {
        return ToAgent::error("Server ID required");
    };
    let Some(action) = action else {
        return ToAgent::error("Connection action required");
    };
    if !matches!(action.as_str(), "start" | "stop" | "refresh") {
        return ToAgent::error("Invalid connection action");
    }
    let Some(stem) = peer.file_stem() else {
        return ToAgent::error("Unsupported local account");
    };
    let mut registrations = lock(&shared.registrations);
    let Some(registration) = registrations.iter_mut().find(|r| &r.principal == peer) else {
        return ToAgent::error("Remote requests are not enabled for this account");
    };
    let identity = match identity::load_for_service(Path::new(&registration.identity_dir), peer) {
        Ok(identity) if identity.device_id == registration.device_id => identity,
        _ => return ToAgent::error("Registered identity unavailable"),
    };
    if !identity.servers.iter().any(|server| {
        server.server_id == server_id && server.status == identity::TrustStatus::Trusted
    }) {
        return ToAgent::error("Server is not trusted");
    }
    let found = registration
        .connections
        .iter()
        .position(|config| config.server_id == server_id);
    let selected_endpoint =
        endpoint.or_else(|| found.map(|index| registration.connections[index].endpoint.clone()));
    if action != "stop"
        && !selected_endpoint
            .as_deref()
            .is_some_and(valid_server_endpoint)
    {
        return ToAgent::error("Provide Server DNS or IP and port");
    }
    let Some(endpoint) = selected_endpoint else {
        return ToAgent::error("Connection not configured");
    };
    if !valid_server_endpoint(&endpoint) {
        return ToAgent::error("Invalid Server DNS or IP and port");
    }
    let previous = registration.connections.clone();
    let previous_generation = found.map(|index| registration.connections[index].generation);
    let runtime_key = connection_key(peer, &server_id);
    let previous_socket = previous_generation.and_then(|generation| {
        lock(&shared.connections)
            .get(&runtime_key)
            .filter(|state| state.generation == generation)
            .and_then(|state| state.socket.clone())
    });
    match found {
        Some(index) => {
            let config = &mut registration.connections[index];
            config.endpoint = endpoint;
            config.enabled = action != "stop";
            config.generation = config.generation.wrapping_add(1);
        }
        None => registration.connections.push(ConnectionConfig {
            server_id,
            endpoint,
            enabled: action != "stop",
            generation: 1,
        }),
    }
    if req::atomic_json(
        &shared.users_dir().join(format!("{stem}.json")),
        registration,
    )
    .is_err()
    {
        registration.connections = previous;
        return ToAgent::error("Cannot save Server connection");
    }
    if let Some(socket) = previous_socket {
        let _ = socket.shutdown(Shutdown::Both);
    }
    drop(registrations);
    ToAgent::ok(Some(shared.status_for(peer)))
}

// ---------------------------------------------------------------------------------------
// Local IPC
// ---------------------------------------------------------------------------------------

fn register(
    shared: &Shared,
    peer: &Principal,
    identity_dir: Option<String>,
    client_name: Option<String>,
) -> ToAgent {
    let Some(stem) = peer.file_stem() else {
        return ToAgent::error("Unsupported local account");
    };
    let Some(dir) = identity_dir.map(PathBuf::from).filter(|d| d.is_absolute()) else {
        return ToAgent::error("Identity folder must be an absolute path");
    };
    let identity = match identity::load_for_service(&dir, peer) {
        Ok(identity) => identity,
        Err(problem) => return ToAgent::error(&problem),
    };
    let registration = Registration {
        schema_version: REGISTRATION_SCHEMA.into(),
        principal: peer.clone(),
        device_id: identity.device_id.clone(),
        name: client_name
            .filter(|name| {
                !name.is_empty() && name.len() <= 128 && !name.chars().any(|ch| ch.is_control() || matches!(ch, '\u{200e}' | '\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2066}'..='\u{2069}'))
            })
            .unwrap_or_else(|| identity.device_id.clone()),
        identity_dir: dir.to_string_lossy().into_owned(),
        registered_at_unix_ms: req::now_ms(),
        connections: lock(&shared.registrations)
            .iter()
            .find(|r| &r.principal == peer && r.device_id == identity.device_id)
            .map_or_else(Vec::new, |r| r.connections.clone()),
    };
    {
        let mut registrations = lock(&shared.registrations);
        if registrations
            .iter()
            .any(|r| &r.principal != peer && r.device_id == registration.device_id)
        {
            return ToAgent::error("This identity is already registered by another account");
        }
        if req::atomic_json(
            &shared.users_dir().join(format!("{stem}.json")),
            &registration,
        )
        .is_err()
        {
            return ToAgent::error("Cannot save the registration");
        }
        registrations.retain(|r| &r.principal != peer);
        registrations.push(registration);
    }
    ToAgent::ok(Some(shared.status_for(peer)))
}

fn unregister(shared: &Shared, peer: &Principal) -> ToAgent {
    let Some(stem) = peer.file_stem() else {
        return ToAgent::error("Unsupported local account");
    };
    let mut registrations = lock(&shared.registrations);
    if !registrations.iter().any(|r| &r.principal == peer) {
        return ToAgent::error("Remote requests are not enabled for this account");
    }
    if fs::remove_file(shared.users_dir().join(format!("{stem}.json"))).is_err() {
        return ToAgent::error("Cannot remove the registration");
    }
    registrations.retain(|r| &r.principal != peer);
    ToAgent::ok(None)
}

/// Allowed transitions reported by the user agent. Anything else is refused.
fn allowed(answered: bool, from: JobState, to: JobState) -> bool {
    use JobState::*;
    if !answered {
        return matches!(to, PendingConsent | Busy | Unavailable | Rejected | Failed);
    }
    match from {
        PendingConsent => matches!(to, Running | Rejected | Expired | Failed),
        Running => matches!(to, Completed | Failed),
        _ => false,
    }
}

struct Update {
    job_id: Option<String>,
    state: Option<JobState>,
    expires: Option<u64>,
    reason: Option<String>,
    result: Option<serde_json::Value>,
}

fn apply_update(shared: &Shared, peer: &Principal, update: Update) -> ToAgent {
    let (Some(job_id), Some(state)) = (update.job_id, update.state) else {
        return ToAgent::error("Invalid update");
    };
    let result = match (state, update.result) {
        (JobState::Completed, Some(report)) => match serde_json::to_vec(&report) {
            Ok(bytes) if bytes.len() <= MAX_RESULT => Some(Arc::new(bytes)),
            _ => return ToAgent::error("Audit result too large"),
        },
        (JobState::Completed, None) => return ToAgent::error("Missing audit result"),
        (_, Some(_)) => return ToAgent::error("Unexpected audit result"),
        (_, None) => None,
    };
    let now = req::now_ms();
    let mut jobs = lock(&shared.jobs);
    let Some(job) = jobs
        .get_mut(&job_id)
        .filter(|job| &job.record.principal == peer)
    else {
        return ToAgent::error("Unknown request");
    };
    if !allowed(job.answered, job.record.state, state) {
        return ToAgent::error("Request already closed");
    }
    if state == JobState::PendingConsent {
        let Some(expires) = update
            .expires
            .filter(|e| *e > now && *e <= now + remote::CONSENT_SECONDS * 1000 + 5000)
        else {
            return ToAgent::error("Invalid consent deadline");
        };
        job.record.consent_expires_at_unix_ms = Some(expires);
    }
    if state == JobState::Running {
        job.record.running_since_unix_ms = Some(now);
    }
    let first = !job.answered;
    job.answered = true;
    job.record.state = state;
    job.record.reason = update.reason.filter(|r| r.len() <= 64);
    job.record.updated_at_unix_ms = now;
    job.result = result;
    // BUSY/UNAVAILABLE on dispatch are not stored: the Server may retry the same ID.
    if !(first && matches!(state, JobState::Busy | JobState::Unavailable)) {
        shared.persist(&job.record);
    }
    shared.changed.notify_all();
    ToAgent::ok(None)
}

/// A link whose ping fails is gone: its user is no longer available.
fn drop_link(shared: &Shared, principal: &Principal, serial: u64) {
    {
        let mut links = lock(&shared.links);
        if links
            .get(principal)
            .is_some_and(|link| link.serial == serial)
        {
            links.remove(principal);
        } else {
            return;
        }
    }
    let now = req::now_ms();
    let mut jobs = lock(&shared.jobs);
    for job in jobs.values_mut() {
        if &job.record.principal == principal && job.active() {
            let first = !job.answered;
            job.answered = true;
            job.record.state = if first {
                JobState::Unavailable
            } else {
                JobState::Failed
            };
            job.record.reason = Some("SESSION_LOST".into());
            job.record.updated_at_unix_ms = now;
            if !first {
                shared.persist(&job.record);
            }
        }
    }
    shared.changed.notify_all();
}

fn handle_ipc(shared: Arc<Shared>, mut connection: ipc::Connection) {
    connection.set_read_timeout(Some(Duration::from_secs(30)));
    let Ok(Some(ToService::Hello {
        protocol,
        intent,
        identity_dir,
        client_name,
        job_id,
        state,
        consent_expires_at_unix_ms,
        reason,
        result,
        server_id,
        endpoint,
        action,
    })) = connection.receive::<ToService>()
    else {
        return;
    };
    let peer = connection.peer.clone();
    if protocol != ipc::PROTOCOL {
        let _ = connection.send(&ToAgent::error("Unsupported IPC protocol version"));
        return;
    }
    let reply = match intent {
        Intent::Register => register(&shared, &peer, identity_dir, client_name),
        Intent::Unregister => unregister(&shared, &peer),
        Intent::Status => ToAgent::ok(Some(shared.status_for(&peer))),
        Intent::Connection => connection_action(&shared, &peer, server_id, endpoint, action),
        Intent::Update => apply_update(
            &shared,
            &peer,
            Update {
                job_id,
                state,
                expires: consent_expires_at_unix_ms,
                reason,
                result,
            },
        ),
        Intent::Link => {
            let registered = lock(&shared.registrations)
                .iter()
                .any(|r| r.principal == peer);
            if !registered {
                let _ = connection.send(&ToAgent::error("NOT_REGISTERED"));
                return;
            }
            // One session per user: a live link keeps its place, a dead one is replaced.
            let existing = lock(&shared.links).get_mut(&peer).map(|link| {
                (
                    ipc::write_message(&mut link.writer, &ToAgent::Ping).is_ok(),
                    link.serial,
                )
            });
            match existing {
                Some((true, _)) => {
                    let _ = connection.send(&ToAgent::error("ALREADY_LINKED"));
                    return;
                }
                Some((false, serial)) => drop_link(&shared, &peer, serial),
                None => {}
            }
            if connection.send(&ToAgent::ok(None)).is_err() {
                return;
            }
            let serial = shared.serial.fetch_add(1, Ordering::SeqCst) as u64;
            lock(&shared.links).insert(
                peer,
                Link {
                    writer: connection.into_writer(),
                    serial,
                },
            );
            return;
        }
    };
    let _ = connection.send(&reply);
}

// ---------------------------------------------------------------------------------------
// Remote HTTP API (only after mutual authentication)
// ---------------------------------------------------------------------------------------

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

struct HttpResponse {
    status: u16,
    body: Vec<u8>,
}

fn json_response<T: Serialize>(status: u16, value: &T) -> HttpResponse {
    HttpResponse {
        status,
        body: serde_json::to_vec(value).unwrap_or_default(),
    }
}

fn error_response(status: u16, code: &str) -> HttpResponse {
    json_response(
        status,
        &serde_json::json!({"schemaVersion": remote::ERROR_SCHEMA, "error": code}),
    )
}

/// Who is asking, as established by mutual TLS for this connection.
struct Caller {
    registration: Registration,
    server: TrustedServer,
}

fn status_document(job: &Job) -> RequestStatus {
    let record = &job.record;
    RequestStatus {
        schema_version: remote::STATUS_SCHEMA.into(),
        request_id: record.request_id.clone(),
        device_id: record.device_id.clone(),
        state: record.state,
        reason: record.reason.clone(),
        created_at_unix_ms: Some(record.created_at_unix_ms),
        updated_at_unix_ms: Some(record.updated_at_unix_ms),
        consent_expires_at_unix_ms: record
            .consent_expires_at_unix_ms
            .filter(|_| record.state == JobState::PendingConsent),
        result_available: job.result.is_some(),
    }
}

fn immediate(caller: &Caller, request_id: &str, state: JobState, reason: &str) -> RequestStatus {
    RequestStatus {
        schema_version: remote::STATUS_SCHEMA.into(),
        request_id: request_id.into(),
        device_id: caller.registration.device_id.clone(),
        state,
        reason: Some(reason.into()),
        created_at_unix_ms: None,
        updated_at_unix_ms: None,
        consent_expires_at_unix_ms: None,
        result_available: false,
    }
}

fn find_job<'a>(
    jobs: &'a HashMap<String, Job>,
    caller: &Caller,
    request_id: &str,
) -> Option<&'a Job> {
    jobs.values().find(|job| {
        job.answered
            && job.record.server_key == caller.server.public_key
            && job.record.device_id == caller.registration.device_id
            && job.record.request_id == request_id
    })
}

fn create_request(shared: &Shared, caller: &Caller, body: &[u8]) -> HttpResponse {
    let Ok(request) = serde_json::from_slice::<AuditRequest>(body) else {
        return error_response(400, "INVALID_REQUEST");
    };
    if request.schema_version != remote::REQUEST_SCHEMA
        || request.operation != remote::OPERATION_AUDIT
        || !remote::valid_request_id(&request.request_id)
        || request.requester.as_ref().is_some_and(|r| !r.valid())
    {
        return error_response(400, "INVALID_REQUEST");
    }
    let now = req::now_ms();
    if request.issued_at_unix_ms.abs_diff(now) > remote::MAX_CLOCK_SKEW_MS {
        return error_response(400, "STALE_REQUEST");
    }
    let principal = caller.registration.principal.clone();
    let job_id = match crate::consent::random_hex(16) {
        Ok(id) => id,
        Err(_) => return error_response(503, "INTERNAL_ERROR"),
    };
    {
        let mut jobs = lock(&shared.jobs);
        jobs.retain(|_, job| {
            let keep = now.saturating_sub(job.record.created_at_unix_ms) <= RETENTION_MS;
            if !keep {
                let _ = fs::remove_file(
                    shared
                        .requests_dir()
                        .join(format!("{}.json", job.record.job_id)),
                );
            }
            keep
        });
        // Same Server, same ID: the original request, never a second execution.
        if let Some(job) = find_job(&jobs, caller, &request.request_id) {
            return json_response(200, &status_document(job));
        }
        if jobs.values().any(Job::active) {
            return json_response(
                409,
                &immediate(
                    caller,
                    &request.request_id,
                    JobState::Busy,
                    "REQUEST_IN_PROGRESS",
                ),
            );
        }
        let mut links = lock(&shared.links);
        let Some(link) = links.get_mut(&principal) else {
            return json_response(
                503,
                &immediate(
                    caller,
                    &request.request_id,
                    JobState::Unavailable,
                    "NO_USER_SESSION",
                ),
            );
        };
        let job = ToAgent::Job {
            job_id: job_id.clone(),
            device_id: caller.registration.device_id.clone(),
            server: JobServer {
                server_id: caller.server.server_id.clone(),
                public_key: caller.server.public_key.clone(),
                fingerprint: caller.server.fingerprint.clone(),
                requester: request.requester.clone(),
            },
        };
        if ipc::write_message(&mut link.writer, &job).is_err() {
            links.remove(&principal);
            return json_response(
                503,
                &immediate(
                    caller,
                    &request.request_id,
                    JobState::Unavailable,
                    "NO_USER_SESSION",
                ),
            );
        }
        jobs.insert(
            job_id.clone(),
            Job {
                record: Record {
                    schema_version: RECORD_SCHEMA.into(),
                    job_id: job_id.clone(),
                    request_id: request.request_id.clone(),
                    server_id: caller.server.server_id.clone(),
                    server_key: caller.server.public_key.clone(),
                    principal,
                    device_id: caller.registration.device_id.clone(),
                    state: JobState::PendingConsent,
                    created_at_unix_ms: now,
                    updated_at_unix_ms: now,
                    consent_expires_at_unix_ms: None,
                    running_since_unix_ms: None,
                    reason: None,
                },
                answered: false,
                result: None,
            },
        );
    }
    // Wait for the user agent's first answer (consent shown, busy, unavailable).
    let jobs = lock(&shared.jobs);
    let (mut jobs, _) = shared
        .changed
        .wait_timeout_while(jobs, DISPATCH_TIMEOUT, |jobs| {
            jobs.get(&job_id).is_some_and(|job| !job.answered)
        })
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let Some(job) = jobs.get(&job_id) else {
        return error_response(503, "INTERNAL_ERROR");
    };
    if !job.answered {
        jobs.remove(&job_id);
        return json_response(
            503,
            &immediate(
                caller,
                &request.request_id,
                JobState::Unavailable,
                "SESSION_NOT_RESPONDING",
            ),
        );
    }
    match job.record.state {
        JobState::Busy | JobState::Unavailable => {
            let status = status_document(job);
            let code = if status.state == JobState::Busy {
                409
            } else {
                503
            };
            jobs.remove(&job_id);
            json_response(code, &status)
        }
        JobState::PendingConsent => json_response(202, &status_document(job)),
        _ => json_response(200, &status_document(job)),
    }
}

fn route(shared: &Shared, caller: &Caller, request: &HttpRequest) -> HttpResponse {
    const PREFIX: &str = "/v1/audit-requests";
    let rest = request.path.strip_prefix(PREFIX);
    match (request.method.as_str(), rest) {
        ("POST", Some("")) => create_request(shared, caller, &request.body),
        ("GET", Some(rest)) if rest.starts_with('/') => {
            let rest = &rest[1..];
            let (id, want_result) = match rest.strip_suffix("/result") {
                Some(id) => (id, true),
                None => (rest, false),
            };
            if !remote::valid_request_id(id) {
                return error_response(404, "UNKNOWN_REQUEST");
            }
            let jobs = lock(&shared.jobs);
            let Some(job) = find_job(&jobs, caller, id) else {
                return error_response(404, "UNKNOWN_REQUEST");
            };
            if !want_result {
                return json_response(200, &status_document(job));
            }
            match (&job.result, job.record.state) {
                (Some(bytes), _) => {
                    let report = serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null);
                    json_response(
                        200,
                        &AuditResult {
                            schema_version: remote::RESULT_SCHEMA.into(),
                            request_id: job.record.request_id.clone(),
                            device_id: job.record.device_id.clone(),
                            report,
                        },
                    )
                }
                (None, JobState::Completed) => error_response(410, "RESULT_EXPIRED"),
                (None, _) => json_response(409, &status_document(job)),
            }
        }
        (_, Some(_)) => error_response(405, "METHOD_NOT_ALLOWED"),
        _ => error_response(404, "NOT_FOUND"),
    }
}

fn write_tunnel_frame<T: Serialize>(stream: &mut impl Write, frame: &T) -> Result<(), String> {
    let bytes = serde_json::to_vec(frame).map_err(|e| e.to_string())?;
    if bytes.len() > MAX_TUNNEL_FRAME {
        return Err("Tunnel frame too large".into());
    }
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .and_then(|_| stream.write_all(&bytes))
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())
}

fn read_tunnel_frame<T: serde::de::DeserializeOwned>(
    stream: &mut impl Read,
) -> Result<Option<T>, String> {
    let mut length = [0u8; 4];
    match stream.read(&mut length[..1]) {
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
            ) =>
        {
            return Ok(None)
        }
        Err(error) => return Err(error.to_string()),
        Ok(0) => return Err("Server tunnel closed".into()),
        Ok(_) => {}
    }
    stream
        .read_exact(&mut length[1..])
        .map_err(|e| e.to_string())?;
    let length = u32::from_be_bytes(length) as usize;
    if length == 0 || length > MAX_TUNNEL_FRAME {
        return Err("Invalid Server tunnel frame".into());
    }
    let mut bytes = vec![0u8; length];
    stream.read_exact(&mut bytes).map_err(|e| e.to_string())?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|_| "Invalid Server tunnel JSON".into())
}

fn current_connection(
    shared: &Shared,
    registration: &Registration,
    config: &ConnectionConfig,
) -> bool {
    lock(&shared.registrations).iter().any(|registered| {
        registered.principal == registration.principal
            && registered.device_id == registration.device_id
            && registered.connections.iter().any(|connection| {
                connection.server_id == config.server_id
                    && connection.generation == config.generation
                    && connection.enabled
            })
    })
}

fn set_connection_runtime(
    shared: &Shared,
    registration: &Registration,
    config: &ConnectionConfig,
    connected: bool,
    error: Option<String>,
) {
    let key = connection_key(&registration.principal, &config.server_id);
    let mut runtime = lock(&shared.connections);
    if runtime
        .get(&key)
        .is_some_and(|state| state.generation == config.generation)
    {
        let socket = connected
            .then(|| runtime.get(&key).and_then(|state| state.socket.clone()))
            .flatten();
        runtime.insert(
            key,
            ConnectionRuntime {
                generation: config.generation,
                connected,
                error,
                socket,
            },
        );
    }
}

fn set_connection_socket(
    shared: &Shared,
    registration: &Registration,
    config: &ConnectionConfig,
    socket: TcpStream,
) {
    let key = connection_key(&registration.principal, &config.server_id);
    let mut runtime = lock(&shared.connections);
    if let Some(state) = runtime
        .get_mut(&key)
        .filter(|state| state.generation == config.generation)
    {
        state.socket = Some(Arc::new(socket));
    }
}

fn connect_tunnel(
    shared: &Shared,
    registration: &Registration,
    config: &ConnectionConfig,
) -> Result<(), String> {
    use base64::Engine as _;
    let identity = identity::load_for_service(
        Path::new(&registration.identity_dir),
        &registration.principal,
    )?;
    if identity.device_id != registration.device_id {
        return Err("Registered identity changed".into());
    }
    let server = identity
        .servers
        .iter()
        .find(|server| {
            server.server_id == config.server_id && server.status == identity::TrustStatus::Trusted
        })
        .ok_or("Server is no longer trusted")?
        .clone();
    let public: [u8; 32] = base64::engine::general_purpose::STANDARD
        .decode(&server.public_key)
        .map_err(|_| "Invalid trusted Server key")?
        .try_into()
        .map_err(|_| "Invalid trusted Server key")?;
    let tls =
        remote::tls::requester_config(identity.signing_key, public).map_err(|e| e.to_string())?;
    let mut tcp = None;
    for address in config
        .endpoint
        .to_socket_addrs()
        .map_err(|e| e.to_string())?
        .take(8)
    {
        if let Ok(stream) = TcpStream::connect_timeout(&address, Duration::from_secs(5)) {
            tcp = Some(stream);
            break;
        }
    }
    let tcp = tcp.ok_or("Server unreachable")?;
    set_connection_socket(
        shared,
        registration,
        config,
        tcp.try_clone().map_err(|e| e.to_string())?,
    );
    tcp.set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|e| e.to_string())?;
    tcp.set_write_timeout(Some(Duration::from_secs(20)))
        .map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from(config.server_id.clone())
        .map_err(|_| "Invalid Server ID")?;
    let connection = rustls::ClientConnection::new(tls, name).map_err(|e| e.to_string())?;
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        stream
            .conn
            .complete_io(&mut stream.sock)
            .map_err(|e| e.to_string())?;
    }
    write_tunnel_frame(
        &mut stream,
        &serde_json::json!({"schemaVersion":TUNNEL_SCHEMA,"deviceId":registration.device_id,"name":if registration.name.is_empty() { &registration.device_id } else { &registration.name }}),
    )?;
    let ack_deadline = Instant::now() + Duration::from_secs(10);
    let ack: serde_json::Value = loop {
        if !current_connection(shared, registration, config) || Instant::now() > ack_deadline {
            return Err("Server tunnel acknowledgement timed out".into());
        }
        if let Some(ack) = read_tunnel_frame(&mut stream)? {
            break ack;
        }
    };
    if ack["schemaVersion"] != TUNNEL_SCHEMA || ack["connected"] != true {
        return Err("Server refused tunnel".into());
    }
    set_connection_runtime(shared, registration, config, true, None);
    let mut last_frame = Instant::now();
    while current_connection(shared, registration, config) {
        let Some(frame): Option<TunnelRequest> = read_tunnel_frame(&mut stream)? else {
            if last_frame.elapsed() > Duration::from_secs(40) {
                return Err("Server heartbeat timed out".into());
            }
            continue;
        };
        last_frame = Instant::now();
        if frame.schema_version != TUNNEL_SCHEMA {
            return Err("Unsupported tunnel protocol".into());
        }
        let current_identity = identity::load_for_service(
            Path::new(&registration.identity_dir),
            &registration.principal,
        )?;
        if current_identity.device_id != registration.device_id
            || !current_identity.trusted(&public).is_some_and(|entry| {
                entry.server_id == config.server_id && entry.public_key == server.public_key
            })
        {
            return Err("Server trust removed".into());
        }
        let response = if frame.method == "GET" && frame.path == "/v1/ping" {
            json_response(200, &serde_json::json!({"ok":true}))
        } else {
            let caller = Caller {
                registration: registration.clone(),
                server: server.clone(),
            };
            route(
                shared,
                &caller,
                &HttpRequest {
                    method: frame.method,
                    path: frame.path,
                    body: frame
                        .body
                        .map(|v| v.to_string().into_bytes())
                        .unwrap_or_default(),
                },
            )
        };
        let body =
            serde_json::from_slice(&response.body).map_err(|_| "Invalid local tunnel response")?;
        write_tunnel_frame(
            &mut stream,
            &TunnelReply {
                schema_version: TUNNEL_SCHEMA,
                sequence: frame.sequence,
                code: response.status,
                body,
            },
        )?;
    }
    stream.conn.send_close_notify();
    let _ = stream.flush();
    Ok(())
}

fn run_connection(shared: Arc<Shared>, registration: Registration, config: ConnectionConfig) {
    let key = connection_key(&registration.principal, &config.server_id);
    while current_connection(&shared, &registration, &config) {
        let error = connect_tunnel(&shared, &registration, &config).err();
        if !current_connection(&shared, &registration, &config) {
            break;
        }
        set_connection_runtime(&shared, &registration, &config, false, error);
        thread::sleep(Duration::from_secs(5));
    }
    let mut runtime = lock(&shared.connections);
    if runtime
        .get(&key)
        .is_some_and(|state| state.generation == config.generation)
    {
        runtime.remove(&key);
    }
}

fn run_connections(shared: Arc<Shared>) {
    loop {
        let registrations = lock(&shared.registrations).clone();
        for registration in registrations {
            for config in registration
                .connections
                .iter()
                .filter(|config| config.enabled)
            {
                let key = connection_key(&registration.principal, &config.server_id);
                let mut runtime = lock(&shared.connections);
                if runtime
                    .get(&key)
                    .is_some_and(|state| state.generation == config.generation)
                {
                    continue;
                }
                runtime.insert(
                    key,
                    ConnectionRuntime {
                        generation: config.generation,
                        connected: false,
                        error: None,
                        socket: None,
                    },
                );
                let (shared, registration, config) =
                    (shared.clone(), registration.clone(), config.clone());
                thread::spawn(move || run_connection(shared, registration, config));
            }
        }
        thread::sleep(Duration::from_secs(2));
    }
}

// Supervision
// ---------------------------------------------------------------------------------------

fn watchdog(shared: Arc<Shared>) {
    loop {
        thread::sleep(PING_EVERY);
        let failed: Vec<(Principal, u64)> = lock(&shared.links)
            .iter_mut()
            .filter_map(|(principal, link)| {
                ipc::write_message(&mut link.writer, &ToAgent::Ping)
                    .is_err()
                    .then(|| (principal.clone(), link.serial))
            })
            .collect();
        for (principal, serial) in failed {
            drop_link(&shared, &principal, serial);
        }
        let now = req::now_ms();
        let mut jobs = lock(&shared.jobs);
        for job in jobs.values_mut().filter(|job| job.answered) {
            let record = &mut job.record;
            let overdue = match record.state {
                JobState::PendingConsent => record
                    .consent_expires_at_unix_ms
                    .is_some_and(|e| now > e + CONSENT_GRACE_MS)
                    .then_some((JobState::Expired, "CONSENT_EXPIRED")),
                JobState::Running => record
                    .running_since_unix_ms
                    .is_some_and(|s| now > s + RUN_LIMIT_MS)
                    .then_some((JobState::Failed, "AUDIT_TIMEOUT")),
                _ => None,
            };
            if let Some((state, reason)) = overdue {
                record.state = state;
                record.reason = Some(reason.into());
                record.updated_at_unix_ms = now;
                shared.persist(record);
            }
            if job.result.is_some()
                && now.saturating_sub(record.updated_at_unix_ms) > RESULT_RETENTION_MS
            {
                job.result = None;
            }
        }
        shared.changed.notify_all();
    }
}

fn serve() -> Result<(), CliError> {
    let shared = Shared::load(service_dir())?;
    let ipc_listener = ipc::Listener::bind()
        .map_err(|_| CliError("Cannot open the local service endpoint".into()))?;
    {
        let shared = shared.clone();
        thread::spawn(move || watchdog(shared));
    }
    {
        let shared = shared.clone();
        thread::spawn(move || run_connections(shared));
    }
    loop {
        match ipc_listener.accept() {
            Ok(connection) => {
                let shared = shared.clone();
                thread::spawn(move || handle_ipc(shared, connection));
            }
            Err(_) => thread::sleep(Duration::from_millis(50)),
        }
    }
}

#[cfg(windows)]
mod windows_scm {
    //! Windows Service Control Manager glue. Compiled, not exercised on this host.
    use super::WINDOWS_SERVICE_NAME;
    use std::{ptr, sync::OnceLock};
    use windows_sys::Win32::{
        Foundation::{ERROR_FAILED_SERVICE_CONTROLLER_CONNECT, NO_ERROR},
        System::Services::{
            RegisterServiceCtrlHandlerExW, SetServiceStatus, StartServiceCtrlDispatcherW,
            SERVICE_ACCEPT_SHUTDOWN, SERVICE_ACCEPT_STOP, SERVICE_CONTROL_SHUTDOWN,
            SERVICE_CONTROL_STOP, SERVICE_RUNNING, SERVICE_STATUS, SERVICE_STATUS_HANDLE,
            SERVICE_STOPPED, SERVICE_TABLE_ENTRYW, SERVICE_WIN32_OWN_PROCESS,
        },
    };

    static HANDLE: OnceLock<usize> = OnceLock::new();

    fn name() -> Vec<u16> {
        WINDOWS_SERVICE_NAME
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect()
    }

    fn report(state: u32) {
        if let Some(handle) = HANDLE.get() {
            let status = SERVICE_STATUS {
                dwServiceType: SERVICE_WIN32_OWN_PROCESS,
                dwCurrentState: state,
                dwControlsAccepted: if state == SERVICE_RUNNING {
                    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN
                } else {
                    0
                },
                dwWin32ExitCode: NO_ERROR,
                dwServiceSpecificExitCode: 0,
                dwCheckPoint: 0,
                dwWaitHint: 0,
            };
            // SAFETY: the handle comes from RegisterServiceCtrlHandlerExW.
            unsafe { SetServiceStatus(*handle as SERVICE_STATUS_HANDLE, &status) };
        }
    }

    unsafe extern "system" fn control(
        code: u32,
        _event: u32,
        _data: *mut core::ffi::c_void,
        _context: *mut core::ffi::c_void,
    ) -> u32 {
        if code == SERVICE_CONTROL_STOP || code == SERVICE_CONTROL_SHUTDOWN {
            report(SERVICE_STOPPED);
            std::process::exit(0);
        }
        NO_ERROR
    }

    unsafe extern "system" fn service_main(_argc: u32, _argv: *mut *mut u16) {
        let name = name();
        let handle = RegisterServiceCtrlHandlerExW(name.as_ptr(), Some(control), ptr::null_mut());
        if handle.is_null() {
            return;
        }
        let _ = HANDLE.set(handle as usize);
        report(SERVICE_RUNNING);
        let _ = super::serve();
        report(SERVICE_STOPPED);
    }

    /// Ok(true): ran under the SCM. Ok(false): not started by the SCM (console run).
    pub(super) fn dispatch() -> Result<bool, ()> {
        let mut name = name();
        let table = [
            SERVICE_TABLE_ENTRYW {
                lpServiceName: name.as_mut_ptr(),
                lpServiceProc: Some(service_main),
            },
            SERVICE_TABLE_ENTRYW {
                lpServiceName: ptr::null_mut(),
                lpServiceProc: None,
            },
        ];
        // SAFETY: the table and the name outlive the dispatcher call.
        if unsafe { StartServiceCtrlDispatcherW(table.as_ptr()) } != 0 {
            return Ok(true);
        }
        if std::io::Error::last_os_error().raw_os_error()
            == Some(ERROR_FAILED_SERVICE_CONTROLLER_CONNECT as i32)
        {
            return Ok(false);
        }
        Err(())
    }
}

#[cfg(windows)]
pub(crate) fn windows_service_installed() -> bool {
    use windows_sys::Win32::System::Services::{
        CloseServiceHandle, OpenSCManagerW, OpenServiceW, SC_MANAGER_CONNECT, SERVICE_QUERY_STATUS,
    };
    let name: Vec<u16> = WINDOWS_SERVICE_NAME
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect();
    // SAFETY: handles are closed; null machine and database mean the local defaults.
    unsafe {
        let manager = OpenSCManagerW(std::ptr::null(), std::ptr::null(), SC_MANAGER_CONNECT);
        if manager.is_null() {
            return false;
        }
        let service = OpenServiceW(manager, name.as_ptr(), SERVICE_QUERY_STATUS);
        let installed = !service.is_null();
        if installed {
            CloseServiceHandle(service);
        }
        CloseServiceHandle(manager);
        installed
    }
}

pub fn run(args: &[OsString]) -> Result<CliOutput, CliError> {
    match args {
        [command] if command == "run" => {
            #[cfg(windows)]
            match windows_scm::dispatch() {
                Ok(true) => {
                    return Ok(CliOutput {
                        text: String::new(),
                        code: 0,
                    })
                }
                Ok(false) => {}
                Err(()) => return Err(CliError("Cannot start the Windows service".into())),
            }
            serve().map(|_| CliOutput {
                text: String::new(),
                code: 0,
            })
        }
        _ => Err(CliError(
            baradwatchu_messages::message(
                "service.usage",
                baradwatchu_messages::configured_language(),
            )
            .into(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transitions_follow_the_consent_flow() {
        use JobState::*;
        assert!(allowed(false, PendingConsent, PendingConsent));
        assert!(allowed(false, PendingConsent, Busy));
        assert!(!allowed(false, PendingConsent, Running));
        assert!(!allowed(false, PendingConsent, Completed));
        assert!(allowed(true, PendingConsent, Running));
        assert!(!allowed(true, PendingConsent, Completed));
        assert!(allowed(true, Running, Completed));
        for closed in [Completed, Rejected, Expired, Failed] {
            for next in [PendingConsent, Running, Completed, Failed] {
                assert!(!allowed(true, closed, next), "{closed:?} -> {next:?}");
            }
        }
    }
}
