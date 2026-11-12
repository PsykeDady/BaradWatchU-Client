//! Milestone 2 system service (`baradwatchu-agent service run`): always-on component that
//! terminates mutual TLS for registered users and relays authorized requests to their
//! agent. It never runs an audit, never writes in a user's folders, never chooses a user:
//! - a user *registers* their own identity folder over the local IPC (the OS tells the
//!   service who they are; every file must belong to them);
//! - a Server connects with SNI = that user's Device ID; the service answers with that
//!   user's Ed25519 key and accepts only Server keys in that user's trust store;
//! - requests are relayed to the user's linked agent (`remote link`, started by the tray);
//!   with no linked agent the answer is `UNAVAILABLE`, while busy it is `BUSY`.
//!
//! Data (`BARADWATCHU_SERVICE_DIR` or the platform default, system-only):
//! `service.json` (operator configuration, listener off when absent), `users/<principal>.json`
//! (registrations), `requests/<job>.json` (request records without results, for duplicate
//! and replay detection across restarts). Results stay in memory only.
use crate::identity::{self, ServiceIdentity, TrustedServer};
use crate::ipc::{self, Intent, JobServer, JobState, Principal, ServiceStatus, ToAgent, ToService};
use crate::remote::{self, tls, AuditRequest, AuditResult, RequestStatus};
use crate::requirements::{self as req, CliError, CliOutput};
use rustls::{
    client::danger::HandshakeSignatureValid,
    pki_types::{CertificateDer, UnixTime},
    server::{
        danger::{ClientCertVerified, ClientCertVerifier},
        ClientHello, ResolvesServerCert,
    },
    sign::CertifiedKey,
    DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    ffi::OsString,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Condvar, Mutex,
    },
    thread,
    time::Duration,
};

const CONFIG_FILE: &str = "service.json";
const CONFIG_SCHEMA: &str = "baradwatchu.service-config.v1";
const REGISTRATION_SCHEMA: &str = "baradwatchu.service-registration.v1";
const RECORD_SCHEMA: &str = "baradwatchu.remote-request-record.v1";
/// Request records (duplicate and replay protection) outlive the accepted clock skew.
const RETENTION_MS: u64 = 24 * 3600 * 1000;
const RESULT_RETENTION_MS: u64 = 3600 * 1000;
const DISPATCH_TIMEOUT: Duration = Duration::from_secs(15);
const CONSENT_GRACE_MS: u64 = 15_000;
const RUN_LIMIT_MS: u64 = 35 * 60 * 1000;
const PING_EVERY: Duration = Duration::from_secs(3);
const MAX_CONNECTIONS: usize = 32;
const MAX_HTTP_HEADERS: usize = 16 * 1024;
const MAX_HTTP_BODY: usize = 16 * 1024;
const MAX_RESULT: usize = 8 * 1024 * 1024;
const DISCOVERY_PORT: u16 = 7444;
const DISCOVERY_PREFIX: &str = "BARADWATCHU_DISCOVER_V1 ";
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

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Config {
    schema_version: String,
    #[serde(default)]
    remote: Option<RemoteConfig>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RemoteConfig {
    /// `address:port`; the operator chooses the interface (e.g. a VPN address).
    listen: String,
    #[serde(default = "enabled_by_default")]
    enabled: bool,
}

fn enabled_by_default() -> bool {
    true
}

fn read_config(dir: &Path) -> Result<Option<Config>, String> {
    let path = dir.join(CONFIG_FILE);
    let text = match fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("Service configuration is not readable".into()),
    };
    let config: Config =
        serde_json::from_str(&text).map_err(|_| "Service configuration is invalid".to_owned())?;
    if config.schema_version != CONFIG_SCHEMA
        || config
            .remote
            .as_ref()
            .is_some_and(|r| r.listen.parse::<SocketAddr>().is_err())
    {
        return Err("Service configuration is invalid".into());
    }
    Ok(Some(config))
}

/// The configured listener address; None = remote listener disabled (default).
fn load_config(dir: &Path) -> Result<Option<SocketAddr>, String> {
    read_config(dir)?
        .and_then(|config| config.remote)
        .filter(|remote| remote.enabled)
        .map(|remote| {
            remote
                .listen
                .parse::<SocketAddr>()
                .map_err(|_| "Service configuration is invalid".to_owned())
        })
        .transpose()
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Registration {
    schema_version: String,
    principal: Principal,
    device_id: String,
    identity_dir: String,
    registered_at_unix_ms: u64,
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

#[derive(Default)]
struct ListenerState {
    address: Option<String>,
    running: bool,
    error: Option<String>,
}

struct Shared {
    dir: PathBuf,
    registrations: Mutex<Vec<Registration>>,
    links: Mutex<HashMap<Principal, Link>>,
    jobs: Mutex<HashMap<String, Job>>,
    changed: Condvar,
    listener: Mutex<ListenerState>,
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
            listener: Mutex::new(ListenerState::default()),
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

    fn registration_for_device(&self, device_id: &str) -> Option<Registration> {
        lock(&self.registrations)
            .iter()
            .find(|r| r.device_id.eq_ignore_ascii_case(device_id))
            .cloned()
    }

    /// The registered identity behind an SNI name, freshly read and still matching.
    fn identity_for(&self, device_id: &str) -> Option<(Registration, ServiceIdentity)> {
        let registration = self.registration_for_device(device_id)?;
        let identity = identity::load_for_service(
            Path::new(&registration.identity_dir),
            &registration.principal,
        )
        .ok()?;
        (identity.device_id == registration.device_id).then_some((registration, identity))
    }

    fn trusted_by_anyone(&self, key: &[u8; 32]) -> bool {
        let registrations = lock(&self.registrations).clone();
        registrations.iter().any(|registration| {
            identity::load_for_service(
                Path::new(&registration.identity_dir),
                &registration.principal,
            )
            .is_ok_and(|identity| {
                identity.device_id == registration.device_id && identity.trusted(key).is_some()
            })
        })
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
        let listener = lock(&self.listener);
        ServiceStatus {
            version: env!("CARGO_PKG_VERSION").into(),
            listener_configured: listener.address.is_some(),
            listener_address: listener.address.clone(),
            listener_running: listener.running,
            listener_error: listener.error.clone(),
            registered: registration.is_some(),
            registered_device_id: registration.map(|r| r.device_id),
            registration_problem,
            session_linked,
            request_in_progress,
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

// ---------------------------------------------------------------------------------------
// Local IPC
// ---------------------------------------------------------------------------------------

fn register(shared: &Shared, peer: &Principal, identity_dir: Option<String>) -> ToAgent {
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
        identity_dir: dir.to_string_lossy().into_owned(),
        registered_at_unix_ms: req::now_ms(),
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
        job_id,
        state,
        consent_expires_at_unix_ms,
        reason,
        result,
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
        Intent::Register => register(&shared, &peer, identity_dir),
        Intent::Unregister => unregister(&shared, &peer),
        Intent::Status => ToAgent::ok(Some(shared.status_for(&peer))),
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
// Mutual TLS
// ---------------------------------------------------------------------------------------

/// Picks the registered user named by SNI and presents *their* Ed25519 key. Unknown or
/// stale names abort the handshake: nothing is revealed about other users.
#[derive(Debug)]
struct Resolver(Arc<Shared>);

impl ResolvesServerCert for Resolver {
    fn resolve(&self, hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let (_, identity) = self.0.identity_for(hello.server_name()?)?;
        Some(Arc::new(
            tls::Ed25519Key::new(identity.signing_key).certified(),
        ))
    }

    fn only_raw_public_keys(&self) -> bool {
        true
    }
}

/// Requires an Ed25519 raw public key that proves possession (CertificateVerify) and that
/// a registered user trusts. The exact user is matched after the handshake (`serve`).
#[derive(Debug)]
struct Verifier(Arc<Shared>);

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, TlsError> {
        let refused = || {
            TlsError::InvalidCertificate(rustls::CertificateError::ApplicationVerificationFailure)
        };
        let key = tls::key_from_spki(end_entity.as_ref()).ok_or_else(refused)?;
        if !intermediates.is_empty() || !self.0.trusted_by_anyone(&key) {
            return Err(refused());
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::General("TLS 1.2 is not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, TlsError> {
        tls::verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }

    fn requires_raw_public_keys(&self) -> bool {
        true
    }
}

fn tls_config(shared: &Arc<Shared>) -> Result<Arc<rustls::ServerConfig>, TlsError> {
    let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(tls::provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(Verifier(shared.clone())))
        .with_cert_resolver(Arc::new(Resolver(shared.clone())));
    // Every connection is authenticated from scratch (revocation applies immediately).
    config.session_storage = Arc::new(rustls::server::NoServerSessionStorage {});
    config.send_tls13_tickets = 0;
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------------------
// Remote HTTP API (only after mutual authentication)
// ---------------------------------------------------------------------------------------

struct HttpRequest {
    method: String,
    path: String,
    body: Vec<u8>,
}

fn read_http<R: BufRead>(reader: &mut R) -> Result<HttpRequest, u16> {
    let mut head = Vec::new();
    loop {
        let mut line = Vec::new();
        let read = reader
            .by_ref()
            .take((MAX_HTTP_HEADERS - head.len().min(MAX_HTTP_HEADERS)) as u64 + 1)
            .read_until(b'\n', &mut line)
            .map_err(|_| 400u16)?;
        if read == 0 || !line.ends_with(b"\n") || head.len() + line.len() > MAX_HTTP_HEADERS {
            return Err(400);
        }
        if line == b"\r\n" || line == b"\n" {
            break;
        }
        head.extend_from_slice(&line);
    }
    let head = String::from_utf8(head).map_err(|_| 400u16)?;
    let mut lines = head.lines();
    let mut request_line = lines.next().ok_or(400u16)?.split(' ');
    let (Some(method), Some(path), Some(version), None) = (
        request_line.next(),
        request_line.next(),
        request_line.next(),
        request_line.next(),
    ) else {
        return Err(400);
    };
    if version != "HTTP/1.1" {
        return Err(400);
    }
    let mut length = None;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(400u16)?;
        let value = value.trim();
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(400);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(400);
            }
            length = Some(value.parse::<usize>().map_err(|_| 400u16)?);
        }
    }
    let length = length.unwrap_or(0);
    if length > MAX_HTTP_BODY {
        return Err(413);
    }
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(|_| 400u16)?;
    Ok(HttpRequest {
        method: method.into(),
        path: path.into(),
        body,
    })
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

fn write_http<W: Write>(writer: &mut W, response: &HttpResponse) -> io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        413 => "Payload Too Large",
        503 => "Service Unavailable",
        _ => "Error",
    };
    write!(
        writer,
        "HTTP/1.1 {} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        response.status,
        response.body.len()
    )?;
    writer.write_all(&response.body)?;
    writer.flush()
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

fn serve_connection(shared: Arc<Shared>, config: Arc<rustls::ServerConfig>, tcp: TcpStream) {
    let _ = tcp.set_read_timeout(Some(Duration::from_secs(15)));
    let _ = tcp.set_write_timeout(Some(Duration::from_secs(15)));
    let Ok(connection) = rustls::ServerConnection::new(config) else {
        return;
    };
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    while stream.conn.is_handshaking() {
        if stream.conn.complete_io(&mut stream.sock).is_err() {
            return;
        }
    }
    // Mutual authentication is complete; bind it to the exact user named by SNI.
    let Some(device_id) = stream.conn.server_name().map(str::to_owned) else {
        return;
    };
    let Some(peer_key) = stream
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .and_then(|cert| tls::key_from_spki(cert.as_ref()))
    else {
        return;
    };
    let Some((registration, identity)) = shared.identity_for(&device_id) else {
        return;
    };
    let Some(server) = identity.trusted(&peer_key).cloned() else {
        // Trusted by another local user, not by this one: closed without an answer.
        stream.conn.send_close_notify();
        let _ = stream.flush();
        return;
    };
    drop(identity);
    let caller = Caller {
        registration,
        server,
    };
    let response = {
        let mut reader = BufReader::new(&mut stream);
        match read_http(&mut reader) {
            Ok(request) => route(&shared, &caller, &request),
            Err(status) => error_response(status, "INVALID_HTTP"),
        }
    };
    let _ = write_http(&mut stream, &response);
    stream.conn.send_close_notify();
    let _ = stream.flush();
}

fn run_remote_listener(shared: Arc<Shared>, address: SocketAddr) {
    let fail = |error: String| {
        let mut listener = lock(&shared.listener);
        listener.running = false;
        listener.error = Some(error);
    };
    let config = match tls_config(&shared) {
        Ok(config) => config,
        Err(error) => return fail(error.to_string()),
    };
    let listener = match TcpListener::bind(address) {
        Ok(listener) => listener,
        Err(error) => return fail(error.to_string()),
    };
    {
        let mut state = lock(&shared.listener);
        state.running = true;
        state.address = listener
            .local_addr()
            .ok()
            .map(|a| a.to_string())
            .or(state.address.take());
    }
    if address.is_ipv4() {
        let shared = shared.clone();
        thread::spawn(move || run_discovery(shared, address));
    }
    let active = Arc::new(AtomicUsize::new(0));
    for stream in listener.incoming() {
        let Ok(stream) = stream else { continue };
        if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
            active.fetch_sub(1, Ordering::SeqCst);
            continue;
        }
        let (shared, config, active) = (shared.clone(), config.clone(), active.clone());
        thread::spawn(move || {
            serve_connection(shared, config, stream);
            active.fetch_sub(1, Ordering::SeqCst);
        });
    }
}

/// Discovery reveals only the endpoint of an already named, locally registered identity.
/// The Server must still authenticate the imported key through mutual TLS.
fn run_discovery(shared: Arc<Shared>, address: SocketAddr) {
    // Limited broadcasts are delivered to wildcard UDP sockets on common Linux stacks.
    // Keep a loopback-only TCP listener's discovery endpoint loopback-only as well.
    let discovery_ip = if address.ip().is_loopback() {
        address.ip()
    } else {
        "0.0.0.0".parse().expect("valid IPv4 wildcard")
    };
    let bind = SocketAddr::new(discovery_ip, DISCOVERY_PORT);
    let Ok(socket) = UdpSocket::bind(bind) else {
        return;
    };
    let mut packet = [0u8; 256];
    loop {
        let Ok((length, peer)) = socket.recv_from(&mut packet) else {
            continue;
        };
        let Ok(query) = std::str::from_utf8(&packet[..length]) else {
            continue;
        };
        let Some(device_id) = query.strip_prefix(DISCOVERY_PREFIX) else {
            continue;
        };
        if device_id.len() > 80 || shared.identity_for(device_id).is_none() {
            continue;
        }
        let reply = format!("BARADWATCHU_FOUND_V1 {device_id} {}", address.port());
        let _ = socket.send_to(reply.as_bytes(), peer);
    }
}

// ---------------------------------------------------------------------------------------
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
    let address = load_config(&shared.dir).map_err(CliError)?;
    lock(&shared.listener).address = read_config(&shared.dir)
        .map_err(CliError)?
        .and_then(|config| config.remote.map(|remote| remote.listen));
    let ipc_listener = ipc::Listener::bind()
        .map_err(|_| CliError("Cannot open the local service endpoint".into()))?;
    if let Some(address) = address {
        let shared = shared.clone();
        thread::spawn(move || run_remote_listener(shared, address));
    }
    {
        let shared = shared.clone();
        thread::spawn(move || watchdog(shared));
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

fn restart_system_service() -> Result<(), CliError> {
    #[cfg(target_os = "linux")]
    let mut command = std::process::Command::new("systemctl");
    #[cfg(target_os = "linux")]
    command.args(["restart", "baradwatchu-agent.service"]);
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("launchctl");
    #[cfg(target_os = "macos")]
    command.args(["kickstart", "-k", "system/io.baradwatchu.agent"]);
    #[cfg(windows)]
    let mut command = std::process::Command::new("powershell.exe");
    #[cfg(windows)]
    command.args(["-NoProfile", "-Command", "$s=Get-Service -Name BaradWatchU -ErrorAction Stop; if ($s.Status -eq 'Running') { Restart-Service -Name BaradWatchU -Force -ErrorAction Stop } else { Start-Service -Name BaradWatchU -ErrorAction Stop }"]);
    let output = command
        .output()
        .map_err(|e| CliError(format!("Cannot restart the system service: {e}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "Cannot restart the system service: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(())
}

fn wait_for_listener(enable: bool) -> Result<(), CliError> {
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(ToAgent::Reply {
            ok: true,
            status: Some(status),
            ..
        }) = ipc::call(&ToService::hello(Intent::Status))
        {
            if status.listener_running == enable {
                return Ok(());
            }
            if let Some(error) = status.listener_error {
                return Err(CliError(format!("Listener failed to start: {error}")));
            }
        }
        if std::time::Instant::now() >= deadline {
            return Err(CliError(
                "Listener did not reach the requested state".into(),
            ));
        }
        thread::sleep(Duration::from_millis(200));
    }
}

fn configure_listener(enable: bool, address: Option<&str>) -> Result<CliOutput, CliError> {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } != 0 {
        return Err(CliError("Administrator privileges are required".into()));
    }
    let dir = service_dir();
    if !dir.is_dir() {
        return Err(CliError("System service is not installed".into()));
    }
    let previous = read_config(&dir).map_err(CliError)?;
    let chosen = address.map(str::to_owned).or_else(|| {
        previous
            .as_ref()
            .and_then(|config| config.remote.as_ref().map(|remote| remote.listen.clone()))
    });
    let Some(listen) = chosen else {
        return Err(CliError("Provide an IP:port for the listener".into()));
    };
    let socket = listen
        .parse::<SocketAddr>()
        .map_err(|_| CliError("Provide a valid IP:port for the listener".into()))?;
    if socket.port() == 0 {
        return Err(CliError("Listener port cannot be zero".into()));
    }
    let updated = Config {
        schema_version: CONFIG_SCHEMA.into(),
        remote: Some(RemoteConfig {
            listen,
            enabled: enable,
        }),
    };
    let path = dir.join(CONFIG_FILE);
    req::atomic_json(&path, &updated)?;
    if let Err(error) = restart_system_service().and_then(|_| wait_for_listener(enable)) {
        if let Some(previous) = previous {
            let _ = req::atomic_json(&path, &previous);
        } else {
            let _ = fs::remove_file(&path);
        }
        let _ = restart_system_service();
        return Err(error);
    }
    Ok(CliOutput {
        text: if enable {
            "Remote listener started"
        } else {
            "Remote listener stopped"
        }
        .into(),
        code: 0,
    })
}

/// Ask the operating system for administrator elevation, then run the fixed listener
/// command in the installed agent. No arbitrary command or path comes from the dashboard.
pub(crate) fn request_listener(enable: bool, address: Option<&str>) -> Result<CliOutput, CliError> {
    if let Some(value) = address {
        let parsed = value
            .parse::<SocketAddr>()
            .map_err(|_| CliError("Provide a valid IP:port for the listener".into()))?;
        if parsed.port() == 0 {
            return Err(CliError("Listener port cannot be zero".into()));
        }
    }
    let exe = std::env::current_exe().map_err(|e| CliError(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let mut item = exe.as_path();
        loop {
            let metadata = fs::metadata(item).map_err(|e| CliError(e.to_string()))?;
            if metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
                return Err(CliError(
                    "The installed agent must be root-owned before elevation".into(),
                ));
            }
            let Some(parent) = item.parent() else { break };
            if parent == item {
                break;
            }
            item = parent;
        }
    }
    let operation = if enable { "start" } else { "stop" };
    #[cfg(target_os = "linux")]
    let mut command = {
        let mut command = std::process::Command::new("pkexec");
        command.arg(&exe).args(["service", "listener", operation]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let escaped = |text: &str| format!("'{}'", text.replace('\'', "'\\''"));
        let mut script = format!(
            "{} service listener {operation}",
            escaped(&exe.to_string_lossy())
        );
        if let Some(value) = address {
            script.push(' ');
            script.push_str(&escaped(value));
        }
        let apple = format!(
            "do shell script \"{}\" with administrator privileges",
            script.replace('\\', "\\\\").replace('"', "\\\"")
        );
        let mut command = std::process::Command::new("osascript");
        command.args(["-e", &apple]);
        command
    };
    #[cfg(windows)]
    let mut command = {
        use base64::Engine;
        let quote = |value: &str| format!("'{}'", value.replace('\'', "''"));
        let mut args = vec!["service", "listener", operation];
        if let Some(value) = address {
            args.push(value);
        }
        let script = format!("$ErrorActionPreference='Stop'; $p=Start-Process -Verb RunAs -FilePath {} -ArgumentList @({}) -Wait -PassThru; exit $p.ExitCode", quote(&exe.to_string_lossy()), args.into_iter().map(quote).collect::<Vec<_>>().join(","));
        let utf16: Vec<u8> = script.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let encoded = base64::engine::general_purpose::STANDARD.encode(utf16);
        let mut command = std::process::Command::new("powershell.exe");
        command.args(["-NoProfile", "-EncodedCommand", &encoded]);
        command
    };
    #[cfg(target_os = "linux")]
    if let Some(value) = address {
        command.arg(value);
    }
    let output = command
        .output()
        .map_err(|e| CliError(format!("Administrator prompt failed: {e}")))?;
    if !output.status.success() {
        return Err(CliError(format!(
            "Listener change was not completed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(CliOutput {
        text: if enable {
            "Remote listener started"
        } else {
            "Remote listener stopped"
        }
        .into(),
        code: 0,
    })
}

pub(crate) fn dashboard_set_listener(text: &str) -> Result<String, CliError> {
    let value: serde_json::Value =
        serde_json::from_str(text).map_err(|_| CliError("Invalid listener request".into()))?;
    let object = value
        .as_object()
        .ok_or_else(|| CliError("Invalid listener request".into()))?;
    if object.len() > 2
        || object
            .keys()
            .any(|key| key != "enabled" && key != "address")
    {
        return Err(CliError("Invalid listener request".into()));
    }
    let enabled = object
        .get("enabled")
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| CliError("Invalid listener request".into()))?;
    let address = object
        .get("address")
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty());
    request_listener(enabled, if enabled { address } else { None })?;
    std::thread::sleep(Duration::from_millis(300));
    req::output_json(&crate::remote::status())
}

pub fn run(args: &[OsString]) -> Result<CliOutput, CliError> {
    match args {
        [command, operation] if command == "listener" && operation == "start" => {
            configure_listener(true, None)
        }
        [command, operation, address] if command == "listener" && operation == "start" => {
            configure_listener(
                true,
                Some(
                    address
                        .to_str()
                        .ok_or_else(|| CliError("Invalid listener address".into()))?,
                ),
            )
        }
        [command, operation] if command == "listener" && operation == "stop" => {
            configure_listener(false, None)
        }
        [command, request, operation]
            if command == "listener" && request == "request" && operation == "start" =>
        {
            request_listener(true, None)
        }
        [command, request, operation, address]
            if command == "listener" && request == "request" && operation == "start" =>
        {
            request_listener(
                true,
                Some(
                    address
                        .to_str()
                        .ok_or_else(|| CliError("Invalid listener address".into()))?,
                ),
            )
        }
        [command, request, operation]
            if command == "listener" && request == "request" && operation == "stop" =>
        {
            request_listener(false, None)
        }
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

    #[test]
    fn http_parser_is_strict_and_bounded() {
        let ok = b"POST /v1/audit-requests HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\n{}";
        let request = read_http(&mut &ok[..]).unwrap();
        assert_eq!(
            (request.method.as_str(), request.path.as_str()),
            ("POST", "/v1/audit-requests")
        );
        assert_eq!(request.body, b"{}");
        for bad in [
            &b"GET / HTTP/1.0\r\n\r\n"[..],
            b"GET /\r\n\r\n",
            b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
            b"GET / HTTP/1.1\r\nbroken\r\n\r\n",
        ] {
            assert!(read_http(&mut &bad[..]).is_err());
        }
        let huge = format!(
            "POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n",
            MAX_HTTP_BODY + 1
        );
        assert_eq!(read_http(&mut huge.as_bytes()).err(), Some(413));
    }

    #[test]
    fn listener_is_disabled_until_configured() {
        let dir = std::env::temp_dir().join(format!("bwu-service-config-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        assert_eq!(load_config(&dir).unwrap(), None);
        fs::write(
            dir.join(CONFIG_FILE),
            r#"{"schemaVersion":"baradwatchu.service-config.v1"}"#,
        )
        .unwrap();
        assert_eq!(load_config(&dir).unwrap(), None);
        fs::write(
            dir.join(CONFIG_FILE),
            r#"{"schemaVersion":"baradwatchu.service-config.v1","remote":{"listen":"10.0.0.5:7443"}}"#,
        )
        .unwrap();
        assert_eq!(
            load_config(&dir).unwrap(),
            Some("10.0.0.5:7443".parse().unwrap())
        );
        fs::write(
            dir.join(CONFIG_FILE),
            r#"{"schemaVersion":"x","remote":{"listen":"nope"}}"#,
        )
        .unwrap();
        assert!(load_config(&dir).is_err());
        let _ = fs::remove_dir_all(dir);
    }
}
