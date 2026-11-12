//! Milestone 2: remote audit requests from trusted BaradWatchU Servers.
//!
//! Architecture (README "Remote audit requests", `docs/remote-protocol.md`):
//! - `service run` (service.rs) is the always-on system component: outbound mTLS tunnels,
//!   availability, concurrency, request records. It never audits.
//! - `remote link` (this file) is the per-user agent, started by the tray companion. It
//!   asks the user through the existing consent flow and runs the existing audit engine.
//! - `remote enable|disable|status` are the user's explicit controls.
//!
//! The protocol types and TLS helpers are shared with the outbound service connection.
use crate::consent::{self, ConsentState};
use crate::events;
use crate::identity::{self, IdentityStatus, ProtectionState};
use crate::ipc::{self, Intent, JobServer, JobState, ServiceStatus, ToAgent, ToService};
use crate::requirements::{self as req, CliError, CliOutput};
use serde::{Deserialize, Serialize};
use std::{
    ffi::OsString,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::Duration,
};

pub use crate::ipc::JobState as RequestState;

pub const REQUEST_SCHEMA: &str = "baradwatchu.remote-audit-request.v1";
pub const STATUS_SCHEMA: &str = "baradwatchu.remote-audit-status.v1";
pub const RESULT_SCHEMA: &str = "baradwatchu.remote-audit-result.v1";
pub const ERROR_SCHEMA: &str = "baradwatchu.remote-error.v1";
/// The only operation a Server can ask for.
pub const OPERATION_AUDIT: &str = "AUDIT_REPORT";
/// Seconds the user has to answer, counted from when the consent request is shown.
pub const CONSENT_SECONDS: u64 = 120;
/// `issuedAtUnixMs` may differ from the Client clock by at most this much.
pub const MAX_CLOCK_SKEW_MS: u64 = 5 * 60 * 1000;

/// `POST /v1/audit-requests` body.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditRequest {
    pub schema_version: String,
    /// Chosen by the Server, unique per Server: 8–64 of `A-Z a-z 0-9 . _ -`.
    pub request_id: String,
    pub operation: String,
    pub issued_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<Requester>,
}

/// Descriptive claims supplied by the authenticated Server, never authentication keys.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Requester {
    pub operator_display_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_display_name: Option<String>,
}
impl Requester {
    pub fn valid(&self) -> bool {
        fn text(s: &str) -> bool {
            !s.trim().is_empty() && s.chars().count()<=128 && !s.chars().any(|c| c.is_control() || matches!(c,'\u{200e}'|'\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}'))
        }
        text(&self.operator_display_name)
            && self.server_display_name.as_ref().map_or(true, |s| text(s))
    }
}

/// Status document returned by every remote endpoint.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RequestStatus {
    pub schema_version: String,
    pub request_id: String,
    pub device_id: String,
    pub state: JobState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at_unix_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consent_expires_at_unix_ms: Option<u64>,
    pub result_available: bool,
}

/// `GET /v1/audit-requests/{id}/result` body.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditResult {
    pub schema_version: String,
    pub request_id: String,
    pub device_id: String,
    pub report: serde_json::Value,
}

pub fn valid_request_id(id: &str) -> bool {
    (8..=64).contains(&id.len())
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

/// TLS 1.3 with RFC 7250 raw public keys: each side authenticates with its Ed25519
/// identity key itself, so the key checked against the trust store *is* the key that
/// proved possession in the handshake. No X.509 certificates, no CA, no second chain.
pub mod tls {
    use rustls::{
        client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
        crypto::{ring, verify_tls13_signature_with_raw_key, WebPkiSupportedAlgorithms},
        pki_types::{CertificateDer, ServerName, SubjectPublicKeyInfoDer, UnixTime},
        sign::{CertifiedKey, Signer, SigningKey},
        DigitallySignedStruct, Error, SignatureAlgorithm, SignatureScheme,
    };
    use std::sync::Arc;

    /// DER prefix of an Ed25519 SubjectPublicKeyInfo (RFC 8410), followed by the 32 bytes.
    const ED25519_SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    pub fn spki(public_key: &[u8; 32]) -> Vec<u8> {
        [&ED25519_SPKI_PREFIX[..], public_key].concat()
    }

    /// The Ed25519 key inside a raw-public-key "certificate"; None for anything else.
    pub fn key_from_spki(der: &[u8]) -> Option<[u8; 32]> {
        der.strip_prefix(&ED25519_SPKI_PREFIX[..])?.try_into().ok()
    }

    pub fn provider() -> rustls::crypto::CryptoProvider {
        ring::default_provider()
    }

    pub(crate) fn algorithms() -> WebPkiSupportedAlgorithms {
        provider().signature_verification_algorithms
    }

    /// Verifies a TLS 1.3 CertificateVerify made with the presented raw Ed25519 key.
    pub(crate) fn verify_signature(
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, Error> {
        if dss.scheme != SignatureScheme::ED25519 || key_from_spki(cert.as_ref()).is_none() {
            return Err(Error::General(
                "only Ed25519 raw public keys are accepted".into(),
            ));
        }
        verify_tls13_signature_with_raw_key(
            message,
            &SubjectPublicKeyInfoDer::from(cert.as_ref()),
            dss,
            &algorithms(),
        )
    }

    /// Ed25519 signing key for rustls; never printed.
    pub struct Ed25519Key(Arc<ed25519_dalek::SigningKey>);

    impl Ed25519Key {
        pub fn new(key: ed25519_dalek::SigningKey) -> Self {
            Self(Arc::new(key))
        }

        pub fn certified(self) -> CertifiedKey {
            let public = self.0.verifying_key().to_bytes();
            CertifiedKey::new(vec![CertificateDer::from(spki(&public))], Arc::new(self))
        }
    }

    impl std::fmt::Debug for Ed25519Key {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Ed25519Key(..)")
        }
    }

    impl SigningKey for Ed25519Key {
        fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
            offered
                .contains(&SignatureScheme::ED25519)
                .then(|| Box::new(Ed25519Signer(self.0.clone())) as Box<dyn Signer>)
        }

        fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
            Some(SubjectPublicKeyInfoDer::from(spki(
                &self.0.verifying_key().to_bytes(),
            )))
        }

        fn algorithm(&self) -> SignatureAlgorithm {
            SignatureAlgorithm::ED25519
        }
    }

    struct Ed25519Signer(Arc<ed25519_dalek::SigningKey>);

    impl std::fmt::Debug for Ed25519Signer {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("Ed25519Signer(..)")
        }
    }

    impl Signer for Ed25519Signer {
        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
            use ed25519_dalek::Signer as _;
            Ok(self.0.sign(message).to_bytes().to_vec())
        }

        fn scheme(&self) -> SignatureScheme {
            SignatureScheme::ED25519
        }
    }

    /// Accepts exactly the Server key imported out of band by this user.
    #[derive(Debug)]
    struct PinnedServerKey([u8; 32]);

    impl ServerCertVerifier for PinnedServerKey {
        fn verify_server_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, Error> {
            if intermediates.is_empty() && key_from_spki(end_entity.as_ref()) == Some(self.0) {
                Ok(ServerCertVerified::assertion())
            } else {
                Err(Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure,
                ))
            }
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            Err(Error::General("TLS 1.2 is not supported".into()))
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, Error> {
            verify_signature(message, cert, dss)
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![SignatureScheme::ED25519]
        }

        fn requires_raw_public_keys(&self) -> bool {
            true
        }
    }

    /// TLS configuration for the Client identity connecting to a trusted Server.
    /// Connect with server name = Server ID; the imported key is pinned.
    pub fn requester_config(
        requester_key: ed25519_dalek::SigningKey,
        server_public_key: [u8; 32],
    ) -> Result<Arc<rustls::ClientConfig>, Error> {
        let certified = Arc::new(Ed25519Key::new(requester_key).certified());
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PinnedServerKey(server_public_key)))
            .with_client_cert_resolver(Arc::new(
                rustls::client::AlwaysResolvesClientRawPublicKeys::new(certified),
            ));
        Ok(Arc::new(config))
    }
}

// ---------------------------------------------------------------------------------------
// User agent: `remote link`
// ---------------------------------------------------------------------------------------

const RECONNECT: Duration = Duration::from_secs(5);
const NOT_REGISTERED_RETRY: Duration = Duration::from_secs(30);
const CONSENT_POLL: Duration = Duration::from_millis(300);

/// Consent request of the job in progress, withdrawn if this process is told to stop.
static CURRENT_CONSENT: Mutex<Option<String>> = Mutex::new(None);

fn withdraw_current() {
    if let Some(id) = CURRENT_CONSENT.lock().ok().and_then(|mut slot| slot.take()) {
        let _ = consent::expire_request(&id);
    }
}

fn update(
    job_id: &str,
    state: JobState,
    expires: Option<u64>,
    reason: Option<&str>,
    result: Option<serde_json::Value>,
) -> bool {
    let ToService::Hello {
        protocol, intent, ..
    } = ToService::hello(Intent::Update);
    let message = ToService::Hello {
        protocol,
        intent,
        identity_dir: None,
        client_name: None,
        job_id: Some(job_id.into()),
        state: Some(state),
        consent_expires_at_unix_ms: expires,
        reason: reason.map(str::to_owned),
        result,
        server_id: None,
        endpoint: None,
        action: None,
    };
    matches!(ipc::call(&message), Ok(ToAgent::Reply { ok: true, .. }))
}

/// One remote request, from availability checks to the audit result.
fn handle_job(job_id: String, device_id: String, server: JobServer, disconnected: Arc<AtomicBool>) {
    let refuse = |state, reason: &str| {
        update(&job_id, state, None, Some(reason), None);
    };
    // The consent window lives in the tray: without it nobody can be asked.
    if events::tray_running() == Some(false) {
        return refuse(JobState::Unavailable, "TRAY_NOT_RUNNING");
    }
    let own = identity::public_identity().ok().flatten();
    if own.as_ref().and_then(|own| own.id.as_deref()) != Some(device_id.as_str()) {
        return refuse(JobState::Unavailable, "IDENTITY_CHANGED");
    }
    let requester = server.requester.clone();
    let key = identity::parse_public_key(&server.public_key).map(|key| key.to_bytes());
    let trusted = |key: &[u8; 32]| identity::trusted_server_for_key(key).ok().flatten();
    let Some((key, server)) = key.ok().and_then(|key| trusted(&key).map(|s| (key, s))) else {
        return refuse(JobState::Rejected, "SERVER_NOT_TRUSTED");
    };
    let Ok(Some(_exclusive)) = events::try_audit_lock() else {
        return refuse(JobState::Busy, "AUDIT_IN_PROGRESS");
    };
    let view = match consent::create_remote(&server, &device_id, requester.as_ref()) {
        Ok(view) => view,
        Err(_) => return refuse(JobState::Failed, "CONSENT_UNAVAILABLE"),
    };
    let consent_id = view.request.request_id.clone();
    if let Ok(mut slot) = CURRENT_CONSENT.lock() {
        *slot = Some(consent_id.clone());
    }
    let finish = |state, reason: &str| {
        let _ = consent::expire_request(&consent_id);
        if let Ok(mut slot) = CURRENT_CONSENT.lock() {
            *slot = None;
        }
        update(&job_id, state, None, Some(reason), None);
    };
    if !update(
        &job_id,
        JobState::PendingConsent,
        Some(view.request.expires_at_unix_ms),
        None,
        None,
    ) {
        // The service gave up (timeout, restart): never leave a request it cannot follow.
        return finish(JobState::Failed, "SERVICE_UNREACHABLE");
    }
    loop {
        if disconnected.load(Ordering::SeqCst) {
            return finish(JobState::Failed, "SERVICE_DISCONNECTED");
        }
        match consent::state_of(&consent_id) {
            Ok(Some(ConsentState::Pending)) => thread::sleep(CONSENT_POLL),
            Ok(Some(ConsentState::Accepted)) => break,
            Ok(Some(ConsentState::Rejected)) => return finish(JobState::Rejected, "USER_REJECTED"),
            Ok(Some(ConsentState::Expired)) => return finish(JobState::Expired, "CONSENT_EXPIRED"),
            _ => return finish(JobState::Failed, "CONSENT_UNAVAILABLE"),
        }
    }
    if let Ok(mut slot) = CURRENT_CONSENT.lock() {
        *slot = None;
    }
    // Accepted. Revocation or reset between the answer and now still stops the audit.
    let same_identity = identity::public_identity()
        .ok()
        .flatten()
        .and_then(|own| own.id)
        == Some(device_id.clone());
    if trusted(&key).is_none() || !same_identity {
        return refuse(JobState::Rejected, "SERVER_NOT_TRUSTED");
    }
    if !update(&job_id, JobState::Running, None, None, None) {
        return; // the service no longer follows this request: do not audit for nobody
    }
    let initiator = req::AuditInitiator::Remote {
        operator_display_name: requester.as_ref().map(|r| r.operator_display_name.clone()),
        server_id: server.server_id.clone(),
        server_display_name: requester
            .as_ref()
            .and_then(|r| r.server_display_name.clone())
            .unwrap_or_else(|| server.name.clone()),
        server_trusted_name: server.name.clone(),
        server_fingerprint: server.fingerprint.clone(),
    };
    match req::remote_audit_json(initiator)
        .map(|text| serde_json::from_str::<serde_json::Value>(&text))
    {
        Ok(Ok(report)) => {
            if !update(&job_id, JobState::Completed, None, None, Some(report)) {
                let _ = update(
                    &job_id,
                    JobState::Failed,
                    None,
                    Some("RESULT_REJECTED"),
                    None,
                );
            }
        }
        _ => refuse(JobState::Failed, "AUDIT_FAILED"),
    }
}

enum LinkEnd {
    Disconnected,
    NotRegistered,
}

fn serve_link() -> Result<LinkEnd, std::io::Error> {
    let mut connection = ipc::connect()?;
    connection.set_read_timeout(Some(Duration::from_secs(30)));
    connection.send(&ToService::hello(Intent::Link))?;
    match connection.receive::<ToAgent>()? {
        Some(ToAgent::Reply { ok: true, .. }) => {}
        Some(ToAgent::Reply { error, .. }) if error.as_deref() == Some("NOT_REGISTERED") => {
            return Ok(LinkEnd::NotRegistered)
        }
        _ => return Ok(LinkEnd::Disconnected),
    }
    // The service pings every few seconds: silence means it is gone.
    connection.set_read_timeout(Some(Duration::from_secs(15)));
    let disconnected = Arc::new(AtomicBool::new(false));
    let mut worker: Option<thread::JoinHandle<()>> = None;
    loop {
        match connection.receive::<ToAgent>() {
            Ok(Some(ToAgent::Job {
                job_id,
                device_id,
                server,
            })) => {
                if worker.as_ref().is_some_and(|w| !w.is_finished()) {
                    update(
                        &job_id,
                        JobState::Busy,
                        None,
                        Some("AUDIT_IN_PROGRESS"),
                        None,
                    );
                    continue;
                }
                let flag = disconnected.clone();
                worker = Some(thread::spawn(move || {
                    handle_job(job_id, device_id, server, flag)
                }));
            }
            Ok(Some(ToAgent::Ping)) => {}
            Ok(Some(ToAgent::Reply { .. })) => {}
            Ok(None) | Err(_) => break,
        }
    }
    disconnected.store(true, Ordering::SeqCst);
    if let Some(worker) = worker {
        // A pending consent is withdrawn by the worker; a running audit is let finish
        // (its result stays local, like any audit).
        let _ = worker.join();
    }
    Ok(LinkEnd::Disconnected)
}

fn run_link(watch_stdin: bool) -> Result<CliOutput, CliError> {
    if watch_stdin {
        // Started by the tray with a pipe on stdin: the tray's end (exit, crash, logout)
        // closes it, and this agent must not outlive the consent window it depends on.
        thread::spawn(|| {
            let mut sink = [0u8; 64];
            let mut stdin = std::io::stdin();
            while matches!(std::io::Read::read(&mut stdin, &mut sink), Ok(n) if n > 0) {}
            withdraw_current();
            std::process::exit(0);
        });
    }
    loop {
        let pause = match serve_link() {
            Ok(LinkEnd::NotRegistered) => NOT_REGISTERED_RETRY,
            _ => RECONNECT,
        };
        thread::sleep(pause);
    }
}

// ---------------------------------------------------------------------------------------
// User controls: `remote enable|disable|status`
// ---------------------------------------------------------------------------------------

/// The six states the README distinguishes, as seen by the current user.
#[derive(Debug, Default, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RemoteStatus {
    pub schema_version: &'static str,
    /// None: cannot tell on this platform.
    pub service_installed: Option<bool>,
    pub service_running: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<ServiceStatus>,
    pub identity_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    pub trusted_servers: usize,
    pub tray_running: Option<bool>,
}

fn service_installed() -> Option<bool> {
    #[cfg(target_os = "linux")]
    {
        return Some(
            [
                "/etc/systemd/system/baradwatchu-agent.service",
                "/usr/lib/systemd/system/baradwatchu-agent.service",
                "/lib/systemd/system/baradwatchu-agent.service",
            ]
            .iter()
            .any(|path| std::path::Path::new(path).is_file()),
        );
    }
    #[cfg(target_os = "macos")]
    {
        return Some(
            std::path::Path::new("/Library/LaunchDaemons/io.baradwatchu.agent.plist").is_file(),
        );
    }
    #[cfg(windows)]
    {
        return Some(crate::service::windows_service_installed());
    }
    #[allow(unreachable_code)]
    None
}

pub fn status() -> RemoteStatus {
    let view = identity::view().ok();
    let service = match ipc::call(&ToService::hello(Intent::Status)) {
        Ok(ToAgent::Reply {
            ok: true,
            status: Some(status),
            ..
        }) => Some(status),
        _ => None,
    };
    RemoteStatus {
        schema_version: "baradwatchu.remote-status.v1",
        service_installed: service_installed(),
        service_running: service.is_some(),
        service,
        identity_configured: view
            .as_ref()
            .is_some_and(|v| v.status == IdentityStatus::Configured),
        device_id: view
            .as_ref()
            .and_then(|v| v.identity.as_ref())
            .and_then(|i| i.id.clone()),
        trusted_servers: view.as_ref().map_or(0, |v| v.trust.trusted),
        tray_running: events::tray_running(),
    }
}

fn msg(key: &str) -> String {
    baradwatchu_messages::message(key, baradwatchu_messages::configured_language()).to_owned()
}

fn yes_no(value: bool) -> String {
    msg(if value { "remote.yes" } else { "remote.no" })
}

fn status_text(status: &RemoteStatus) -> String {
    let unknown = msg("remote.unknown");
    let service = status.service.as_ref();
    let connected = service.map_or(unknown.clone(), |service| {
        service
            .connections
            .iter()
            .filter(|connection| connection.connected)
            .count()
            .to_string()
    });
    let registered = match service {
        Some(s) if s.registered => match &s.registration_problem {
            Some(problem) => msg("remote.registered.stale").replace(
                "{problem}",
                &baradwatchu_messages::localize_diagnostic(
                    problem,
                    baradwatchu_messages::configured_language(),
                ),
            ),
            None => msg("remote.registered.yes")
                .replace("{id}", s.registered_device_id.as_deref().unwrap_or("")),
        },
        Some(_) => msg("remote.registered.no"),
        None => unknown.clone(),
    };
    msg("remote.status")
        .replace(
            "{installed}",
            &status.service_installed.map_or(unknown.clone(), yes_no),
        )
        .replace("{running}", &yes_no(status.service_running))
        .replace("{connections}", &connected)
        .replace(
            "{identity}",
            &status
                .device_id
                .clone()
                .filter(|_| status.identity_configured)
                .unwrap_or_else(|| msg("remote.no")),
        )
        .replace("{servers}", &status.trusted_servers.to_string())
        .replace("{registered}", &registered)
        .replace(
            "{session}",
            &service.map_or(unknown.clone(), |s| yes_no(s.session_linked)),
        )
        .replace("{tray}", &status.tray_running.map_or(unknown, yes_no))
}

fn service_error(error: std::io::Error) -> CliError {
    if error.kind() == std::io::ErrorKind::PermissionDenied {
        CliError("The local service endpoint is not owned by the system".into())
    } else {
        CliError("The BaradWatchU service is not reachable: install and start it first".into())
    }
}

fn reply_result(reply: std::io::Result<ToAgent>) -> Result<(), CliError> {
    match reply.map_err(service_error)? {
        ToAgent::Reply { ok: true, .. } => Ok(()),
        ToAgent::Reply { error, .. } => {
            Err(CliError(error.unwrap_or_else(|| {
                "The service refused the request".into()
            })))
        }
        _ => Err(CliError("Unexpected answer from the service".into())),
    }
}

fn enable() -> Result<CliOutput, CliError> {
    let view = identity::view()?;
    if view.status != IdentityStatus::Configured {
        return Err(CliError(
            "No local identity: generate one with identity generate".into(),
        ));
    }
    if view
        .protection
        .as_ref()
        .is_some_and(|p| p.state == ProtectionState::TooOpen)
    {
        return Err(CliError(
            "Identity key files are accessible to other users: signing refused".into(),
        ));
    }
    let ToService::Hello {
        protocol, intent, ..
    } = ToService::hello(Intent::Register);
    let dir = identity::identity_dir()?;
    let dir = std::fs::canonicalize(&dir).unwrap_or(dir);
    reply_result(ipc::call(&ToService::Hello {
        protocol,
        intent,
        identity_dir: Some(dir.to_string_lossy().into_owned()),
        client_name: view
            .identity
            .as_ref()
            .and_then(|identity| identity.name.clone()),
        job_id: None,
        state: None,
        consent_expires_at_unix_ms: None,
        reason: None,
        result: None,
        server_id: None,
        endpoint: None,
        action: None,
    }))?;
    Ok(CliOutput {
        text: msg("remote.enabled").replace(
            "{id}",
            view.identity
                .as_ref()
                .and_then(|i| i.id.as_deref())
                .unwrap_or(""),
        ) + "\n\n"
            + &status_text(&status()),
        code: 0,
    })
}

fn disable() -> Result<CliOutput, CliError> {
    reply_result(ipc::call(&ToService::hello(Intent::Unregister)))?;
    Ok(CliOutput {
        text: msg("remote.disabled"),
        code: 0,
    })
}

/// Dashboard control for this OS-authenticated user's registration only.
pub(crate) fn dashboard_set_registration(text: &str) -> Result<String, CliError> {
    let value: serde_json::Value = serde_json::from_str(text)
        .map_err(|_| CliError("Invalid remote registration request".into()))?;
    let enabled = value
        .as_object()
        .filter(|object| object.len() == 1)
        .and_then(|object| object.get("enabled"))
        .and_then(serde_json::Value::as_bool)
        .ok_or_else(|| CliError("Invalid remote registration request".into()))?;
    if enabled {
        enable()?;
    } else {
        disable()?;
    }
    crate::requirements::output_json(&status())
}

/// Changes only the connection belonging to this authenticated local user.
pub(crate) fn dashboard_connection(text: &str) -> Result<String, CliError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase", deny_unknown_fields)]
    struct Change {
        server_id: String,
        action: String,
        endpoint: Option<String>,
    }
    let change: Change = serde_json::from_str(text)
        .map_err(|_| CliError("Invalid Server connection request".into()))?;
    let ToService::Hello {
        protocol, intent, ..
    } = ToService::hello(Intent::Connection);
    reply_result(ipc::call(&ToService::Hello {
        protocol,
        intent,
        identity_dir: None,
        client_name: None,
        job_id: None,
        state: None,
        consent_expires_at_unix_ms: None,
        reason: None,
        result: None,
        server_id: Some(change.server_id),
        endpoint: change.endpoint,
        action: Some(change.action),
    }))?;
    req::output_json(&status())
}

fn usage() -> String {
    msg("remote.usage")
}

pub fn run(args: &[OsString]) -> Result<CliOutput, CliError> {
    let args: Vec<&str> = args.iter().map(|a| a.to_str().unwrap_or("\u{0}")).collect();
    match args.as_slice() {
        ["enable"] => enable(),
        ["disable"] => disable(),
        ["status"] => Ok(CliOutput {
            text: status_text(&status()),
            code: 0,
        }),
        ["status", "--json"] => Ok(CliOutput {
            text: req::output_json(&status())?,
            code: 0,
        }),
        ["link"] => run_link(false),
        ["link", "--watch-stdin"] => run_link(true),
        _ => Err(CliError(usage())),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn requester_metadata_is_optional_and_cannot_disguise_the_prompt() {
        let old = r#"{"schemaVersion":"baradwatchu.remote-audit-request.v1","requestId":"legacy-001","operation":"AUDIT_REPORT","issuedAtUnixMs":1}"#;
        let request: super::AuditRequest = serde_json::from_str(old).unwrap();
        assert!(request.requester.is_none());
        let mut r = super::Requester {
            operator_display_name: "Mario Rossi".into(),
            server_display_name: Some("Company Server".into()),
        };
        assert!(r.valid());
        for name in ["", "Mario\nApprove", "Mario\u{202e}Approve"] {
            r.operator_display_name = name.into();
            assert!(!r.valid());
        }
    }

    use super::*;

    #[test]
    fn request_ids_are_bounded_and_plain() {
        assert!(valid_request_id("req-2026.11_10"));
        assert!(!valid_request_id("short"));
        assert!(!valid_request_id(&"a".repeat(65)));
        assert!(!valid_request_id("../../etc/passwd"));
        assert!(!valid_request_id("id with space"));
    }

    #[test]
    fn raw_public_key_encoding_round_trips() {
        let key = [7u8; 32];
        let der = tls::spki(&key);
        assert_eq!(der.len(), 44);
        assert_eq!(tls::key_from_spki(&der), Some(key));
        assert_eq!(tls::key_from_spki(&der[..43]), None);
        let mut other = der.clone();
        other[8] = 0x71; // Ed448 OID
        assert_eq!(tls::key_from_spki(&other), None);
    }
}
