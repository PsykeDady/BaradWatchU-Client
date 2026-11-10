//! Milestone 2 end-to-end tests: the real `service run`, `remote link` and CLI binaries in
//! isolated folders, with a small harness standing in for the remote Server (mutual TLS
//! with raw Ed25519 keys, see `remote::tls`). Linux/Unix only: the service endpoint is a
//! Unix socket and the tray is recognized through `/proc`.
#![cfg(target_os = "linux")]
use baradwatchu_agent::{identity, remote};
use ed25519_dalek::SigningKey;
use serde_json::{json, Value};
use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};

const SERVER_SEED: [u8; 32] = [11; 32];
const OTHER_SEED: [u8; 32] = [22; 32];

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

struct Fixture {
    root: PathBuf,
    service: Option<Child>,
    link: Option<Child>,
    tray: Option<Child>,
    address: SocketAddr,
    device_id: String,
    client_key: [u8; 32],
}

impl Drop for Fixture {
    fn drop(&mut self) {
        for child in [&mut self.link, &mut self.tray, &mut self.service]
            .into_iter()
            .flatten()
        {
            let _ = child.kill();
            let _ = child.wait();
        }
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

fn wait_until(what: &str, timeout: Duration, mut check: impl FnMut() -> bool) {
    let deadline = Instant::now() + timeout;
    while !check() {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn server_document(key: &SigningKey, name: &str) -> Value {
    let public = key.verifying_key().to_bytes();
    json!({
        "schemaVersion": identity::PUBLIC_IDENTITY_SCHEMA,
        "role": "server",
        "name": name,
        "algorithm": "Ed25519",
        "publicKey": identity::encode_public_key(&public),
        "fingerprint": identity::fingerprint(&public),
    })
}

impl Fixture {
    fn agent(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_baradwatchu-agent"));
        command
            .env("XDG_CONFIG_HOME", self.root.join("config"))
            .env("XDG_STATE_HOME", self.root.join("state"))
            .env("XDG_CACHE_HOME", self.root.join("cache"))
            .env("XDG_RUNTIME_DIR", self.root.join("run"))
            .env("BARADWATCHU_SERVICE_DIR", self.root.join("service"))
            .env(
                "BARADWATCHU_SERVICE_SOCKET",
                self.root.join("sock/agent.sock"),
            )
            .env("LC_ALL", "en_US.UTF-8")
            .stdin(Stdio::null());
        command
    }

    fn run(&self, args: &[&str]) -> (i32, String, String) {
        let output = self.agent().args(args).output().unwrap();
        (
            output.status.code().unwrap_or(-1),
            String::from_utf8_lossy(&output.stdout).into_owned(),
            String::from_utf8_lossy(&output.stderr).into_owned(),
        )
    }

    fn ok(&self, args: &[&str]) -> String {
        let (code, out, err) = self.run(args);
        assert_eq!(code, 0, "{args:?}: {out}{err}");
        out
    }

    /// Identity, one trusted Server, fast audit (built-in checks disabled), service with a
    /// loopback listener, remote requests enabled. No tray, no link yet.
    fn new(label: &str) -> Self {
        let root = std::env::temp_dir().join(format!(
            "bwu-remote-{label}-{}-{}",
            std::process::id(),
            now_ms() % 1_000_000
        ));
        std::fs::create_dir_all(root.join("config/baradwatchu")).unwrap();
        std::fs::write(
            root.join("config/baradwatchu/language.json"),
            r#"{"schemaVersion":"baradwatchu.language.v1","language":"english"}"#,
        )
        .unwrap();
        let mut fixture = Self {
            root,
            service: None,
            link: None,
            tray: None,
            address: "127.0.0.1:1".parse().unwrap(),
            device_id: String::new(),
            client_key: [0; 32],
        };
        fixture.ok(&["identity", "generate", "--yes"]);
        let export: Value = serde_json::from_str(&fixture.ok(&["identity", "export"])).unwrap();
        fixture.device_id = export["id"].as_str().unwrap().to_owned();
        fixture.client_key = identity::parse_public_key(export["publicKey"].as_str().unwrap())
            .unwrap()
            .to_bytes();
        for n in 1..=9 {
            fixture.ok(&["disable", &format!("REQ-00{n}")]);
        }
        fixture.trust(&SigningKey::from_bytes(&SERVER_SEED), "Server Test");
        std::fs::create_dir_all(fixture.root.join("service")).unwrap();
        std::fs::write(
            fixture.root.join("service/service.json"),
            r#"{"schemaVersion":"baradwatchu.service-config.v1","remote":{"listen":"127.0.0.1:0"}}"#,
        )
        .unwrap();
        fixture.start_service();
        let out = fixture.ok(&["remote", "enable"]);
        assert!(out.contains(&fixture.device_id), "{out}");
        fixture
    }

    fn trust(&self, key: &SigningKey, name: &str) {
        let document = server_document(key, name);
        let file = self.root.join(format!("{name}.json").replace(' ', "-"));
        std::fs::write(&file, document.to_string()).unwrap();
        self.ok(&[
            "trust",
            "import",
            file.to_str().unwrap(),
            "--fingerprint",
            document["fingerprint"].as_str().unwrap(),
        ]);
    }

    fn status(&self) -> Value {
        serde_json::from_str(&self.ok(&["remote", "status", "--json"])).unwrap()
    }

    fn start_service(&mut self) {
        let child = self
            .agent()
            .args(["service", "run"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.service = Some(child);
        wait_until("service", Duration::from_secs(10), || {
            self.status()["serviceRunning"] == true
        });
        if let Some(address) = self.status()["service"]["listenerAddress"].as_str() {
            if self.status()["service"]["listenerRunning"] == true {
                self.address = address.parse().unwrap();
            }
        }
    }

    fn stop_service(&mut self) {
        if let Some(mut child) = self.service.take() {
            child.kill().unwrap();
            child.wait().unwrap();
        }
    }

    /// A process whose name is `baradwatchu-tray`, recorded like the real tray does.
    fn start_tray(&mut self) {
        let fake = self.root.join("baradwatchu-tray");
        std::fs::copy("/usr/bin/sleep", &fake).unwrap();
        // A copy just written may be briefly "busy" while another test thread forks.
        let mut attempts = 0;
        let child = loop {
            match Command::new(&fake).arg("600").spawn() {
                Ok(child) => break child,
                Err(error) if error.raw_os_error() == Some(26) && attempts < 50 => {
                    attempts += 1;
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => panic!("{error}"),
            }
        };
        let dir = self.root.join("run/baradwatchu");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("tray.lock"), child.id().to_string()).unwrap();
        self.tray = Some(child);
    }

    fn start_link(&mut self) {
        let child = self
            .agent()
            .args(["remote", "link", "--watch-stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        self.link = Some(child);
        wait_until("link", Duration::from_secs(10), || {
            self.status()["service"]["sessionLinked"] == true
        });
    }

    fn stop_link(&mut self) {
        if let Some(mut child) = self.link.take() {
            drop(child.stdin.take()); // as when the tray exits
            wait_until("link exit", Duration::from_secs(10), || {
                child.try_wait().unwrap().is_some()
            });
        }
    }

    fn https(&self, key: &SigningKey, sni: &str, request: &str) -> Result<(u16, Value), String> {
        https_with(self.address, sni, self.client_key, key, request)
    }

    fn post(&self, key: &SigningKey, request_id: &str) -> (u16, Value) {
        let body = json!({
            "schemaVersion": remote::REQUEST_SCHEMA,
            "requestId": request_id,
            "operation": remote::OPERATION_AUDIT,
            "issuedAtUnixMs": now_ms(),
        })
        .to_string();
        self.https(key, &self.device_id, &post_request(&body))
            .unwrap()
    }

    fn get(&self, key: &SigningKey, path: &str) -> (u16, Value) {
        self.https(
            key,
            &self.device_id,
            &format!("GET {path} HTTP/1.1\r\nHost: client\r\n\r\n"),
        )
        .unwrap()
    }

    fn wait_state(&self, key: &SigningKey, id: &str, state: &str) -> Value {
        let mut last = Value::Null;
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            let (_, body) = self.get(key, &format!("/v1/audit-requests/{id}"));
            if body["state"] == state {
                return body;
            }
            last = body;
            std::thread::sleep(Duration::from_millis(200));
        }
        panic!("request {id} never reached {state}; last {last}");
    }

    fn consents(&self) -> Vec<Value> {
        let list: Value = serde_json::from_str(&self.ok(&["consent", "list", "--json"])).unwrap();
        list.as_array().unwrap().clone()
    }

    fn pending_remote(&self) -> Value {
        let mut found = None;
        wait_until("pending consent", Duration::from_secs(10), || {
            found = self
                .consents()
                .into_iter()
                .find(|c| c["state"] == "PENDING" && c["source"] == "REMOTE_SERVER");
            found.is_some()
        });
        found.unwrap()
    }
}

fn post_request(body: &str) -> String {
    format!(
        "POST /v1/audit-requests HTTP/1.1\r\nHost: client\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

/// The Server stand-in: one HTTP/1.1 exchange over mutual TLS.
fn https_with(
    address: SocketAddr,
    sni: &str,
    client_key: [u8; 32],
    key: &SigningKey,
    request: &str,
) -> Result<(u16, Value), String> {
    let config =
        remote::tls::requester_config(key.clone(), client_key).map_err(|e| e.to_string())?;
    let name = rustls::pki_types::ServerName::try_from(sni.to_ascii_lowercase())
        .map_err(|e| e.to_string())?;
    let connection = rustls::ClientConnection::new(config, name).map_err(|e| e.to_string())?;
    let tcp = TcpStream::connect(address).map_err(|e| e.to_string())?;
    tcp.set_read_timeout(Some(Duration::from_secs(30))).unwrap();
    let mut stream = rustls::StreamOwned::new(connection, tcp);
    stream
        .write_all(request.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())?;
    let mut response = Vec::new();
    stream
        .read_to_end(&mut response)
        .map_err(|e| e.to_string())?;
    let text = String::from_utf8(response).map_err(|e| e.to_string())?;
    let (head, body) = text.split_once("\r\n\r\n").ok_or("no HTTP response")?;
    let status = head
        .split(' ')
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or("bad status line")?;
    Ok((status, serde_json::from_str(body).unwrap_or(Value::Null)))
}

fn server() -> SigningKey {
    SigningKey::from_bytes(&SERVER_SEED)
}

#[test]
fn accepted_consent_runs_one_audit_and_only_the_requester_gets_the_result() {
    let mut f = Fixture::new("accept");
    f.start_tray();
    f.start_link();
    let named_request = json!({"schemaVersion":remote::REQUEST_SCHEMA,"requestId":"req-accept-0001","operation":remote::OPERATION_AUDIT,"issuedAtUnixMs":now_ms(),"requester":{"operatorDisplayName":"Mario Rossi","serverDisplayName":"Company Server"}});
    let (code, body) = f
        .https(
            &server(),
            &f.device_id,
            &post_request(&named_request.to_string()),
        )
        .unwrap();
    assert_eq!(code, 202, "{body}");
    assert_eq!(body["state"], "PENDING_CONSENT");
    let deadline = body["consentExpiresAtUnixMs"].as_u64().unwrap();
    let remaining = deadline.saturating_sub(now_ms());
    assert!(
        (110_000..=121_000).contains(&remaining),
        "120 s from the prompt: {remaining}"
    );
    // The prompt names the Server and the operation.
    let consent = f.pending_remote();
    let prompt = consent["prompt"].as_str().unwrap();
    assert!(
        prompt.contains("Server Test") && prompt.contains("audit"),
        "{prompt}"
    );
    assert!(prompt.contains(&identity::fingerprint(&server().verifying_key().to_bytes())));
    assert!(prompt.contains("Mario Rossi") && prompt.contains("Company Server"));
    // Not decided yet: no result.
    let (code, _) = f.get(&server(), "/v1/audit-requests/req-accept-0001/result");
    assert_eq!(code, 409);
    // While the consent is pending the Client is busy: local audits and other requests.
    let (code, _, err) = f.run(&["audit", "--json"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("in progress"), "{err}");
    let (code, body) = f.post(&server(), "req-accept-0002");
    assert_eq!((code, body["state"].as_str()), (409, Some("BUSY")));
    // A retransmission is the same request, not a new one.
    let (code, body) = f.post(&server(), "req-accept-0001");
    assert_eq!(
        (code, body["state"].as_str()),
        (200, Some("PENDING_CONSENT"))
    );
    // The user accepts in the consent window.
    f.ok(&[
        "consent",
        "accept",
        consent["requestId"].as_str().unwrap(),
        "--via",
        "window",
    ]);
    f.wait_state(&server(), "req-accept-0001", "COMPLETED");
    let (code, result) = f.get(&server(), "/v1/audit-requests/req-accept-0001/result");
    assert_eq!(code, 200, "{result}");
    assert_eq!(result["schemaVersion"], remote::RESULT_SCHEMA);
    assert_eq!(result["deviceId"], f.device_id.as_str());
    assert!(result["report"]["results"].is_array(), "{result}");
    assert_eq!(result["report"]["initiator"]["origin"], "REMOTE");
    assert_eq!(
        result["report"]["initiator"]["operatorDisplayName"],
        "Mario Rossi"
    );
    assert_eq!(
        result["report"]["initiator"]["serverId"],
        identity::server_id(&server().verifying_key().to_bytes())
    );
    let stamp = result["report"]["completedAtUnixMs"].as_u64().unwrap();
    let cached: Value = serde_json::from_slice(
        &std::fs::read(
            f.root
                .join(format!("cache/baradwatchu/audit/reports/{stamp}.json")),
        )
        .unwrap(),
    )
    .unwrap();
    assert_eq!(cached["initiator"], result["report"]["initiator"]);
    let pdf_path = result["report"]["pdf"]["path"].as_str().unwrap();
    let pdf = std::fs::read(pdf_path).unwrap();
    assert!(String::from_utf8_lossy(&pdf).contains("Mario Rossi"));
    // Exactly one consent request and one audit for all the calls above.
    let remote_consents = f
        .consents()
        .into_iter()
        .filter(|c| c["source"] == "REMOTE_SERVER")
        .count();
    assert_eq!(remote_consents, 1);
    // Replay after completion: the stored outcome, never a second execution.
    let (code, body) = f.post(&server(), "req-accept-0001");
    assert_eq!((code, body["state"].as_str()), (200, Some("COMPLETED")));
    assert_eq!(
        f.consents()
            .iter()
            .filter(|c| c["source"] == "REMOTE_SERVER")
            .count(),
        1
    );
    // Another trusted Server cannot see this request or its result.
    let other = SigningKey::from_bytes(&OTHER_SEED);
    f.trust(&other, "Other Server");
    let (code, _) = f.get(&other, "/v1/audit-requests/req-accept-0001/result");
    assert_eq!(code, 404);
    // The Client is free again.
    f.ok(&["audit", "--json"]);
    // Nothing secret is served: no private key material anywhere in the answers.
    let private = std::fs::read_dir(f.root.join("state/baradwatchu/identity"))
        .unwrap()
        .filter_map(Result::ok)
        .find(|e| e.file_name().to_string_lossy().starts_with("key-"))
        .map(|e| std::fs::read_to_string(e.path().join("private.key")).unwrap())
        .unwrap();
    let seed: Value = serde_json::from_str(&private).unwrap();
    let seed = seed["seed"].as_str().unwrap();
    assert!(!result.to_string().contains(seed));
    assert!(!f.ok(&["remote", "status", "--json"]).contains(seed));
}

#[test]
fn rejection_expiry_and_late_acceptance_never_run_an_audit() {
    let mut f = Fixture::new("reject");
    f.start_tray();
    f.start_link();
    // Rejected by the user.
    assert_eq!(f.post(&server(), "req-reject-0001").0, 202);
    let consent = f.pending_remote();
    f.ok(&[
        "consent",
        "reject",
        consent["requestId"].as_str().unwrap(),
        "--via",
        "window",
    ]);
    let body = f.wait_state(&server(), "req-reject-0001", "REJECTED");
    assert_eq!(body["resultAvailable"], false);
    assert_eq!(
        f.get(&server(), "/v1/audit-requests/req-reject-0001/result")
            .0,
        409
    );
    // Screen locked / user away: nothing happens until the deadline; a late answer within
    // the deadline still counts (here after a few seconds).
    assert_eq!(f.post(&server(), "req-late-00001").0, 202);
    let consent = f.pending_remote();
    std::thread::sleep(Duration::from_secs(3));
    assert_eq!(
        f.wait_state(&server(), "req-late-00001", "PENDING_CONSENT")["state"],
        "PENDING_CONSENT"
    );
    f.ok(&["consent", "accept", consent["requestId"].as_str().unwrap()]);
    f.wait_state(&server(), "req-late-00001", "COMPLETED");
    // Deadline reached (clock moved past `expiresAtUnixMs`): EXPIRED, accept refused.
    assert_eq!(f.post(&server(), "req-expire-001").0, 202);
    let consent = f.pending_remote();
    let id = consent["requestId"].as_str().unwrap().to_owned();
    let file = f.root.join(format!("state/baradwatchu/consent/{id}.json"));
    let mut record: Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    record["expiresAtUnixMs"] = json!(now_ms() - 1);
    std::fs::write(&file, record.to_string()).unwrap();
    f.wait_state(&server(), "req-expire-001", "EXPIRED");
    let (code, _, err) = f.run(&["consent", "accept", &id]);
    assert_eq!(code, 2, "{err}");
    // The concurrency slot is free again.
    assert_eq!(f.post(&server(), "req-after-0001").0, 202);
}

#[test]
fn unavailable_without_session_or_tray_and_busy_with_a_local_audit() {
    let mut f = Fixture::new("avail");
    // Registered, no linked session (nobody logged in): UNAVAILABLE, nothing stored.
    let (code, body) = f.post(&server(), "req-nosession1");
    assert_eq!((code, body["state"].as_str()), (503, Some("UNAVAILABLE")));
    assert_eq!(body["reason"], "NO_USER_SESSION");
    assert_eq!(f.get(&server(), "/v1/audit-requests/req-nosession1").0, 404);
    // Session linked but no tray (no consent window): UNAVAILABLE.
    f.start_link();
    let (code, body) = f.post(&server(), "req-notray-001");
    assert_eq!((code, body["state"].as_str()), (503, Some("UNAVAILABLE")));
    assert_eq!(body["reason"], "TRAY_NOT_RUNNING");
    assert!(f.consents().is_empty());
    // Tray up, but a local audit holds the audit lock: BUSY, no consent prompt.
    f.start_tray();
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(f.root.join("state/baradwatchu/.audit.lock"))
        .unwrap();
    use std::os::unix::io::AsRawFd;
    assert_eq!(unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX) }, 0);
    let (code, body) = f.post(&server(), "req-localbusy1");
    assert_eq!((code, body["state"].as_str()), (409, Some("BUSY")));
    assert_eq!(body["reason"], "AUDIT_IN_PROGRESS");
    drop(lock);
    // The same request ID may be retried once the Client is free.
    assert_eq!(f.post(&server(), "req-localbusy1").0, 202);
    // The tray goes away (logout): the link stops, pending consent is withdrawn.
    f.stop_link();
    wait_until("unlinked", Duration::from_secs(15), || {
        f.status()["service"]["sessionLinked"] == false
    });
    let body = f.wait_state(&server(), "req-localbusy1", "FAILED");
    assert_eq!(body["resultAvailable"], false);
    assert!(f.consents().iter().all(|c| c["state"] != "PENDING"));
    let (code, body) = f.post(&server(), "req-afterlogout");
    assert_eq!((code, body["state"].as_str()), (503, Some("UNAVAILABLE")));
}

#[test]
fn unknown_revoked_and_mismatched_keys_are_refused_by_the_handshake() {
    let mut f = Fixture::new("auth");
    f.start_tray();
    f.start_link();
    let request = "GET /v1/audit-requests/req-unknown01 HTTP/1.1\r\nHost: c\r\n\r\n";
    // Unknown Server key.
    let stranger = SigningKey::from_bytes(&[33; 32]);
    assert!(f.https(&stranger, &f.device_id, request).is_err());
    // Wrong device name (SNI): no key is presented for unregistered names.
    assert!(f
        .https(&server(), "BWU-0000-0000-0000-0000", request)
        .is_err());
    // The Server expects a different Client key: the Server side refuses the handshake.
    let wrong = https_with(f.address, &f.device_id, [9; 32], &server(), request);
    assert!(wrong.is_err());
    // Dashboard endpoints do not exist on the remote listener.
    for path in ["/api/identity", "/api/trust/clear", "/api/audit", "/"] {
        let (code, _) = f.get(&server(), path);
        assert_eq!(code, 404, "{path}");
    }
    // Stale or malformed requests.
    let stale = json!({"schemaVersion": remote::REQUEST_SCHEMA, "requestId": "req-stale-0001",
        "operation": remote::OPERATION_AUDIT, "issuedAtUnixMs": now_ms() - 3_600_000})
    .to_string();
    let (code, body) = f
        .https(&server(), &f.device_id, &post_request(&stale))
        .unwrap();
    assert_eq!((code, body["error"].as_str()), (400, Some("STALE_REQUEST")));
    let other_op = json!({"schemaVersion": remote::REQUEST_SCHEMA, "requestId": "req-op-000001",
        "operation": "RUN_COMMAND", "issuedAtUnixMs": now_ms()})
    .to_string();
    assert_eq!(
        f.https(&server(), &f.device_id, &post_request(&other_op))
            .unwrap()
            .0,
        400
    );
    // Revocation while a consent is pending: the request dies, the Server is cut off.
    assert_eq!(f.post(&server(), "req-revoke-001").0, 202);
    let consent = f.pending_remote();
    let server_id = identity::server_id(&server().verifying_key().to_bytes());
    f.ok(&["trust", "revoke", &server_id, "--yes"]);
    assert!(f.https(&server(), &f.device_id, request).is_err());
    let (code, _, _) = f.run(&["consent", "accept", consent["requestId"].as_str().unwrap()]);
    assert_eq!(code, 2, "a revoked Server's request cannot be accepted");
    // Another trusted Server can work again once the slot is released.
    let other = SigningKey::from_bytes(&OTHER_SEED);
    f.trust(&other, "Other Server");
    wait_until("slot released", Duration::from_secs(20), || {
        f.status()["service"]["requestInProgress"] == false
    });
    assert_eq!(f.post(&other, "req-other-0001").0, 202);
    // `trust clear` cuts every Server off and withdraws the pending request.
    f.ok(&["trust", "clear", "--yes"]);
    assert!(f.https(&other, &f.device_id, request).is_err());
    wait_until("withdrawn", Duration::from_secs(10), || {
        f.consents().iter().all(|c| c["state"] != "PENDING")
    });
}

#[test]
fn identity_reset_and_service_restart_never_resume_or_repeat_a_request() {
    let mut f = Fixture::new("restart");
    f.start_tray();
    f.start_link();
    assert_eq!(f.post(&server(), "req-restart-01").0, 202);
    f.pending_remote();
    // Service stops with a request pending: the user agent withdraws the consent.
    f.stop_service();
    wait_until("withdrawn", Duration::from_secs(30), || {
        f.consents().iter().all(|c| c["state"] != "PENDING")
    });
    f.start_service();
    // The record survives as FAILED; the same ID is never executed again.
    let body = f.wait_state(&server(), "req-restart-01", "FAILED");
    assert_eq!(body["reason"], "SERVICE_RESTARTED");
    let (code, body) = f.post(&server(), "req-restart-01");
    assert_eq!((code, body["state"].as_str()), (200, Some("FAILED")));
    // The link reconnects by itself.
    wait_until("relinked", Duration::from_secs(20), || {
        f.status()["service"]["sessionLinked"] == true
    });
    // A Server disconnecting mid-request does not disturb the service.
    let mut tcp = TcpStream::connect(f.address).unwrap();
    tcp.write_all(b"\x16\x03\x01\x00").unwrap();
    drop(tcp);
    assert_eq!(f.post(&server(), "req-restart-02").0, 202);
    // Identity reset: the pending request expires, the old key no longer answers, and the
    // registration must be renewed explicitly (no implicit re-registration).
    f.ok(&["identity", "reset", "--yes"]);
    wait_until("expired", Duration::from_secs(10), || {
        f.consents().iter().all(|c| c["state"] != "PENDING")
    });
    let request = "GET /v1/audit-requests/req-restart-02 HTTP/1.1\r\nHost: c\r\n\r\n";
    assert!(f.https(&server(), &f.device_id, request).is_err());
    let status = f.status();
    assert!(
        status["service"]["registrationProblem"].is_string(),
        "{status}"
    );
    // The registration file holds no key material.
    let registration = std::fs::read_dir(f.root.join("service/users"))
        .unwrap()
        .filter_map(Result::ok)
        .map(|e| std::fs::read_to_string(e.path()).unwrap())
        .collect::<String>();
    assert!(!registration.contains("seed") && !registration.contains("publicKey"));
}

#[test]
fn registration_is_explicit_and_bound_to_the_owner() {
    let f = Fixture::new("register");
    // Remote requests are refused once disabled; the link is told it is not registered.
    f.ok(&["remote", "disable"]);
    let request = "GET /v1/audit-requests/req-x-000001 HTTP/1.1\r\nHost: c\r\n\r\n";
    assert!(f.https(&server(), &f.device_id, request).is_err());
    let (code, _, _) = f.run(&["remote", "disable"]);
    assert_eq!(code, 2);
    // Folder permissions loosened: registration refused (keys must be owner-only).
    let dir = f.root.join("state/baradwatchu/identity");
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let (code, _, err) = f.run(&["remote", "enable"]);
    assert_eq!(code, 2, "{err}");
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    f.ok(&["remote", "enable"]);
    assert!(f.https(&server(), &f.device_id, request).is_ok());
    // Without identity the command explains what to do; the service is never asked to
    // create one.
    let empty = Fixture {
        root: f.root.join("empty"),
        service: None,
        link: None,
        tray: None,
        address: f.address,
        device_id: String::new(),
        client_key: [0; 32],
    };
    std::fs::create_dir_all(empty.root.join("config/baradwatchu")).unwrap();
    let (code, _, err) = empty.run(&["remote", "enable"]);
    assert_eq!(code, 2, "{err}");
    assert!(err.contains("identity generate"), "{err}");
}

/// Real 120-second deadline (slow; run with `cargo test -- --ignored`).
#[test]
#[ignore]
fn consent_expires_after_120_real_seconds() {
    let mut f = Fixture::new("timeout");
    f.start_tray();
    f.start_link();
    let started = Instant::now();
    assert_eq!(f.post(&server(), "req-realtime01").0, 202);
    let consent = f.pending_remote();
    std::thread::sleep(Duration::from_secs(110));
    assert_eq!(
        f.get(&server(), "/v1/audit-requests/req-realtime01").1["state"],
        "PENDING_CONSENT"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let (_, body) = f.get(&server(), "/v1/audit-requests/req-realtime01");
        if body["state"] == "EXPIRED" {
            break;
        }
        assert!(Instant::now() < deadline, "{body}");
        std::thread::sleep(Duration::from_millis(250));
    }
    let elapsed = started.elapsed().as_secs();
    assert!((119..=125).contains(&elapsed), "{elapsed}");
    let (code, _, _) = f.run(&["consent", "accept", consent["requestId"].as_str().unwrap()]);
    assert_eq!(code, 2);
}
