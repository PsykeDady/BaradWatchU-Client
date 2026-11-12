//! Short-lived loopback HTTP bridge for the Angular dashboard.
use crate::requirements;
use std::{
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    net::{TcpListener, TcpStream},
    path::{Component, Path, PathBuf},
    process::Command,
    time::Duration,
};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_BODY: usize = 2 * 1024 * 1024;

struct Response {
    status: u16,
    content_type: &'static str,
    body: Vec<u8>,
}

impl Response {
    fn json(status: u16, body: impl Into<Vec<u8>>) -> Self {
        Self {
            status,
            content_type: "application/json; charset=utf-8",
            body: body.into(),
        }
    }
    fn error(status: u16, message: &str) -> Self {
        let message = baradwatchu_messages::localize_diagnostic(
            message,
            baradwatchu_messages::configured_language(),
        );
        Self::json(status, serde_json::json!({"error": message}).to_string())
    }
    fn pdf(bytes: Vec<u8>) -> Self {
        Self {
            status: 200,
            content_type: "application/pdf",
            body: bytes,
        }
    }
}

fn web_root() -> Result<PathBuf, String> {
    let root = requirements::install_root()
        .map_err(|e| e.0)?
        .join("share/baradwatchu-client/web");
    let canonical = root
        .canonicalize()
        .map_err(|_| "Installed dashboard files are missing".to_owned())?;
    if !canonical.is_dir() {
        return Err("Installed dashboard files are invalid".into());
    }
    Ok(canonical)
}

/// Dashboard section opened in the browser (`dashboard --open ROUTE`).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Route {
    Status,
    Custom,
    History,
    Notifications,
    Settings,
}

impl Route {
    fn hash(self) -> &'static str {
        match self {
            Self::Status => "#/",
            Self::Custom => "#/custom",
            Self::History => "#/history",
            Self::Notifications => "#/notifiche",
            Self::Settings => "#/impostazioni",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    pub open_browser: bool,
    pub route: Route,
}

pub fn usage() -> &'static str {
    baradwatchu_messages::message(
        "cli.dashboard.usage",
        baradwatchu_messages::configured_language(),
    )
}

pub fn parse_options(args: &[std::ffi::OsString]) -> Result<Options, String> {
    let mut options = Options {
        open_browser: true,
        route: Route::Status,
    };
    let (mut seen_browser, mut seen_route) = (false, false);
    let mut args = args.iter();
    while let Some(arg) = args.next() {
        match arg.to_str() {
            Some("--no-browser") if !seen_browser => {
                options.open_browser = false;
                seen_browser = true;
            }
            Some("--open") if !seen_route => {
                options.route = match args.next().and_then(|v| v.to_str()) {
                    Some("status") => Route::Status,
                    Some("custom") => Route::Custom,
                    Some("history") => Route::History,
                    Some("notifications") => Route::Notifications,
                    Some("settings") => Route::Settings,
                    _ => return Err(usage().into()),
                };
                seen_route = true;
            }
            _ => return Err(usage().into()),
        }
    }
    Ok(options)
}

/// Private per-session record that lets a second `dashboard` call (e.g. from the tray)
/// reuse the running instance instead of starting another one.
#[derive(serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Session {
    schema_version: String,
    pid: u32,
    port: u16,
    token: String,
}

const SESSION_SCHEMA: &str = "baradwatchu.dashboard-session.v1";

fn runtime_dir() -> Result<PathBuf, String> {
    let dir = requirements::runtime_dir().map_err(|e| e.0)?;
    requirements::ensure_private_dir(&dir).map_err(|e| e.0)?;
    Ok(dir)
}

fn read_session(dir: &Path) -> Option<Session> {
    let path = dir.join("dashboard.json");
    let metadata = fs::symlink_metadata(&path).ok()?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 4096 {
        return None;
    }
    let session: Session = serde_json::from_str(&fs::read_to_string(path).ok()?).ok()?;
    (session.schema_version == SESSION_SCHEMA && valid_token(&session.token)).then_some(session)
}

fn valid_token(token: &str) -> bool {
    token.len() == 64
        && token
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// A recorded session is reused only if its port accepts connections and, on Linux, the
/// recorded PID is this same executable (a busy single-threaded server still accepts).
fn session_alive(session: &Session) -> bool {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], session.port));
    if TcpStream::connect_timeout(&address, Duration::from_millis(500)).is_err() {
        return false;
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(current) = std::env::current_exe().and_then(|p| p.canonicalize()) else {
            return false;
        };
        return fs::read_link(format!("/proc/{}/exe", session.pid)).is_ok_and(|exe| exe == current);
    }
    #[allow(unreachable_code)]
    true
}

fn session_url(session: &Session, route: Route) -> String {
    format!(
        "http://127.0.0.1:{}/?k={}{}",
        session.port,
        session.token,
        route.hash()
    )
}

/// The session token never appears on a process command line (readable by other local
/// users): the browser opens a private launcher file that redirects to the tokenized URL.
fn open_in_browser(dir: &Path, session: &Session, route: Route) {
    let url = session_url(session, route);
    let launcher = dir.join("open-dashboard.html");
    let language = baradwatchu_messages::configured_language().effective();
    let html_language = match language {
        baradwatchu_messages::Language::Italian => "it",
        _ => "en",
    };
    let open_label = baradwatchu_messages::message("cli.dashboard.open_link", language);
    let html = format!("<!doctype html><html lang=\"{html_language}\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><meta http-equiv=\"refresh\" content=\"0;url={url}\"><title>BaradWatchU</title></head><body><p><a href=\"{url}\">{open_label}</a></p></body></html>\n");
    if requirements::atomic_text(&launcher, &html).is_err() {
        return;
    }
    // Windows: Explorer opens the .html launcher with the user's default browser.
    #[cfg(windows)]
    let opener = requirements::windows_root().join("explorer.exe");
    #[cfg(not(windows))]
    let opener = PathBuf::from(if cfg!(target_os = "macos") {
        "/usr/bin/open"
    } else {
        "/usr/bin/xdg-open"
    });
    let graphical = cfg!(any(target_os = "macos", windows))
        || std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var_os("DISPLAY").is_some();
    if graphical && opener.is_file() {
        let _ = Command::new(&opener)
            .arg(&launcher)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            // Reap in the background: the opener may stay alive as long as the browser.
            .map(|mut child| std::thread::spawn(move || child.wait()));
    }
}

pub fn run(options: Options) -> Result<(), String> {
    let dir = runtime_dir()?;
    let language = baradwatchu_messages::configured_language();
    if let Some(session) = read_session(&dir).filter(session_alive) {
        println!(
            "{}",
            baradwatchu_messages::message("cli.dashboard.already_running", language)
                .replace("{url}", &session_url(&session, options.route))
                .trim_end()
        );
        if options.open_browser {
            open_in_browser(&dir, &session, options.route);
        }
        return Ok(());
    }
    let root = web_root()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "Cannot start local dashboard".to_owned())?;
    let port = listener
        .local_addr()
        .map_err(|_| "Cannot determine dashboard address".to_owned())?
        .port();
    let session = Session {
        schema_version: SESSION_SCHEMA.into(),
        pid: std::process::id(),
        port,
        token: crate::consent::random_hex(32).map_err(|e| e.0)?,
    };
    requirements::atomic_json(&dir.join("dashboard.json"), &session).map_err(|e| e.0)?;
    let origin = format!("http://127.0.0.1:{port}");
    println!(
        "{}",
        baradwatchu_messages::message("cli.dashboard.started", language)
            .replace("{url}", &session_url(&session, options.route))
            .trim_end()
    );
    io::stdout()
        .flush()
        .map_err(|_| "Cannot print dashboard address".to_owned())?;
    if options.open_browser {
        open_in_browser(&dir, &session, options.route);
    }
    for stream in listener.incoming().flatten() {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = handle(stream, &origin, port, &session.token, &root);
    }
    Ok(())
}

/// Constant-time comparison of the session token.
fn token_matches(expected: &str, provided: Option<&str>) -> bool {
    let Some(provided) = provided else {
        return false;
    };
    expected.len() == provided.len()
        && expected
            .bytes()
            .zip(provided.bytes())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}

fn handle(
    mut stream: TcpStream,
    origin: &str,
    port: u16,
    token: &str,
    root: &Path,
) -> io::Result<()> {
    let clone = stream.try_clone()?;
    let mut reader = BufReader::new(clone);
    let mut request_line = String::new();
    reader.read_line(&mut request_line)?;
    if request_line.len() > 8192 {
        return write_response(&mut stream, Response::error(400, "Richiesta non valida"));
    }
    let mut request = request_line.split_whitespace();
    let method = request.next().unwrap_or("");
    let target = request.next().unwrap_or("");
    let version = request.next().unwrap_or("");
    if target.is_empty() || version != "HTTP/1.1" {
        return write_response(&mut stream, Response::error(400, "Richiesta non valida"));
    }

    let mut header_bytes = request_line.len();
    let mut host = None;
    let mut duplicate_host = false;
    let mut request_origin = None;
    let mut duplicate_origin = false;
    let mut content_type = None;
    let mut content_length = None;
    let mut transfer_encoding = false;
    let mut session_token = None;
    let mut duplicate_token = false;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return write_response(&mut stream, Response::error(400, "Intestazioni incomplete"));
        }
        header_bytes += read;
        if header_bytes > MAX_HEADERS {
            return write_response(
                &mut stream,
                Response::error(431, "Intestazioni troppo grandi"),
            );
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return write_response(&mut stream, Response::error(400, "Intestazione non valida"));
        };
        let value = value.trim();
        match name.trim().to_ascii_lowercase().as_str() {
            "host" if host.is_none() => host = Some(value.to_owned()),
            "host" => duplicate_host = true,
            "origin" if request_origin.is_none() => request_origin = Some(value.to_owned()),
            "origin" => duplicate_origin = true,
            "content-type" if content_type.is_none() => {
                content_type = Some(
                    value
                        .split(';')
                        .next()
                        .unwrap_or("")
                        .trim()
                        .to_ascii_lowercase(),
                )
            }
            "content-length" if content_length.is_none() => {
                content_length = Some(match value.parse::<usize>() {
                    Ok(n) if n <= MAX_BODY => n,
                    _ => {
                        return write_response(
                            &mut stream,
                            Response::error(413, "Corpo troppo grande"),
                        )
                    }
                })
            }
            "transfer-encoding" => transfer_encoding = true,
            "x-baradwatchu-token" if session_token.is_none() => {
                session_token = Some(value.to_owned())
            }
            "x-baradwatchu-token" => duplicate_token = true,
            _ => {}
        }
    }
    if duplicate_host
        || duplicate_origin
        || host.as_deref() != Some(&format!("127.0.0.1:{port}"))
        || transfer_encoding
    {
        return write_response(&mut stream, Response::error(403, "Richiesta rifiutata"));
    }
    if request_origin
        .as_deref()
        .is_some_and(|value| value != origin)
    {
        return write_response(&mut stream, Response::error(403, "Origine rifiutata"));
    }
    let is_api = target.starts_with("/api/");
    // Loopback is not a security boundary (other local users and processes can connect):
    // every API call needs the per-session token; static files carry no data.
    if is_api && (duplicate_token || !token_matches(token, session_token.as_deref())) {
        return write_response(
            &mut stream,
            Response::error(401, "Sessione non valida: riapri la dashboard"),
        );
    }
    if is_api
        && matches!(method, "POST" | "PUT" | "DELETE")
        && (request_origin.as_deref() != Some(origin)
            || content_type.as_deref() != Some("application/json"))
    {
        return write_response(
            &mut stream,
            Response::error(403, "Origine o tipo di contenuto rifiutato"),
        );
    }
    let mut body = vec![0; content_length.unwrap_or(0)];
    reader.read_exact(&mut body)?;
    let response = route(method, target, &body, root);
    write_response(&mut stream, response)
}

fn route(method: &str, target: &str, body: &[u8], root: &Path) -> Response {
    let path = target.split('?').next().unwrap_or("");
    match (method, path) {
        ("GET", "/api/ping") => Response::json(200, "{\"ok\":true}"),
        ("GET", "/api/notifications") => api(crate::events::dashboard_notifications_json()),
        ("GET", "/api/configuration") => api(crate::configuration::dashboard_configuration_json()),
        ("GET", "/api/remote/status") => {
            api(crate::requirements::output_json(&crate::remote::status()))
        }
        ("PUT", "/api/remote/registration") => api(crate::remote::dashboard_set_registration(
            std::str::from_utf8(body).unwrap_or_default(),
        )),
        ("PUT", "/api/remote/connection") => api(crate::remote::dashboard_connection(
            std::str::from_utf8(body).unwrap_or_default(),
        )),
        ("GET", "/api/messages") => api(crate::configuration::dashboard_messages_json()),
        ("GET", "/api/report-theme") => api(crate::pdf::dashboard_theme_json()),
        ("PUT", "/api/report-theme") => api(crate::pdf::dashboard_update_theme(
            std::str::from_utf8(body).unwrap_or(""),
        )),
        ("PUT", "/api/configuration/autostart") => {
            api(crate::configuration::dashboard_set_autostart(
                std::str::from_utf8(body).unwrap_or_default(),
            ))
        }
        ("PUT", "/api/configuration/language") => {
            api(crate::configuration::dashboard_set_language(
                std::str::from_utf8(body).unwrap_or_default(),
            ))
        }
        ("PUT", "/api/notifications") => api(crate::events::dashboard_update_preferences(
            std::str::from_utf8(body).unwrap_or(""),
        )),
        ("POST", "/api/consent/simulate") => api(crate::consent::dashboard_simulate(
            std::str::from_utf8(body).unwrap_or(""),
        )),
        // Identity and trust store: local operator actions only. Imports carry the content of
        // a file the operator picked; nothing here accepts a key offered by a remote party.
        ("GET", "/api/identity") => api(crate::identity::dashboard_view_json()),
        ("POST", "/api/identity/generate") => api(crate::identity::dashboard_generate(
            std::str::from_utf8(body).unwrap_or_default(),
        )),
        ("POST", "/api/identity/reset") => api(crate::identity::dashboard_reset(
            std::str::from_utf8(body).unwrap_or_default(),
        )),
        ("POST", "/api/trust/preview") => api(crate::identity::dashboard_trust_preview(
            std::str::from_utf8(body).unwrap_or_default(),
        )),
        ("POST", "/api/trust/import") => api(crate::identity::dashboard_trust_import(
            std::str::from_utf8(body).unwrap_or_default(),
        )),
        ("POST", "/api/trust/clear") => api(crate::identity::dashboard_trust_clear(
            std::str::from_utf8(body).unwrap_or_default(),
        )),
        ("POST", path) if path.starts_with("/api/trust/revoke/") => {
            let id = &path["/api/trust/revoke/".len()..];
            api(crate::identity::dashboard_trust_revoke(
                id,
                std::str::from_utf8(body).unwrap_or_default(),
            ))
        }
        ("GET", "/api/requirements") => api(requirements::dashboard_data_json()),
        ("POST", "/api/refresh") => api(requirements::dashboard_refresh_json()),
        ("GET", "/api/status") => api(requirements::dashboard_status_json()),
        ("GET", "/api/history") => api(requirements::dashboard_history_json()),
        ("POST", "/api/audit") => api(requirements::dashboard_audit_json()),
        ("PUT", "/api/settings") => api(requirements::update_dashboard_settings(
            std::str::from_utf8(body).unwrap_or(""),
        )),
        ("POST", "/api/custom-checks") => api(requirements::dashboard_import_custom(
            std::str::from_utf8(body).unwrap_or(""),
        )),
        ("POST", path) if path.starts_with("/api/custom-checks/update/") => {
            let id = &path["/api/custom-checks/update/".len()..];
            api(requirements::dashboard_update_custom(
                id,
                std::str::from_utf8(body).unwrap_or(""),
            ))
        }
        ("POST", path) if path.starts_with("/api/custom-checks/restore/") => {
            let id = &path["/api/custom-checks/restore/".len()..];
            api(requirements::dashboard_restore_builtin(id))
        }
        ("POST", path) if path.starts_with("/api/custom-checks/accept/") => {
            let id = &path["/api/custom-checks/accept/".len()..];
            api(requirements::dashboard_accept_custom(id))
        }
        ("DELETE", path) if path.starts_with("/api/custom-checks/") => {
            let id = &path["/api/custom-checks/".len()..];
            api(requirements::dashboard_remove_custom(id))
        }
        ("POST", route) if route.starts_with("/api/check/") => {
            let id = &route["/api/check/".len()..];
            if id.is_empty() || id.contains('/') {
                return Response::error(404, "Requisito non trovato");
            }
            api(requirements::dashboard_check_json(id))
        }
        ("GET", "/api/history/usage") => api(crate::history::dashboard_usage_json()),
        ("DELETE", "/api/history") => api(crate::history::dashboard_clear_json()),
        ("DELETE", route) if route.starts_with("/api/history/") => {
            let stamp = &route["/api/history/".len()..];
            api(crate::history::dashboard_delete_json(stamp))
        }
        ("GET", route) if route.starts_with("/api/history/") => {
            if let Some(stamp) = route
                .strip_prefix("/api/history/")
                .and_then(|value| value.strip_suffix("/pdf"))
            {
                return match crate::pdf::history_pdf(stamp) {
                    Ok(bytes) => Response::pdf(bytes),
                    Err(error) => Response::error(404, &error.0),
                };
            }
            let stamp = &route["/api/history/".len()..];
            api(requirements::dashboard_history_report_json(stamp))
        }
        ("GET", path) if !path.starts_with("/api/") => static_file(path, root),
        ("GET" | "POST" | "PUT", _) => Response::error(404, "Percorso non trovato"),
        _ => Response::error(405, "Metodo non consentito"),
    }
}

fn api(result: Result<String, requirements::CliError>) -> Response {
    match result {
        Ok(body) => Response::json(200, body),
        Err(error) => Response::error(400, &error.0),
    }
}

fn static_file(path: &str, root: &Path) -> Response {
    let relative = if path == "/" {
        "index.html"
    } else {
        path.strip_prefix('/').unwrap_or("")
    };
    if relative.is_empty()
        || relative.contains('%')
        || relative.contains('\\')
        || Path::new(relative)
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
    {
        return Response::error(404, "File non trovato");
    }
    let candidate = root.join(relative);
    let Ok(metadata) = fs::symlink_metadata(&candidate) else {
        return Response::error(404, "File non trovato");
    };
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 10 * 1024 * 1024
    {
        return Response::error(404, "File non trovato");
    }
    let Ok(path) = candidate.canonicalize() else {
        return Response::error(404, "File non trovato");
    };
    // Compare canonical forms (on Windows canonical paths carry the `\\?\` prefix).
    let Ok(canonical_root) = root.canonicalize() else {
        return Response::error(404, "File non trovato");
    };
    if !path.starts_with(&canonical_root) {
        return Response::error(404, "File non trovato");
    }
    let Ok(body) = fs::read(path) else {
        return Response::error(404, "File non trovato");
    };
    let content_type = match candidate
        .extension()
        .and_then(|ext| ext.to_str())
        .unwrap_or("")
    {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "svg" => "image/svg+xml",
        "png" => "image/png",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        _ => "application/octet-stream",
    };
    Response {
        status: 200,
        content_type,
        body,
    }
}

fn write_response(stream: &mut TcpStream, response: Response) -> io::Result<()> {
    let reason = match response.status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        431 => "Request Header Fields Too Large",
        _ => "Error",
    };
    write!(stream, "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: DENY\r\nContent-Security-Policy: default-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; frame-ancestors 'none'; base-uri 'self'\r\nCache-Control: no-store\r\n\r\n", response.status, reason, response.content_type, response.body.len())?;
    stream.write_all(&response.body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn routes_only_supported_methods_and_known_endpoints() {
        let _env = requirements::TestEnv::new("dashboard-routes");
        let path = PathBuf::from("/does/not/exist");
        assert_eq!(route("GET", "/api/nope", &[], &path).status, 404);
        assert_eq!(route("DELETE", "/api/audit", &[], &path).status, 405);
        assert_eq!(
            route("POST", "/api/check/REQ-999", b"{}", &path).status,
            400
        );
        assert_eq!(
            route("POST", "/api/custom-checks", b"{}", &path).status,
            400
        );
        assert_eq!(
            route("POST", "/api/custom-checks/restore/REQ-001", b"{}", &path).status,
            400
        );
        assert_eq!(
            route("DELETE", "/api/custom-checks/CUSTOM-UNKNOWN", b"{}", &path).status,
            400
        );
        assert_eq!(
            route(
                "POST",
                "/api/custom-checks/accept/CUSTOM-UNKNOWN",
                b"{}",
                &path
            )
            .status,
            400
        );
        assert_eq!(route("GET", "/api/requirements", &[], &path).status, 200);
        assert_eq!(
            route("GET", "/api/history/not-a-timestamp", &[], &path).status,
            400
        );
        let stamp = requirements::now_ms().to_string();
        let history = requirements::history_dir().unwrap();
        fs::create_dir_all(&history).unwrap();
        let pdf_bytes = b"%PDF-1.7\nmock report";
        fs::write(history.join(format!("{stamp}.pdf")), pdf_bytes).unwrap();
        let response = route("GET", &format!("/api/history/{stamp}/pdf"), &[], &path);
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "application/pdf");
        assert_eq!(response.body, pdf_bytes);
    }

    /// Sends one raw request through the real `handle` (token, Host, Origin, Content-Type).
    fn exchange(request: &str, token: &str) -> String {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let origin = format!("http://127.0.0.1:{port}");
        let token = token.to_owned();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            handle(stream, &origin, port, &token, Path::new("/does/not/exist")).unwrap();
        });
        let mut client = TcpStream::connect(("127.0.0.1", port)).unwrap();
        client
            .write_all(request.replace("{port}", &port.to_string()).as_bytes())
            .unwrap();
        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server.join().unwrap();
        response
    }

    #[test]
    fn identity_and_trust_api_need_token_origin_and_json() {
        let _env = requirements::TestEnv::new("dashboard-identity");
        let token = "d".repeat(64);
        let body = r#"{"confirm":true}"#;
        let post = |path: &str, headers: &str| {
            format!(
                "POST {path} HTTP/1.1\r\nHost: 127.0.0.1:{{port}}\r\n{headers}Content-Length: {}\r\n\r\n{body}",
                body.len()
            )
        };
        let good_origin = "Origin: http://127.0.0.1:{port}\r\n";
        let json = "Content-Type: application/json\r\n";
        let auth = format!("X-BaradWatchU-Token: {token}\r\n");
        let identity_dir = crate::identity::identity_dir().unwrap();
        for path in [
            "/api/identity/generate",
            "/api/identity/reset",
            "/api/trust/clear",
            "/api/trust/import",
        ] {
            // No token.
            let response = exchange(&post(path, &format!("{good_origin}{json}")), &token);
            assert!(response.starts_with("HTTP/1.1 401"), "{path}: {response}");
            // Foreign origin (cross-site page).
            let response = exchange(
                &post(
                    path,
                    &format!("Origin: http://evil.example\r\n{json}{auth}"),
                ),
                &token,
            );
            assert!(response.starts_with("HTTP/1.1 403"), "{path}: {response}");
            // Missing Origin or non-JSON content type (simple cross-origin form posts).
            let response = exchange(&post(path, &format!("{json}{auth}")), &token);
            assert!(response.starts_with("HTTP/1.1 403"), "{path}: {response}");
            let response = exchange(
                &post(
                    path,
                    &format!("{good_origin}Content-Type: text/plain\r\n{auth}"),
                ),
                &token,
            );
            assert!(response.starts_with("HTTP/1.1 403"), "{path}: {response}");
            // Wrong Host (DNS rebinding).
            let response = exchange(
                &post(path, &format!("{good_origin}{json}{auth}"))
                    .replace("Host: 127.0.0.1:{port}", "Host: attacker.example"),
                &token,
            );
            assert!(response.starts_with("HTTP/1.1 403"), "{path}: {response}");
        }
        assert!(
            !identity_dir.exists(),
            "a refused request changed local state"
        );
        let get = "GET /api/identity HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n".to_owned();
        assert!(exchange(&get, &token).starts_with("HTTP/1.1 401"));
        // Authorized local dashboard request.
        let response = exchange(
            &post(
                "/api/identity/generate",
                &format!("{good_origin}{json}{auth}"),
            ),
            &token,
        );
        assert!(response.starts_with("HTTP/1.1 200"), "{response}");
        assert!(response.contains("\"CONFIGURED\""));
        assert!(!response.contains("seed"));
        assert_eq!(
            route("GET", "/api/identity", &[], Path::new("/x")).status,
            200
        );
        assert_eq!(
            route(
                "POST",
                "/api/identity/generate",
                body.as_bytes(),
                Path::new("/x")
            )
            .status,
            400
        );
        assert_eq!(
            route(
                "POST",
                "/api/trust/revoke/SRV-0000-0000-0000-0000",
                body.as_bytes(),
                Path::new("/x")
            )
            .status,
            400
        );
        assert_eq!(
            route("DELETE", "/api/identity", &[], Path::new("/x")).status,
            405
        );
    }

    #[test]
    fn dashboard_options_accept_routes_once() {
        let parse = |args: &[&str]| {
            parse_options(
                &args
                    .iter()
                    .map(std::ffi::OsString::from)
                    .collect::<Vec<_>>(),
            )
        };
        assert_eq!(
            parse(&[]).unwrap(),
            Options {
                open_browser: true,
                route: Route::Status
            }
        );
        let options = parse(&["--no-browser", "--open", "notifications"]).unwrap();
        assert!(!options.open_browser);
        assert_eq!(options.route.hash(), "#/notifiche");
        assert!(parse(&["--open"]).is_err());
        assert!(parse(&["--open", "javascript:alert(1)"]).is_err());
        assert!(parse(&["--no-browser", "--no-browser"]).is_err());
    }

    #[test]
    fn api_token_comparison_is_exact() {
        let token = "a".repeat(64);
        assert!(token_matches(&token, Some(&token)));
        assert!(!token_matches(&token, None));
        assert!(!token_matches(&token, Some(&"b".repeat(64))));
        assert!(!token_matches(&token, Some(&"a".repeat(63))));
        assert!(valid_token(&token));
        assert!(!valid_token("A".repeat(64).as_str()));
    }

    #[test]
    fn stale_dashboard_session_is_not_reused() {
        let env = requirements::TestEnv::new("dashboard-session");
        let dir = env.root.join("run/baradwatchu");
        fs::create_dir_all(&dir).unwrap();
        // A port nobody listens on: the recorded session must be treated as dead.
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let session = Session {
            schema_version: SESSION_SCHEMA.into(),
            pid: std::process::id(),
            port,
            token: "c".repeat(64),
        };
        requirements::atomic_json(&dir.join("dashboard.json"), &session).unwrap();
        let read = read_session(&dir).unwrap();
        assert_eq!(read.port, port);
        assert!(!session_alive(&read));
        fs::write(dir.join("dashboard.json"), "{\"pid\":1}").unwrap();
        assert!(read_session(&dir).is_none());
    }

    #[test]
    fn static_paths_reject_traversal_and_encoded_aliases() {
        let path = PathBuf::from("/tmp");
        assert_eq!(static_file("/../etc/passwd", &path).status, 404);
        assert_eq!(static_file("/%2e%2e/etc/passwd", &path).status, 404);
    }

    #[test]
    fn dashboard_serves_the_built_angular_entrypoint() {
        let root = std::env::temp_dir().join(format!(
            "baradwatchu-dashboard-static-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("index.html"), "<bwu-root>dashboard</bwu-root>").unwrap();

        let response = static_file("/", &root);
        assert_eq!(response.status, 200);
        assert_eq!(response.content_type, "text/html; charset=utf-8");
        assert_eq!(
            String::from_utf8(response.body).unwrap(),
            "<bwu-root>dashboard</bwu-root>"
        );
        fs::remove_dir_all(root).unwrap();
    }
}
