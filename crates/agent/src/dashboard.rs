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
        Self::json(status, serde_json::json!({"error": message}).to_string())
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
}

impl Route {
    fn hash(self) -> &'static str {
        match self {
            Self::Status => "#/",
            Self::Custom => "#/custom",
            Self::History => "#/history",
            Self::Notifications => "#/notifiche",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Options {
    pub open_browser: bool,
    pub route: Route,
}

pub const USAGE: &str =
    "Usage: dashboard [--no-browser] [--open status|custom|history|notifications]";

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
                    _ => return Err(USAGE.into()),
                };
                seen_route = true;
            }
            _ => return Err(USAGE.into()),
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
    let html = format!("<!doctype html><html lang=\"it\"><head><meta charset=\"utf-8\"><meta name=\"referrer\" content=\"no-referrer\"><meta http-equiv=\"refresh\" content=\"0;url={url}\"><title>BaradWatchU</title></head><body><p><a href=\"{url}\">Apri la dashboard BaradWatchU</a></p></body></html>\n");
    if requirements::atomic_text(&launcher, &html).is_err() {
        return;
    }
    let opener = if cfg!(target_os = "macos") {
        "/usr/bin/open"
    } else {
        "/usr/bin/xdg-open"
    };
    let graphical = cfg!(target_os = "macos")
        || std::env::var_os("WAYLAND_DISPLAY").is_some()
        || std::env::var_os("DISPLAY").is_some();
    if graphical && Path::new(opener).is_file() {
        let _ = Command::new(opener)
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
    if let Some(session) = read_session(&dir).filter(session_alive) {
        println!(
            "Dashboard già attiva: {}",
            session_url(&session, options.route)
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
        "Dashboard locale: {} (Ctrl+C per chiuderla)",
        session_url(&session, options.route)
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
        ("PUT", "/api/notifications") => api(crate::events::dashboard_update_preferences(
            std::str::from_utf8(body).unwrap_or(""),
        )),
        ("POST", "/api/consent/simulate") => api(crate::consent::dashboard_simulate(
            std::str::from_utf8(body).unwrap_or(""),
        )),
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
        ("GET", route) if route.starts_with("/api/history/") => {
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
    if !path.starts_with(root) {
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
