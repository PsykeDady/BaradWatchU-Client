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

pub fn run() -> Result<(), String> {
    let root = web_root()?;
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .map_err(|_| "Cannot start local dashboard".to_owned())?;
    let port = listener
        .local_addr()
        .map_err(|_| "Cannot determine dashboard address".to_owned())?
        .port();
    let origin = format!("http://127.0.0.1:{port}");
    println!("Dashboard locale: {origin} (Ctrl+C per chiuderla)");
    io::stdout()
        .flush()
        .map_err(|_| "Cannot print dashboard address".to_owned())?;
    if (std::env::var_os("WAYLAND_DISPLAY").is_some() || std::env::var_os("DISPLAY").is_some())
        && Path::new("/usr/bin/xdg-open").is_file()
    {
        let _ = Command::new("/usr/bin/xdg-open")
            .arg(&origin)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
    }
    for stream in listener.incoming().flatten() {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));
        let _ = handle(stream, &origin, port, &root);
    }
    Ok(())
}

fn handle(mut stream: TcpStream, origin: &str, port: u16, root: &Path) -> io::Result<()> {
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
