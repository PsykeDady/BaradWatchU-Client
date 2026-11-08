//! Client for the BaradWatchU agent executable.
//!
//! The tray never audits by itself and never runs arbitrary commands: it launches the
//! agent installed next to it (never looked up in PATH) with one of a fixed set of
//! subcommands, without a shell, and parses its JSON output.
use crate::{model, platform};
use std::{
    io::Read,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const SNAPSHOT_TIMEOUT: Duration = Duration::from_secs(20);
const DECISION_TIMEOUT: Duration = Duration::from_secs(20);
/// Upper bound for a full audit (each check has its own timeout, REQ-001 up to 90 s).
const AUDIT_TIMEOUT: Duration = Duration::from_secs(30 * 60);
const MAX_OUTPUT: u64 = 4 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DashboardRoute {
    Status,
    History,
    Notifications,
}

#[derive(Clone, Debug)]
pub struct Agent {
    path: PathBuf,
}

impl Agent {
    pub fn locate() -> Result<Self, String> {
        let exe = std::env::current_exe()
            .map_err(|_| "impossibile localizzare l'eseguibile della tray".to_owned())?;
        let name = if cfg!(windows) {
            "baradwatchu-agent.exe"
        } else {
            "baradwatchu-agent"
        };
        let path = exe
            .parent()
            .map(|dir| dir.join(name))
            .ok_or_else(|| "cartella di installazione non valida".to_owned())?;
        Ok(Self { path })
    }

    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn command(&self) -> Result<Command, String> {
        if !self.path.is_file() {
            return Err(format!("agente non trovato in {}", self.path.display()));
        }
        let mut command = Command::new(&self.path);
        command.stdin(Stdio::null());
        platform::no_console(&mut command);
        Ok(command)
    }

    pub fn snapshot(&self, after: Option<u64>) -> Result<model::Snapshot, String> {
        let mut command = self.command()?;
        command.args(["events", "--json"]);
        if let Some(after) = after {
            command.arg("--after").arg(after.to_string());
        }
        let (code, stdout, stderr) = run(command, SNAPSHOT_TIMEOUT)?;
        if code != Some(0) {
            return Err(failure("stato non disponibile", &stderr));
        }
        model::parse_snapshot(&stdout)
    }

    /// Runs a full audit through the agent; the agent records the result and its event.
    pub fn audit(&self) -> Result<(), String> {
        let mut command = self.command()?;
        command.args(["audit", "--json"]);
        let (code, stdout, stderr) = run(command, AUDIT_TIMEOUT)?;
        // 0 PASS, 1 ERROR results, 3 FAIL, 4 WARN: all are completed audits.
        match code {
            Some(0 | 1 | 3 | 4)
                if serde_json::from_str::<serde_json::Value>(&stdout)
                    .is_ok_and(|v| v["results"].is_array()) =>
            {
                Ok(())
            }
            _ => Err(failure("audit non completato", &stderr)),
        }
    }

    pub fn decide(&self, request_id: &str, accept: bool) -> Result<String, String> {
        if request_id.len() != 32 || !request_id.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err("identificativo di richiesta non valido".into());
        }
        let mut command = self.command()?;
        command
            .arg("consent")
            .arg(if accept { "accept" } else { "reject" })
            .arg(request_id)
            .args(["--via", "window"]);
        let (code, stdout, stderr) = run(command, DECISION_TIMEOUT)?;
        if code == Some(0) {
            Ok(stdout.trim().to_owned())
        } else {
            Err(failure("decisione non registrata", &stderr))
        }
    }

    /// Opens the browser dashboard; the agent reuses a running dashboard of this user or
    /// starts one detached, so it keeps running if the tray is closed.
    pub fn open_dashboard(&self, route: DashboardRoute) -> Result<(), String> {
        let mut command = self.command()?;
        command.args([
            "dashboard",
            "--open",
            match route {
                DashboardRoute::Status => "status",
                DashboardRoute::History => "history",
                DashboardRoute::Notifications => "notifications",
            },
        ]);
        command.stdout(Stdio::null()).stderr(Stdio::null());
        platform::detach(&mut command);
        let mut child = command
            .spawn()
            .map_err(|_| "impossibile avviare la dashboard".to_owned())?;
        thread::spawn(move || child.wait());
        Ok(())
    }
}

fn failure(context: &str, stderr: &str) -> String {
    let detail = stderr
        .lines()
        .map(str::trim)
        .find(|line| !line.is_empty())
        .unwrap_or("nessun dettaglio");
    let detail: String = detail.chars().take(200).collect();
    format!("{context}: {detail}")
}

fn reader(stream: Option<impl Read + Send + 'static>) -> thread::JoinHandle<String> {
    thread::spawn(move || {
        let mut text = String::new();
        if let Some(stream) = stream {
            let _ = stream.take(MAX_OUTPUT).read_to_string(&mut text);
        }
        text
    })
}

fn kill(child: &mut Child) {
    let _ = child.kill();
    let _ = child.wait();
}

fn run(mut command: Command, timeout: Duration) -> Result<(Option<i32>, String, String), String> {
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command
        .spawn()
        .map_err(|_| "impossibile avviare l'agente".to_owned())?;
    let stdout = reader(child.stdout.take());
    let stderr = reader(child.stderr.take());
    let started = Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                kill(&mut child);
                return Err("l'agente non ha risposto entro il tempo massimo".into());
            }
            Ok(None) => thread::sleep(Duration::from_millis(100)),
            Err(_) => {
                kill(&mut child);
                return Err("errore nell'attesa dell'agente".into());
            }
        }
    };
    let stdout = stdout.join().unwrap_or_default();
    let stderr = stderr.join().unwrap_or_default();
    Ok((status.code(), stdout, stderr))
}
