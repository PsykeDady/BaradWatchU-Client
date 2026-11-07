//! Small local requirement runner used by the user-facing CLI.
//! Tools are package-owned executables and are launched directly, without a shell.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::{self, Read, Write},
    path::{Component, Path, PathBuf},
    process::{Command, Stdio},
    thread,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

const MAX_TOOL_OUTPUT: usize = 64 * 1024;
const TOOL_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ResultStatus {
    Pass,
    Fail,
    Warn,
    Error,
    Disabled,
    NotApplicable,
}

impl std::fmt::Display for ResultStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Pass => "PASS",
            Self::Fail => "FAIL",
            Self::Warn => "WARN",
            Self::Error => "ERROR",
            Self::Disabled => "DISABLED",
            Self::NotApplicable => "NOT_APPLICABLE",
        })
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Priority {
    Highest,
    High,
    Medium,
    Low,
    Optional,
}

impl std::fmt::Display for Priority {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Highest => "HIGHEST",
            Self::High => "HIGH",
            Self::Medium => "MEDIUM",
            Self::Low => "LOW",
            Self::Optional => "OPTIONAL",
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Requirement {
    pub id: String,
    pub name: String,
    pub description: String,
    pub enabled: bool,
    pub priority: Priority,
    #[serde(default = "empty_parameters")]
    pub parameters: serde_json::Value,
    pub tools: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema_version: String,
    requirements: Vec<Requirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    schema_version: String,
    requirements: BTreeMap<String, RequirementSettings>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RequirementSettings {
    enabled: bool,
    priority: Priority,
    #[serde(default = "empty_parameters")]
    parameters: serde_json::Value,
}

fn empty_parameters() -> serde_json::Value {
    serde_json::json!({})
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ToolResult {
    id: String,
    status: ResultStatus,
    summary: String,
    #[serde(default)]
    details: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultRecord {
    pub id: String,
    pub name: String,
    pub priority: Priority,
    pub status: ResultStatus,
    pub summary: String,
    pub details: Vec<String>,
    pub completed_at_unix_ms: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditReport {
    pub schema_version: String,
    pub completed_at_unix_ms: u64,
    pub results: Vec<ResultRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_file: Option<String>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditHistoryEntry {
    completed_at_unix_ms: u64,
    overall_status: String,
    pass: usize,
    fail: usize,
    warn: usize,
    error: usize,
    other: usize,
}

#[derive(Clone, Debug)]
pub struct CliOutput {
    pub text: String,
    pub code: u8,
}

#[derive(Debug)]
pub struct CliError(pub String);

fn catalog() -> Result<Catalog, CliError> {
    let path = install_root()?.join("share/baradwatchu-client/catalog/requirements.json");
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| CliError("Requirement catalog is missing".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err(CliError(
            "Requirement catalog is unsafe or too large".into(),
        ));
    }
    let text =
        fs::read_to_string(path).map_err(|_| CliError("Cannot read requirement catalog".into()))?;
    let value: Catalog = serde_json::from_str(&text)
        .map_err(|_| CliError("Built-in requirement catalog is invalid".into()))?;
    if value.schema_version != "baradwatchu.requirements.v1" || value.requirements.is_empty() {
        return Err(CliError("Unsupported or empty requirement catalog".into()));
    }
    let mut ids = std::collections::BTreeSet::new();
    for requirement in &value.requirements {
        if requirement.id.is_empty()
            || !ids.insert(requirement.id.as_str())
            || requirement.tools.is_empty()
            || requirement
                .tools
                .values()
                .any(|path| !safe_relative_path(path))
        {
            return Err(CliError(
                "Requirement catalog contains an invalid entry".into(),
            ));
        }
    }
    Ok(value)
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.as_os_str().is_empty()
        && !value.contains("//")
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_)))
}

fn state_dir() -> Result<PathBuf, CliError> {
    let base = std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .ok_or_else(|| CliError("Cannot locate the user configuration directory".into()))?;
    Ok(base.join("baradwatchu"))
}

fn history_dir() -> Result<PathBuf, CliError> {
    let base = std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".local/state")))
        .ok_or_else(|| CliError("Cannot locate the user state directory".into()))?;
    Ok(base.join("baradwatchu").join("audits"))
}

fn initial_settings(catalog: &Catalog) -> Settings {
    Settings {
        schema_version: "baradwatchu.settings.v1".into(),
        requirements: catalog
            .requirements
            .iter()
            .map(|r| {
                (
                    r.id.clone(),
                    RequirementSettings {
                        enabled: r.enabled,
                        priority: r.priority,
                        parameters: r.parameters.clone(),
                    },
                )
            })
            .collect(),
    }
}

fn load_settings(catalog: &Catalog) -> Result<Settings, CliError> {
    let path = state_dir()?.join("settings.json");
    if !path.exists() {
        return Ok(initial_settings(catalog));
    }
    let metadata = fs::symlink_metadata(&path)
        .map_err(|_| CliError("Cannot inspect local settings".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err(CliError(
            "Local settings file is unsafe or too large".into(),
        ));
    }
    let text =
        fs::read_to_string(path).map_err(|_| CliError("Cannot read local settings".into()))?;
    let settings: Settings = serde_json::from_str(&text)
        .map_err(|_| CliError("Local settings JSON is invalid".into()))?;
    if settings.schema_version != "baradwatchu.settings.v1"
        || settings
            .requirements
            .keys()
            .any(|id| !catalog.requirements.iter().any(|r| &r.id == id))
        || settings
            .requirements
            .values()
            .any(|item| !item.parameters.is_object())
    {
        return Err(CliError(
            "Local settings do not match this Client catalog".into(),
        ));
    }
    Ok(settings)
}

fn save_settings(settings: &Settings) -> Result<(), CliError> {
    let directory = state_dir()?;
    fs::create_dir_all(&directory)
        .map_err(|_| CliError("Cannot create local settings directory".into()))?;
    secure_dir(&directory)?;
    let path = directory.join("settings.json");
    atomic_json(&path, settings)
}

fn secure_dir(path: &Path) -> Result<(), CliError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliError("Cannot inspect local data directory".into()))?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(CliError("Local data directory is unsafe".into()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))
            .map_err(|_| CliError("Cannot secure local data directory".into()))?;
    }
    Ok(())
}

fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError("Invalid local data path".into()))?;
    let temp = parent.join(format!(".tmp-{}", std::process::id()));
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|_| CliError("Cannot encode local data".into()))?;
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|_| CliError("Cannot create temporary local data file".into()))?;
    file.write_all(&bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| CliError("Cannot write local data file".into()))?;
    fs::rename(&temp, path).map_err(|_| CliError("Cannot replace local data file".into()))?;
    Ok(())
}

fn atomic_text(path: &Path, value: &str) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError("Invalid local log path".into()))?;
    let temp = parent.join(format!(".tmp-{}", std::process::id()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&temp)
        .map_err(|_| CliError("Cannot create temporary audit log".into()))?;
    file.write_all(value.as_bytes())
        .and_then(|_| file.sync_all())
        .map_err(|_| CliError("Cannot write audit log".into()))?;
    fs::rename(&temp, path).map_err(|_| CliError("Cannot replace audit log".into()))?;
    Ok(())
}

pub(crate) fn install_root() -> Result<PathBuf, CliError> {
    let executable = std::env::current_exe()
        .map_err(|_| CliError("Cannot locate Client installation".into()))?;
    executable
        .parent()
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .ok_or_else(|| CliError("Cannot locate Client installation directory".into()))
}

fn platform_key() -> &'static str {
    if cfg!(target_os = "linux") {
        "linux"
    } else if cfg!(target_os = "windows") {
        "windows"
    } else if cfg!(target_os = "macos") {
        "macos"
    } else {
        "unsupported"
    }
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

fn error_result(requirement: &Requirement, priority: Priority, summary: &str) -> ResultRecord {
    ResultRecord {
        id: requirement.id.clone(),
        name: requirement.name.clone(),
        priority,
        status: ResultStatus::Error,
        summary: summary.into(),
        details: vec![],
        completed_at_unix_ms: now_ms(),
    }
}

fn execute(
    requirement: &Requirement,
    priority: Priority,
    parameters: &serde_json::Value,
) -> ResultRecord {
    let Some(relative) = requirement.tools.get(platform_key()) else {
        return ResultRecord {
            id: requirement.id.clone(),
            name: requirement.name.clone(),
            priority,
            status: ResultStatus::NotApplicable,
            summary: "No tool is available for this operating system".into(),
            details: vec![],
            completed_at_unix_ms: now_ms(),
        };
    };
    if !safe_relative_path(relative) {
        return error_result(requirement, priority, "Tool path is invalid");
    }
    let root = match install_root() {
        Ok(root) => root,
        Err(_) => return error_result(requirement, priority, "Cannot locate Client installation"),
    };
    let root = match root.canonicalize() {
        Ok(root) => root,
        Err(_) => return error_result(requirement, priority, "Cannot locate Client installation"),
    };
    let tool_path = root.join(relative);
    let canonical_tool = match tool_path.canonicalize() {
        Ok(path) if path.starts_with(&root) => path,
        _ => {
            return error_result(
                requirement,
                priority,
                "Tool path escapes or is missing from the Client installation",
            )
        }
    };
    let metadata = match fs::symlink_metadata(&canonical_tool) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        _ => return error_result(requirement, priority, "Required tool is missing or unsafe"),
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return error_result(requirement, priority, "Required tool is not executable");
        }
    }
    let parameter_input =
        if parameters.is_null() || parameters.as_object().is_some_and(|map| map.is_empty()) {
            None
        } else {
            let encoded = match serde_json::to_vec(
                &serde_json::json!({"requirementId":requirement.id,"parameters":parameters}),
            ) {
                Ok(encoded) if encoded.len() <= 16 * 1024 => encoded,
                _ => {
                    return error_result(
                        requirement,
                        priority,
                        "Requirement parameters are invalid or too large",
                    )
                }
            };
            Some(encoded)
        };
    let mut command = Command::new(&canonical_tool);
    command
        .stdin(if parameter_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", "/usr/bin:/bin");
    for name in [
        "HOME",
        "USER",
        "LOGNAME",
        "LANG",
        "XDG_CONFIG_HOME",
        "XDG_RUNTIME_DIR",
        "DBUS_SESSION_BUS_ADDRESS",
        "XDG_CURRENT_DESKTOP",
        "XDG_SESSION_TYPE",
        "XDG_SESSION_ID",
        "DESKTOP_SESSION",
        "WAYLAND_DISPLAY",
        "DISPLAY",
        "KDE_SESSION_VERSION",
        "KDE_FULL_SESSION",
    ] {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(_) => return error_result(requirement, priority, "Could not start requirement tool"),
    };
    if let Some(input) = parameter_input {
        let Some(mut stdin) = child.stdin.take() else {
            let _ = child.kill();
            return error_result(
                requirement,
                priority,
                "Could not send requirement parameters",
            );
        };
        if stdin.write_all(&input).is_err() {
            let _ = child.kill();
            return error_result(
                requirement,
                priority,
                "Could not send requirement parameters",
            );
        }
    }
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill();
        return error_result(
            requirement,
            priority,
            "Could not read requirement tool result",
        );
    };
    let reader = thread::spawn(move || -> io::Result<Vec<u8>> {
        let mut data = Vec::new();
        stdout
            .take((MAX_TOOL_OUTPUT + 1) as u64)
            .read_to_end(&mut data)?;
        Ok(data)
    });
    let deadline = std::time::Instant::now() + TOOL_TIMEOUT;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20))
            }
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    let output = match reader.join() {
        Ok(Ok(output)) if output.len() <= MAX_TOOL_OUTPUT => output,
        _ => {
            return error_result(
                requirement,
                priority,
                "Requirement tool output is invalid or too large",
            )
        }
    };
    if !status.is_some_and(|status| status.success()) {
        return error_result(
            requirement,
            priority,
            "Requirement tool failed or timed out",
        );
    }
    let text = match std::str::from_utf8(&output) {
        Ok(text) => text,
        Err(_) => {
            return error_result(
                requirement,
                priority,
                "Requirement tool returned invalid text",
            )
        }
    };
    let result: ToolResult = match serde_json::from_str(text) {
        Ok(result) => result,
        Err(_) => {
            return error_result(
                requirement,
                priority,
                "Requirement tool returned invalid JSON",
            )
        }
    };
    if result.id != requirement.id || result.summary.trim().is_empty() || result.details.len() > 64
    {
        return error_result(
            requirement,
            priority,
            "Requirement tool returned an invalid result",
        );
    }
    let mut details = result.details;
    details.insert(0, format!("Tool eseguito: {}", canonical_tool.display()));
    details.insert(1, "Codice uscita tool: 0".into());
    ResultRecord {
        id: requirement.id.clone(),
        name: requirement.name.clone(),
        priority,
        status: result.status,
        summary: result.summary,
        details,
        completed_at_unix_ms: now_ms(),
    }
}

fn save_audit(report: &mut AuditReport, include_log: bool) -> Result<Option<PathBuf>, CliError> {
    let directory = history_dir()?;
    save_audit_at(&directory, report, include_log)
}

fn save_audit_at(
    directory: &Path,
    report: &mut AuditReport,
    include_log: bool,
) -> Result<Option<PathBuf>, CliError> {
    fs::create_dir_all(&directory)
        .map_err(|_| CliError("Cannot create audit history directory".into()))?;
    secure_dir(&directory)?;
    let reports = directory.join("reports");
    fs::create_dir_all(&reports)
        .map_err(|_| CliError("Cannot create audit report directory".into()))?;
    secure_dir(&reports)?;
    let stamp = report.completed_at_unix_ms;
    let log_path = directory.join(format!("{stamp}.log"));
    report.log_file = include_log.then(|| log_path.display().to_string());
    let report_path = reports.join(format!("{stamp}.json"));
    if include_log {
        let mut log = format!("BaradWatchU — log audit\nCompletato (Unix ms): {stamp}\n\n");
        for result in &report.results {
            log.push_str(&human_result(result));
            log.push('\n');
        }
        atomic_text(&log_path, &log)?;
    }
    atomic_json(&report_path, report)?;
    Ok(include_log.then_some(log_path))
}

fn load_last_audit() -> Result<Option<AuditReport>, CliError> {
    let directory = history_dir()?;
    let entries = match fs::read_dir(&directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(CliError("Cannot read audit history".into())),
    };
    let mut paths = entries
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    let reports = directory.join("reports");
    if let Ok(metadata) = fs::symlink_metadata(&reports) {
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(CliError("Audit report directory is unsafe".into()));
        }
    }
    if let Ok(entries) = fs::read_dir(&reports) {
        paths.extend(
            entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .filter(|path| path.extension().is_some_and(|ext| ext == "json")),
        );
    }
    paths.sort_by_key(|path| path.file_stem().map(OsString::from).unwrap_or_default());
    let Some(path) = paths.pop() else {
        return Ok(None);
    };
    let metadata =
        fs::symlink_metadata(&path).map_err(|_| CliError("Cannot inspect latest audit".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 2 * 1024 * 1024
    {
        return Err(CliError("Latest audit file is unsafe or too large".into()));
    }
    let text = fs::read_to_string(path).map_err(|_| CliError("Cannot read latest audit".into()))?;
    serde_json::from_str(&text)
        .map(Some)
        .map_err(|_| CliError("Latest audit JSON is invalid".into()))
}

fn read_history_report(path: &Path, expected_stamp: u64) -> Result<AuditReport, CliError> {
    let metadata = fs::symlink_metadata(path)
        .map_err(|_| CliError("Cannot inspect an audit history report".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 2 * 1024 * 1024
    {
        return Err(CliError(
            "An audit history report is unsafe or too large".into(),
        ));
    }
    let text = fs::read_to_string(path)
        .map_err(|_| CliError("Cannot read an audit history report".into()))?;
    let report: AuditReport = serde_json::from_str(&text)
        .map_err(|_| CliError("An audit history report is invalid".into()))?;
    if report.schema_version != "baradwatchu.audit.v1"
        || report.completed_at_unix_ms != expected_stamp
        || report.results.len() > 256
    {
        return Err(CliError(
            "An audit history report has invalid metadata".into(),
        ));
    }
    Ok(report)
}

fn history_reports_at(directory: &Path) -> Result<Vec<AuditReport>, CliError> {
    let mut reports = Vec::new();
    for folder in [directory.to_path_buf(), directory.join("reports")] {
        let folder_metadata = match fs::symlink_metadata(&folder) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(CliError("Cannot inspect audit history".into())),
        };
        if !folder_metadata.is_dir() || folder_metadata.file_type().is_symlink() {
            return Err(CliError("Audit history directory is unsafe".into()));
        }
        let entries =
            fs::read_dir(&folder).map_err(|_| CliError("Cannot read audit history".into()))?;
        for entry in entries {
            let entry = entry.map_err(|_| CliError("Cannot read an audit history entry".into()))?;
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != "json") {
                continue;
            }
            let stamp = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u64>().ok())
                .ok_or_else(|| CliError("An audit history filename is invalid".into()))?;
            reports.push(read_history_report(&path, stamp)?);
        }
    }
    reports.sort_by_key(|report| std::cmp::Reverse(report.completed_at_unix_ms));
    reports.dedup_by_key(|report| report.completed_at_unix_ms);
    Ok(reports)
}

fn history_entry(report: &AuditReport) -> AuditHistoryEntry {
    let mut entry = AuditHistoryEntry {
        completed_at_unix_ms: report.completed_at_unix_ms,
        overall_status: "PASS".into(),
        pass: 0,
        fail: 0,
        warn: 0,
        error: 0,
        other: 0,
    };
    for result in &report.results {
        match result.status {
            ResultStatus::Pass => entry.pass += 1,
            ResultStatus::Fail => entry.fail += 1,
            ResultStatus::Warn => entry.warn += 1,
            ResultStatus::Error => entry.error += 1,
            ResultStatus::Disabled | ResultStatus::NotApplicable => entry.other += 1,
        }
    }
    entry.overall_status = if entry.error > 0 {
        "ERROR"
    } else if entry.fail > 0 {
        "FAIL"
    } else if entry.warn > 0 || entry.other > 0 || report.results.is_empty() {
        "WARN"
    } else {
        "PASS"
    }
    .into();
    entry
}

fn human_result(result: &ResultRecord) -> String {
    let mut text = format!(
        "{}  {:<11} {} ({}) — {}\n",
        result.id, result.status, result.name, result.priority, result.summary
    );
    for detail in &result.details {
        for line in detail.lines() {
            text.push_str("    - ");
            text.push_str(line);
            text.push('\n');
        }
    }
    text
}

fn output_json<T: Serialize>(value: &T) -> Result<String, CliError> {
    serde_json::to_string_pretty(value)
        .map(|s| s + "\n")
        .map_err(|_| CliError("Cannot encode JSON output".into()))
}

fn parse_priority(value: &OsString) -> Option<Priority> {
    match value.to_str()?.to_ascii_uppercase().as_str() {
        "HIGHEST" => Some(Priority::Highest),
        "HIGH" => Some(Priority::High),
        "MEDIUM" => Some(Priority::Medium),
        "LOW" => Some(Priority::Low),
        "OPTIONAL" => Some(Priority::Optional),
        _ => None,
    }
}

pub fn run(args: &[OsString]) -> Result<CliOutput, CliError> {
    let catalog = catalog()?;
    let mut settings = load_settings(&catalog)?;
    fn id_of(value: &OsString) -> &str {
        value.to_str().unwrap_or("")
    }
    match args {
        [command] if command == "list" => {
            let list = catalog.requirements.iter().map(|r| {
                let local = settings.requirements.get(&r.id);
                let mut item = r.clone();
                if let Some(local) = local { item.enabled = local.enabled; item.priority = local.priority; item.parameters = local.parameters.clone(); }
                item
            }).collect::<Vec<_>>();
            let text = list.iter().map(|r| format!("{}  {:<8} {:<7} {} — {}\n", r.id, if r.enabled { "enabled" } else { "disabled" }, r.priority, r.name, r.description)).collect();
            Ok(CliOutput { text, code: 0 })
        }
        [command, flag] if command == "list" && flag == "--json" => {
            let list = catalog.requirements.iter().map(|r| { let mut item=r.clone(); if let Some(local)=settings.requirements.get(&r.id) {item.enabled=local.enabled;item.priority=local.priority;item.parameters=local.parameters.clone();} item }).collect::<Vec<_>>();
            Ok(CliOutput { text: output_json(&list)?, code: 0 })
        }
        [command, id] if (command == "enable" || command == "disable") => {
            let id = id_of(id);
            if !catalog.requirements.iter().any(|r| r.id == id) { return Err(CliError(format!("Unknown requirement: {id}"))); }
            let local = settings.requirements.entry(id.into()).or_insert(RequirementSettings { enabled: true, priority: Priority::High, parameters: serde_json::json!({}) });
            local.enabled = command == "enable";
            let enabled = local.enabled;
            save_settings(&settings)?;
            Ok(CliOutput { text: format!("{} {}\n", if enabled { "Enabled" } else { "Disabled" }, id), code: 0 })
        }
        [command, id, priority] if command == "priority" => {
            let id = id_of(id);
            if !catalog.requirements.iter().any(|r| r.id == id) { return Err(CliError(format!("Unknown requirement: {id}"))); }
            let priority = parse_priority(priority).ok_or_else(|| CliError("Priority must be HIGHEST, HIGH, MEDIUM, LOW or OPTIONAL".into()))?;
            let local = settings.requirements.entry(id.into()).or_insert(RequirementSettings { enabled: true, priority, parameters: serde_json::json!({}) });
            local.priority = priority;
            save_settings(&settings)?;
            Ok(CliOutput { text: format!("Priority for {id}: {priority}\n"), code: 0 })
        }
        [command, id, value] if command == "configure" => {
            let id = id_of(id);
            if !catalog.requirements.iter().any(|r| r.id == id) { return Err(CliError(format!("Unknown requirement: {id}"))); }
            if value.to_string_lossy().len() > 16 * 1024 { return Err(CliError("Parameters JSON exceeds 16 KiB".into())); }
            let raw = value.to_str().ok_or_else(|| CliError("Parameters must be UTF-8 JSON".into()))?;
            let parameters: serde_json::Value = serde_json::from_str(raw).map_err(|_| CliError("Parameters must be a JSON object".into()))?;
            if !parameters.is_object() { return Err(CliError("Parameters must be a JSON object".into())); }
            let local = settings.requirements.entry(id.into()).or_insert(RequirementSettings { enabled: true, priority: Priority::High, parameters: serde_json::json!({}) });
            local.parameters = parameters;
            save_settings(&settings)?;
            Ok(CliOutput { text: format!("Parameters saved for {id}\n"), code: 0 })
        }
        [command, id] if command == "check" => run_check(&catalog, &settings, id_of(id), false),
        [command, id, flag] if command == "check" && flag == "--log" => run_check(&catalog, &settings, id_of(id), true),
        [command, options @ ..] if command == "audit" => {
            let (json, notify, include_log) = parse_audit_options(options)?;
            run_audit(&catalog, &settings, json, notify, include_log)
        }
        [command] if command == "status" => {
            match load_last_audit()? {
                Some(report) => { let mut text=report.results.iter().map(human_result).collect::<String>(); if let Some(path)=report.log_file { text.push_str(&format!("\nLog audit: {path}\n")); } Ok(CliOutput {text,code:0}) },
                None => Ok(CliOutput {text:"No audit results saved yet. Run `baradwatchu-agent audit`.\n".into(),code:0}),
            }
        }
        [command, flag] if command == "status" && flag == "--json" => {
            Ok(CliOutput { text: match load_last_audit()? {Some(report)=>output_json(&report)?,None=>"null\n".into()}, code:0 })
        }
        _ => Err(CliError("Usage: list [--json] | enable ID | disable ID | priority ID HIGHEST|HIGH|MEDIUM|LOW|OPTIONAL | configure ID JSON_OBJECT | check ID [--log] | audit [--json] [--notify] [--log] | status [--json] | dashboard | --version".into())),
    }
}

fn result_code(status: &ResultStatus) -> u8 {
    match status {
        ResultStatus::Pass | ResultStatus::NotApplicable | ResultStatus::Disabled => 0,
        ResultStatus::Warn => 4,
        ResultStatus::Fail => 3,
        ResultStatus::Error => 1,
    }
}

fn parse_audit_options(options: &[OsString]) -> Result<(bool, bool, bool), CliError> {
    let (mut json, mut notify, mut log) = (false, false, false);
    for option in options {
        let target = match option.to_str() {
            Some("--json") => &mut json,
            Some("--notify") => &mut notify,
            Some("--log") => &mut log,
            _ => return Err(CliError("Usage: audit [--json] [--notify] [--log]".into())),
        };
        if *target {
            return Err(CliError(
                "Usage: audit [--json] [--notify] [--log] (options cannot be repeated)".into(),
            ));
        }
        *target = true;
    }
    Ok((json, notify, log))
}

fn run_check(
    catalog: &Catalog,
    settings: &Settings,
    id: &str,
    include_log: bool,
) -> Result<CliOutput, CliError> {
    let requirement = catalog
        .requirements
        .iter()
        .find(|requirement| requirement.id == id)
        .ok_or_else(|| CliError(format!("Unknown requirement: {id}")))?;
    let local = settings.requirements.get(&requirement.id);
    let priority = local.map_or(requirement.priority, |value| value.priority);
    let result = if local.is_some_and(|value| !value.enabled) {
        ResultRecord {
            id: requirement.id.clone(),
            name: requirement.name.clone(),
            priority,
            status: ResultStatus::Disabled,
            summary: "Requirement is disabled".into(),
            details: vec![],
            completed_at_unix_ms: now_ms(),
        }
    } else {
        execute(
            requirement,
            priority,
            local.map_or(&requirement.parameters, |value| &value.parameters),
        )
    };
    let mut report = AuditReport {
        schema_version: "baradwatchu.audit.v1".into(),
        completed_at_unix_ms: now_ms(),
        results: vec![result.clone()],
        log_file: None,
    };
    let log_path = save_audit(&mut report, include_log)?;
    let mut text = human_result(&result);
    if let Some(path) = log_path {
        text.push_str(&format!("Log audit: {}\n", path.display()));
    }
    Ok(CliOutput {
        text,
        code: result_code(&result.status),
    })
}

fn run_audit(
    catalog: &Catalog,
    settings: &Settings,
    json: bool,
    notify: bool,
    include_log: bool,
) -> Result<CliOutput, CliError> {
    let mut results = Vec::with_capacity(catalog.requirements.len());
    for requirement in &catalog.requirements {
        let local = settings.requirements.get(&requirement.id);
        let enabled = local.map_or(requirement.enabled, |v| v.enabled);
        let priority = local.map_or(requirement.priority, |v| v.priority);
        let result = if enabled {
            execute(
                requirement,
                priority,
                local.map_or(&requirement.parameters, |v| &v.parameters),
            )
        } else {
            ResultRecord {
                id: requirement.id.clone(),
                name: requirement.name.clone(),
                priority,
                status: ResultStatus::Disabled,
                summary: "Requirement is disabled".into(),
                details: vec![],
                completed_at_unix_ms: now_ms(),
            }
        };
        results.push(result);
    }
    let mut report = AuditReport {
        schema_version: "baradwatchu.audit.v1".into(),
        completed_at_unix_ms: now_ms(),
        results,
        log_file: None,
    };
    let log_path = save_audit(&mut report, include_log)?;
    if notify {
        send_notification(&report);
    }
    let code = if report
        .results
        .iter()
        .any(|r| r.status == ResultStatus::Error)
    {
        1
    } else if report
        .results
        .iter()
        .any(|r| r.status == ResultStatus::Fail)
    {
        3
    } else if report
        .results
        .iter()
        .any(|r| r.status == ResultStatus::Warn)
    {
        4
    } else {
        0
    };
    let text = if json {
        output_json(&report)?
    } else {
        let mut text = report.results.iter().map(human_result).collect::<String>();
        if let Some(path) = log_path {
            text.push_str(&format!("\nLog audit: {}\n", path.display()));
        }
        text
    };
    Ok(CliOutput { text, code })
}

pub(crate) fn dashboard_data_json() -> Result<String, CliError> {
    let catalog = catalog()?;
    let settings = load_settings(&catalog)?;
    let requirements = catalog
        .requirements
        .iter()
        .map(|requirement| {
            let mut item = requirement.clone();
            if let Some(local) = settings.requirements.get(&item.id) {
                item.enabled = local.enabled;
                item.priority = local.priority;
                item.parameters = local.parameters.clone();
            }
            item
        })
        .collect::<Vec<_>>();
    output_json(
        &serde_json::json!({"schemaVersion":"baradwatchu.dashboard.v1","requirements":requirements}),
    )
}

pub(crate) fn update_dashboard_settings(text: &str) -> Result<String, CliError> {
    if text.len() > 64 * 1024 {
        return Err(CliError("Settings request is too large".into()));
    }
    let catalog = catalog()?;
    let settings: Settings =
        serde_json::from_str(text).map_err(|_| CliError("Settings JSON is invalid".into()))?;
    if settings.schema_version != "baradwatchu.settings.v1"
        || settings.requirements.len() != catalog.requirements.len()
        || settings
            .requirements
            .keys()
            .any(|id| !catalog.requirements.iter().any(|r| &r.id == id))
        || settings
            .requirements
            .values()
            .any(|item| !item.parameters.is_object())
    {
        return Err(CliError(
            "Settings must contain exactly the known requirement IDs".into(),
        ));
    }
    save_settings(&settings)?;
    dashboard_data_json()
}

pub(crate) fn dashboard_audit_json() -> Result<String, CliError> {
    let catalog = catalog()?;
    let settings = load_settings(&catalog)?;
    Ok(run_audit(&catalog, &settings, true, true, false)?.text)
}

pub(crate) fn dashboard_check_json(id: &str) -> Result<String, CliError> {
    let catalog = catalog()?;
    let settings = load_settings(&catalog)?;
    let requirement = catalog
        .requirements
        .iter()
        .find(|r| r.id == id)
        .ok_or_else(|| CliError(format!("Unknown requirement: {id}")))?;
    let local = settings.requirements.get(&requirement.id);
    let priority = local.map_or(requirement.priority, |v| v.priority);
    let result = if local.is_some_and(|v| !v.enabled) {
        ResultRecord {
            id: requirement.id.clone(),
            name: requirement.name.clone(),
            priority,
            status: ResultStatus::Disabled,
            summary: "Requisito disabilitato".into(),
            details: vec![],
            completed_at_unix_ms: now_ms(),
        }
    } else {
        execute(
            requirement,
            priority,
            local.map_or(&requirement.parameters, |v| &v.parameters),
        )
    };
    let mut report = AuditReport {
        schema_version: "baradwatchu.audit.v1".into(),
        completed_at_unix_ms: now_ms(),
        results: vec![result],
        log_file: None,
    };
    save_audit(&mut report, false)?;
    output_json(&report)
}

pub(crate) fn dashboard_status_json() -> Result<String, CliError> {
    match load_last_audit()? {
        Some(report) => output_json(&report),
        None => Ok("null\n".into()),
    }
}

pub(crate) fn dashboard_history_json() -> Result<String, CliError> {
    let entries = history_reports_at(&history_dir()?).map(|reports| {
        reports
            .iter()
            .take(50)
            .map(history_entry)
            .collect::<Vec<_>>()
    })?;
    output_json(&entries)
}

pub(crate) fn dashboard_history_report_json(stamp: &str) -> Result<String, CliError> {
    if stamp.is_empty() || !stamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError("Invalid audit history identifier".into()));
    }
    let stamp = stamp
        .parse::<u64>()
        .map_err(|_| CliError("Invalid audit history identifier".into()))?;
    let directory = history_dir()?;
    for path in [
        directory.join("reports").join(format!("{stamp}.json")),
        directory.join(format!("{stamp}.json")),
    ] {
        match fs::symlink_metadata(&path) {
            Ok(_) => return output_json(&read_history_report(&path, stamp)?),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(CliError("Cannot inspect the selected audit".into())),
        }
    }
    Err(CliError("Audit not found in local history".into()))
}

fn send_notification(report: &AuditReport) {
    let mut counts = BTreeMap::<&str, usize>::new();
    for result in &report.results {
        *counts
            .entry(match result.status {
                ResultStatus::Pass => "PASS",
                ResultStatus::Fail => "FAIL",
                ResultStatus::Warn => "WARN",
                ResultStatus::Error => "ERROR",
                ResultStatus::Disabled => "DISABLED",
                ResultStatus::NotApplicable => "NOT_APPLICABLE",
            })
            .or_default() += 1;
    }
    let body = format!(
        "PASS: {} · FAIL: {} · WARN: {} · ERROR: {}",
        counts.get("PASS").unwrap_or(&0),
        counts.get("FAIL").unwrap_or(&0),
        counts.get("WARN").unwrap_or(&0),
        counts.get("ERROR").unwrap_or(&0)
    );
    let _ = std::process::Command::new("/usr/bin/notify-send")
        .args([
            "--app-name=BaradWatchU",
            "--urgency=normal",
            "Audit completato",
            &body,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn help() -> String {
    format!("BaradWatchU Client {}\n\nUsage:\n  baradwatchu-agent list [--json]\n  baradwatchu-agent enable ID\n  baradwatchu-agent disable ID\n  baradwatchu-agent priority ID HIGHEST|HIGH|MEDIUM|LOW|OPTIONAL\n  baradwatchu-agent configure ID JSON_OBJECT\n  baradwatchu-agent check ID [--log]\n  baradwatchu-agent audit [--json] [--notify] [--log]\n  baradwatchu-agent status [--json]\n  baradwatchu-agent dashboard\n  baradwatchu-agent --version\n\nUse --log to write a plain-text audit log; structured reports are kept locally. Audits run without the dashboard or Server. REQ-001 may contact Arch mirrors via checkupdates. Tools run directly as the current user.\n", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shipped_catalog_has_unique_ids_safe_paths_and_nine_requirements() {
        let catalog = catalog().unwrap();
        assert_eq!(catalog.requirements.len(), 9);
        assert_eq!(
            catalog
                .requirements
                .iter()
                .map(|r| r.id.as_str())
                .collect::<std::collections::BTreeSet<_>>()
                .len(),
            9
        );
        assert!(catalog
            .requirements
            .iter()
            .flat_map(|r| r.tools.values())
            .all(|p| safe_relative_path(p)));
    }

    #[test]
    fn tool_path_cannot_escape_installation() {
        for path in ["../tool", "/usr/bin/bash", "tools/../x", "", "tools//check"] {
            assert!(!safe_relative_path(path), "{path}");
        }
        assert!(safe_relative_path(
            "share/baradwatchu-client/tools/linux/check.sh"
        ));
    }

    #[test]
    fn priority_levels_round_trip() {
        for (label, expected) in [
            ("HIGHEST", "HIGHEST"),
            ("HIGH", "HIGH"),
            ("MEDIUM", "MEDIUM"),
            ("LOW", "LOW"),
            ("OPTIONAL", "OPTIONAL"),
        ] {
            let value = OsString::from(label);
            assert_eq!(parse_priority(&value).unwrap().to_string(), expected);
        }
    }

    #[test]
    fn audit_options_allow_log_with_json_and_notification() {
        let options = ["--notify", "--log", "--json"].map(OsString::from);
        assert_eq!(parse_audit_options(&options).unwrap(), (true, true, true));
        assert!(parse_audit_options(&[OsString::from("--log"), OsString::from("--log")]).is_err());
        assert!(parse_audit_options(&[OsString::from("--verbose")]).is_err());
    }

    #[test]
    fn audit_log_is_plain_text_and_includes_command_diagnostics() {
        let result = ResultRecord {
            id: "REQ-009".into(),
            name: "Sicurezza di avvio".into(),
            priority: Priority::Optional,
            status: ResultStatus::Warn,
            summary: "Secure Boot non determinabile".into(),
            details: vec![
                "Tool eseguito: /opt/baradwatchu/tools/linux/boot-security/check.sh".into(),
                "Comando: /usr/bin/mokutil --sb-state".into(),
                "Codice uscita: 127".into(),
                "Output: mokutil non è installato".into(),
            ],
            completed_at_unix_ms: 1,
        };
        let log = human_result(&result);
        assert!(log.starts_with("REQ-009  WARN"));
        assert!(log.contains("Comando: /usr/bin/mokutil --sb-state"));
        assert!(log.contains("Codice uscita: 127"));
        assert!(!log.trim_start().starts_with('{'));
    }

    #[test]
    fn audit_report_is_saved_without_text_log_unless_requested() {
        let directory = std::env::temp_dir().join(format!(
            "baradwatchu-log-option-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let mut report = AuditReport {
            schema_version: "baradwatchu.audit.v1".into(),
            completed_at_unix_ms: now_ms(),
            results: vec![],
            log_file: None,
        };
        let log_path = save_audit_at(&directory, &mut report, false).unwrap();
        assert!(log_path.is_none());
        assert!(report.log_file.is_none());
        assert!(!directory
            .join(format!("{}.log", report.completed_at_unix_ms))
            .exists());
        assert!(directory
            .join("reports")
            .join(format!("{}.json", report.completed_at_unix_ms))
            .is_file());

        report.completed_at_unix_ms += 1;
        let log_path = save_audit_at(&directory, &mut report, true)
            .unwrap()
            .unwrap();
        assert!(log_path.is_file());
        assert_eq!(report.log_file.as_deref(), Some(log_path.to_str().unwrap()));
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn dashboard_history_lists_reports_newest_first_and_validates_selected_report() {
        let directory = std::env::temp_dir().join(format!(
            "baradwatchu-dashboard-history-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let reports = directory.join("reports");
        fs::create_dir_all(&reports).unwrap();
        for (stamp, status) in [(100, ResultStatus::Pass), (200, ResultStatus::Warn)] {
            let report = AuditReport {
                schema_version: "baradwatchu.audit.v1".into(),
                completed_at_unix_ms: stamp,
                results: vec![ResultRecord {
                    id: "REQ-001".into(),
                    name: "Aggiornamenti software".into(),
                    priority: Priority::High,
                    status,
                    summary: "Fixture result".into(),
                    details: vec!["Diagnostic fixture".into()],
                    completed_at_unix_ms: stamp,
                }],
                log_file: None,
            };
            fs::write(
                reports.join(format!("{stamp}.json")),
                serde_json::to_vec(&report).unwrap(),
            )
            .unwrap();
        }

        let history = history_reports_at(&directory).unwrap();
        assert_eq!(history.len(), 2);
        assert_eq!(history[0].completed_at_unix_ms, 200);
        assert_eq!(history_entry(&history[0]).overall_status, "WARN");
        assert_eq!(history_entry(&history[1]).pass, 1);
        assert_eq!(
            read_history_report(&reports.join("100.json"), 100)
                .unwrap()
                .results[0]
                .details[0],
            "Diagnostic fixture"
        );
        assert!(read_history_report(&reports.join("100.json"), 200).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
