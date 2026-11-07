//! Small local requirement runner used by the user-facing CLI.
//! Tools are package-owned executables and are launched directly, without a shell.
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    #[serde(default)]
    pub arguments: Vec<String>,
    pub tools: BTreeMap<String, String>,
    #[serde(default)]
    pub origin: ControlOrigin,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_sha256: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub replaces_builtin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_tool_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_tool_version: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builtin_tool_path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual_sha256: Option<String>,
    #[serde(default)]
    pub integrity_status: IntegrityStatus,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlOrigin {
    #[default]
    Builtin,
    Custom,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum IntegrityStatus {
    Verified,
    Mismatch,
    #[default]
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ControlProvenance {
    pub tool_id: String,
    pub tool_version: Option<u64>,
    pub origin: ControlOrigin,
    pub tool_path: Option<String>,
    pub expected_sha256: Option<String>,
    pub actual_sha256: Option<String>,
    pub integrity_status: IntegrityStatus,
    pub integrity_scope: String,
    pub is_override: bool,
    pub override_builtin_id: Option<String>,
    pub builtin_tool_path: Option<String>,
    pub builtin_expected_sha256: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    schema_version: String,
    requirements: Vec<Requirement>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CustomRegistry {
    schema_version: String,
    checks: Vec<CustomEntry>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CustomEntry {
    id: String,
    name: String,
    description: String,
    priority: Priority,
    enabled: bool,
    tool_path: String,
    #[serde(default)]
    arguments: Vec<String>,
    expected_sha256: String,
    version: u64,
    #[serde(default)]
    parameters: serde_json::Value,
    #[serde(default)]
    override_builtin_id: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ImportRequest {
    id: String,
    name: String,
    description: String,
    priority: Priority,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    override_builtin_id: Option<String>,
    #[serde(default)]
    clone_from: Option<String>,
    file_name: String,
    file_base64: String,
    #[serde(default)]
    arguments: Vec<String>,
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

#[derive(Clone, Copy, Debug, Deserialize)]
enum CustomToolStatus {
    #[serde(rename = "PASS")]
    Pass,
    #[serde(rename = "WARNING")]
    Warning,
    #[serde(rename = "FAIL")]
    Fail,
    #[serde(rename = "ERROR")]
    Error,
}

impl From<CustomToolStatus> for ResultStatus {
    fn from(status: CustomToolStatus) -> Self {
        match status {
            CustomToolStatus::Pass => Self::Pass,
            CustomToolStatus::Warning => Self::Warn,
            CustomToolStatus::Fail => Self::Fail,
            CustomToolStatus::Error => Self::Error,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(untagged)]
enum CustomToolDetails {
    One(String),
    Many(Vec<String>),
}

impl CustomToolDetails {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::One(detail) => vec![detail],
            Self::Many(details) => details,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CustomToolResult {
    status: CustomToolStatus,
    summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    details: Option<CustomToolDetails>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ResultRecord {
    pub id: String,
    pub name: String,
    pub priority: Priority,
    pub status: ResultStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compliance_status: Option<ResultStatus>,
    pub summary: String,
    pub details: Vec<String>,
    pub completed_at_unix_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provenance: Option<ControlProvenance>,
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

struct TemporaryTool(PathBuf);
impl Drop for TemporaryTool {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn catalog() -> Result<Catalog, CliError> {
    // Discover controls from their folders on every call. `refresh` deliberately calls
    // this same scanner; there is no persisted/in-memory registry to go stale.
    let install = install_root()?;
    let requirements = discover_builtin_checks(&install)?;
    if requirements.is_empty() {
        return Err(CliError("No built-in check folders were discovered".into()));
    }
    let mut value = Catalog {
        schema_version: "baradwatchu.requirements.v1".into(),
        requirements,
    };
    let registry = load_custom_registry()?;
    let builtin_ids = value
        .requirements
        .iter()
        .map(|r| r.id.clone())
        .collect::<std::collections::BTreeSet<_>>();
    let mut seen_custom = std::collections::BTreeSet::new();
    let mut seen_overrides = std::collections::BTreeSet::new();
    for entry in registry.checks {
        if !valid_custom_id(&entry.id)
            || !seen_custom.insert(entry.id.clone())
            || entry.name.trim().is_empty()
            || entry.name.len() > 160
            || entry.description.len() > 2048
            || !entry.parameters.is_object()
            || entry.expected_sha256.len() != 64
            || !entry.expected_sha256.bytes().all(|b| b.is_ascii_hexdigit())
            || !safe_relative_path(&entry.tool_path)
        {
            return Err(CliError(
                "Custom-check registry contains an invalid entry".into(),
            ));
        }
        if let Some(target) = entry.override_builtin_id.as_deref() {
            if !builtin_ids.contains(target) || !seen_overrides.insert(target.to_owned()) {
                return Err(CliError(
                    "Custom-check override target is invalid or duplicated".into(),
                ));
            }
            let builtin = value
                .requirements
                .iter_mut()
                .find(|r| r.id == target)
                .unwrap();
            builtin.builtin_tool_path = builtin.tools.get(platform_key()).cloned();
            builtin.tools.insert(platform_key().into(), entry.tool_path);
            builtin.expected_sha256 = Some(entry.expected_sha256);
            builtin.arguments = entry.arguments;
            builtin.origin = ControlOrigin::Custom;
            builtin.replaces_builtin = Some(target.to_owned());
            builtin.custom_tool_id = Some(entry.id);
            builtin.custom_tool_version = Some(entry.version);
            builtin.enabled = entry.enabled;
        } else {
            let mut tools = BTreeMap::new();
            tools.insert(platform_key().into(), entry.tool_path);
            value.requirements.push(Requirement {
                id: entry.id.clone(),
                name: entry.name,
                description: entry.description,
                enabled: entry.enabled,
                priority: entry.priority,
                parameters: entry.parameters,
                arguments: entry.arguments,
                tools,
                origin: ControlOrigin::Custom,
                expected_sha256: Some(entry.expected_sha256),
                replaces_builtin: None,
                custom_tool_id: Some(entry.id),
                custom_tool_version: Some(entry.version),
                builtin_tool_path: None,
                actual_sha256: None,
                integrity_status: IntegrityStatus::Unknown,
            });
        }
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

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckConfiguration {
    schema_version: String,
    id: String,
    name: String,
    description: String,
    priority: Priority,
    enabled: bool,
    tool_path: String,
    #[serde(default)]
    arguments: Vec<String>,
    #[serde(default = "empty_parameters")]
    parameters: serde_json::Value,
    #[serde(default)]
    expected_sha256: Option<String>,
    #[serde(default)]
    version: Option<u64>,
    #[serde(default)]
    override_builtin_id: Option<String>,
}

fn discover_check_folders(parent: &Path) -> Result<Vec<(PathBuf, CheckConfiguration)>, CliError> {
    let metadata = match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => metadata,
        Ok(_) => return Err(CliError("Check folder root is unsafe".into())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(CliError("Cannot inspect check folders".into())),
    };
    let _ = metadata;
    let mut discovered = Vec::new();
    for entry in fs::read_dir(parent).map_err(|_| CliError("Cannot scan check folders".into()))? {
        let entry = entry.map_err(|_| CliError("Cannot read check folder".into()))?;
        let folder = entry.path();
        let meta = fs::symlink_metadata(&folder)
            .map_err(|_| CliError("Cannot inspect a check folder".into()))?;
        if !meta.is_dir() || meta.file_type().is_symlink() {
            continue;
        }
        let config = folder.join("configuration.json");
        let meta = match fs::symlink_metadata(&config) {
            Ok(meta)
                if meta.is_file() && !meta.file_type().is_symlink() && meta.len() <= 64 * 1024 =>
            {
                meta
            }
            Ok(_) => continue,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(CliError("Cannot inspect check configuration".into())),
        };
        let _ = meta;
        let bytes =
            fs::read(&config).map_err(|_| CliError("Cannot read check configuration".into()))?;
        let parsed: CheckConfiguration = serde_json::from_slice(&bytes).map_err(|_| {
            CliError(format!(
                "Invalid configuration.json in {}",
                folder.display()
            ))
        })?;
        if parsed.schema_version != "baradwatchu.custom-checks.v1"
            || parsed.id != entry.file_name().to_string_lossy()
            || parsed.name.trim().is_empty()
            || parsed.name.len() > 160
            || parsed.description.len() > 2048
            || !parsed.parameters.is_object()
            || parsed.arguments.len() > 64
            || parsed.arguments.iter().any(|arg| arg.len() > 4096)
            || !safe_relative_path(&parsed.tool_path)
        {
            return Err(CliError(format!(
                "Invalid check configuration for {}",
                parsed.id
            )));
        }
        discovered.push((folder, parsed));
    }
    discovered.sort_by(|a, b| a.1.id.cmp(&b.1.id));
    Ok(discovered)
}

fn discover_builtin_checks(install: &Path) -> Result<Vec<Requirement>, CliError> {
    let parent = install.join("share/baradwatchu-client/catalog/checks");
    let mut requirements = Vec::new();
    for (folder, config) in discover_check_folders(&parent)? {
        let trusted_hash = builtin_hash(&config.id, platform_key());
        if config.expected_sha256.as_deref() != trusted_hash.as_deref() {
            return Err(CliError(format!(
                "Trusted hash mismatch in configuration for {}",
                config.id
            )));
        }
        let tool = folder
            .join(&config.tool_path)
            .canonicalize()
            .map_err(|_| CliError(format!("Tool missing for {}", config.id)))?;
        let root = install
            .canonicalize()
            .map_err(|_| CliError("Cannot locate Client installation".into()))?;
        if !tool.starts_with(&root) || !tool.is_file() {
            return Err(CliError(format!("Unsafe tool path for {}", config.id)));
        }
        let relative = tool
            .strip_prefix(&root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        requirements.push(Requirement {
            id: config.id.clone(),
            name: config.name,
            description: config.description,
            enabled: config.enabled,
            priority: config.priority,
            parameters: config.parameters,
            arguments: config.arguments,
            tools: BTreeMap::from([(platform_key().into(), relative)]),
            origin: ControlOrigin::Builtin,
            expected_sha256: trusted_hash,
            replaces_builtin: None,
            custom_tool_id: None,
            custom_tool_version: None,
            builtin_tool_path: None,
            actual_sha256: None,
            integrity_status: IntegrityStatus::Unknown,
        });
    }
    Ok(requirements)
}

fn valid_custom_id(id: &str) -> bool {
    id.starts_with("CUSTOM-")
        && id.len() <= 64
        && id[7..]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
        && id.len() > 7
}

fn load_custom_registry() -> Result<CustomRegistry, CliError> {
    let root = state_dir()?;
    let mut checks = Vec::new();
    for (folder, config) in discover_check_folders(&root.join("custom-tools"))? {
        if !valid_custom_id(&config.id) {
            return Err(CliError(format!("Invalid custom check ID: {}", config.id)));
        }
        let local_tool = config
            .tool_path
            .strip_prefix("./")
            .unwrap_or(&config.tool_path);
        checks.push(CustomEntry {
            id: config.id,
            name: config.name,
            description: config.description,
            priority: config.priority,
            enabled: config.enabled,
            tool_path: format!(
                "custom-tools/{}/{}",
                folder.file_name().unwrap().to_string_lossy(),
                local_tool
            ),
            arguments: config.arguments,
            expected_sha256: config.expected_sha256.unwrap_or_default(),
            version: config.version.unwrap_or(1),
            parameters: config.parameters,
            override_builtin_id: config.override_builtin_id,
        });
    }
    if checks.len() > 256 {
        return Err(CliError("Too many custom check folders".into()));
    }
    Ok(CustomRegistry {
        schema_version: "baradwatchu.custom-checks.v1".into(),
        checks,
    })
}

fn decode_base64(value: &str) -> Result<Vec<u8>, CliError> {
    let mut output = Vec::with_capacity(value.len() * 3 / 4);
    let mut chunk = [0u8; 4];
    let bytes = value.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 != 0 || bytes.len() > 1_500_000 {
        return Err(CliError(
            "Tool file encoding is invalid or too large".into(),
        ));
    }
    let group_count = bytes.len() / 4;
    for (group_index, group) in bytes.chunks_exact(4).enumerate() {
        let last_group = group_index + 1 == group_count;
        if group[0] == b'='
            || group[1] == b'='
            || (group[2] == b'=' && group[3] != b'=')
            || (!last_group && (group[2] == b'=' || group[3] == b'='))
        {
            return Err(CliError("Tool file encoding is invalid".into()));
        }
        for (i, b) in group.iter().enumerate() {
            chunk[i] = match *b {
                b'A'..=b'Z' => *b - b'A',
                b'a'..=b'z' => *b - b'a' + 26,
                b'0'..=b'9' => *b - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if i >= 2 => 0,
                _ => return Err(CliError("Tool file encoding is invalid".into())),
            };
        }
        if group[2] == b'=' && chunk[1] & 0x0f != 0
            || group[3] == b'=' && group[2] != b'=' && chunk[2] & 0x03 != 0
        {
            return Err(CliError("Tool file encoding is invalid".into()));
        }
        output.push((chunk[0] << 2) | (chunk[1] >> 4));
        if group[2] != b'=' {
            output.push((chunk[1] << 4) | (chunk[2] >> 2));
        }
        if group[3] != b'=' {
            output.push((chunk[2] << 6) | chunk[3]);
        }
        if output.len() > 1024 * 1024 {
            return Err(CliError("Tool file exceeds 1 MiB".into()));
        }
    }
    if output.is_empty() {
        return Err(CliError("Tool file is empty".into()));
    }
    Ok(output)
}

fn save_custom_entry(entry: &CustomEntry) -> Result<(), CliError> {
    let folder = state_dir()?.join("custom-tools").join(&entry.id);
    fs::create_dir_all(&folder)
        .map_err(|_| CliError("Cannot create custom check folder".into()))?;
    secure_dir(folder.parent().unwrap())?;
    secure_dir(&folder)?;
    let prefix = format!("custom-tools/{}/", entry.id);
    let local_tool = entry
        .tool_path
        .strip_prefix(&prefix)
        .ok_or_else(|| CliError("Invalid custom tool path".into()))?;
    let config = serde_json::json!({
        "schemaVersion":"baradwatchu.custom-checks.v1", "id":entry.id, "name":entry.name,
        "description":entry.description, "priority":entry.priority, "enabled":entry.enabled,
        "toolPath":format!("./{local_tool}"), "arguments":entry.arguments,
        "expectedSha256":entry.expected_sha256, "version":entry.version,
        "parameters":entry.parameters, "overrideBuiltinId":entry.override_builtin_id
    });
    atomic_json(&folder.join("configuration.json"), &config)
}

fn store_custom_tool(id: &str, bytes: &[u8]) -> Result<(String, String), CliError> {
    let directory = state_dir()?;
    let tools = directory.join("custom-tools").join(id);
    fs::create_dir_all(&tools)
        .map_err(|_| CliError("Cannot create custom tool directory".into()))?;
    secure_dir(&directory)?;
    secure_dir(tools.parent().unwrap())?;
    secure_dir(&tools)?;
    let relative = format!("custom-tools/{id}/{id}.tool");
    let path = directory.join(&relative);
    let temp = tools.join(format!(".tmp-{}-{}", std::process::id(), now_ms()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o700);
    }
    let mut file = options
        .open(&temp)
        .map_err(|_| CliError("Cannot stage custom tool".into()))?;
    file.write_all(bytes)
        .and_then(|_| file.sync_all())
        .map_err(|_| CliError("Cannot write custom tool".into()))?;
    fs::rename(&temp, &path).map_err(|_| CliError("Cannot install custom tool".into()))?;
    Ok((
        relative,
        sha256_bytes(bytes).ok_or_else(|| CliError("Cannot calculate SHA-256".into()))?,
    ))
}

pub(crate) fn dashboard_import_custom(text: &str) -> Result<String, CliError> {
    if text.len() > 2 * 1024 * 1024 {
        return Err(CliError("Import request exceeds 2 MiB".into()));
    }
    let request: ImportRequest = serde_json::from_str(text)
        .map_err(|_| CliError("Custom-check import is invalid".into()))?;
    if !valid_custom_id(&request.id)
        || request.name.trim().is_empty()
        || request.name.len() > 160
        || request.description.len() > 2048
        || request.file_name.is_empty()
        || request.file_name.len() > 255
        || request.arguments.len() > 64
        || request.arguments.iter().any(|arg| arg.len() > 4096)
        || Path::new(&request.file_name)
            .file_name()
            .and_then(|n| n.to_str())
            != Some(request.file_name.as_str())
    {
        return Err(CliError(
            "Custom-check ID, name or description is invalid".into(),
        ));
    }
    let bytes = decode_base64(&request.file_base64)?;
    let catalog = catalog()?;
    let mut registry = load_custom_registry()?;
    if registry.checks.iter().any(|c| c.id == request.id) {
        return Err(CliError("Custom-check ID already exists".into()));
    }
    if let Some(target) = request.override_builtin_id.as_deref() {
        if !catalog
            .requirements
            .iter()
            .any(|r| r.id == target && r.origin == ControlOrigin::Builtin)
            || registry
                .checks
                .iter()
                .any(|c| c.override_builtin_id.as_deref() == Some(target))
        {
            return Err(CliError(
                "Override target is unknown or already overridden".into(),
            ));
        }
    }
    if let Some(base) = request.clone_from.as_deref() {
        if !catalog.requirements.iter().any(|r| r.id == base) {
            return Err(CliError("Clone source requirement is unknown".into()));
        }
    }
    let (tool_path, expected_sha256) = store_custom_tool(&request.id, &bytes)?;
    registry.checks.push(CustomEntry {
        id: request.id,
        name: request.name,
        description: request.description,
        priority: request.priority,
        enabled: request.enabled.unwrap_or(true),
        tool_path,
        expected_sha256,
        version: 1,
        arguments: request.arguments,
        parameters: serde_json::json!({}),
        override_builtin_id: request.override_builtin_id,
    });
    save_custom_entry(registry.checks.last().unwrap())?;
    dashboard_data_json()
}

pub(crate) fn dashboard_remove_custom(id: &str) -> Result<String, CliError> {
    let mut registry = load_custom_registry()?;
    let Some(index) = registry.checks.iter().position(|c| c.id == id) else {
        return Err(CliError("Custom check not found".into()));
    };
    registry.checks.remove(index);
    let folder = state_dir()?.join("custom-tools").join(id);
    fs::remove_dir_all(folder).map_err(|_| CliError("Cannot remove custom check folder".into()))?;
    remove_local_requirement_setting(id)?;
    dashboard_data_json()
}

pub(crate) fn dashboard_restore_builtin(id: &str) -> Result<String, CliError> {
    let mut registry = load_custom_registry()?;
    let entry = registry
        .checks
        .iter_mut()
        .find(|c| c.override_builtin_id.as_deref() == Some(id))
        .ok_or_else(|| CliError("No override exists for this built-in requirement".into()))?;
    entry.override_builtin_id = None;
    save_custom_entry(entry)?;
    dashboard_data_json()
}

pub(crate) fn dashboard_update_custom(id: &str, text: &str) -> Result<String, CliError> {
    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    #[serde(deny_unknown_fields)]
    struct Update {
        file_base64: String,
    }
    if text.len() > 2 * 1024 * 1024 {
        return Err(CliError("Update request exceeds 2 MiB".into()));
    }
    let update: Update =
        serde_json::from_str(text).map_err(|_| CliError("Custom tool update is invalid".into()))?;
    let bytes = decode_base64(&update.file_base64)?;
    let mut registry = load_custom_registry()?;
    let entry = registry
        .checks
        .iter_mut()
        .find(|c| c.id == id)
        .ok_or_else(|| CliError("Custom check not found".into()))?;
    let (path, hash) = store_custom_tool(id, &bytes)?;
    entry.tool_path = path;
    entry.expected_sha256 = hash;
    entry.version = entry.version.saturating_add(1);
    save_custom_entry(entry)?;
    dashboard_data_json()
}

fn builtin_hash(id: &str, platform: &str) -> Option<String> {
    include_str!("../../../catalog/builtin-tools.sha256")
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((
                fields.next()?,
                fields.next()?,
                fields.next()?,
                fields.next()?,
            ))
        })
        .find(|(entry_id, entry_platform, _, _)| *entry_id == id && *entry_platform == platform)
        .map(|(_, _, _, hash)| hash.to_owned())
}

fn sha256_bytes(bytes: &[u8]) -> Option<String> {
    Some(format!("{:x}", Sha256::digest(bytes)))
}

fn control_provenance(requirement: &Requirement) -> ControlProvenance {
    let root = if requirement.origin == ControlOrigin::Builtin {
        install_root().ok()
    } else {
        state_dir().ok()
    };
    let relative = requirement.tools.get(platform_key());
    let resolved = root.as_ref().zip(relative).and_then(|(root, relative)| {
        if !safe_relative_path(relative) {
            return None;
        }
        let path = root.join(relative);
        match path.canonicalize() {
            Ok(canonical) if canonical.starts_with(root) => Some(canonical),
            Ok(_) => None,
            Err(_) => Some(path),
        }
    });
    let tool_path = resolved.as_ref().map(|path| path.display().to_string());
    let actual_sha256 = resolved.as_ref().and_then(|path| {
        let metadata = fs::symlink_metadata(path).ok()?;
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > 4 * 1024 * 1024
        {
            return None;
        }
        sha256_bytes(&fs::read(path).ok()?)
    });
    let builtin_tool_path = requirement.builtin_tool_path.as_ref().and_then(|relative| {
        let root = install_root().ok()?;
        safe_relative_path(relative).then(|| root.join(relative).display().to_string())
    });
    let integrity_status = match (&requirement.expected_sha256, &actual_sha256) {
        (Some(expected), Some(actual)) if expected.eq_ignore_ascii_case(actual) => {
            IntegrityStatus::Verified
        }
        (Some(_), Some(_)) => IntegrityStatus::Mismatch,
        _ => IntegrityStatus::Unknown,
    };
    ControlProvenance {
        tool_id: requirement
            .custom_tool_id
            .clone()
            .unwrap_or_else(|| requirement.id.clone()),
        tool_version: requirement.custom_tool_version,
        origin: requirement.origin,
        tool_path,
        expected_sha256: requirement.expected_sha256.clone(),
        actual_sha256,
        integrity_status,
        integrity_scope: "ENTRYPOINT_FILE_ONLY".into(),
        is_override: requirement.replaces_builtin.is_some(),
        override_builtin_id: requirement.replaces_builtin.clone(),
        builtin_tool_path,
        builtin_expected_sha256: requirement
            .replaces_builtin
            .as_deref()
            .and_then(|id| builtin_hash(id, platform_key())),
    }
}

fn attach_provenance(result: &mut ResultRecord, requirement: &Requirement) {
    result.compliance_status = Some(result.status);
    if result.provenance.is_none() {
        result.provenance = Some(control_provenance(requirement));
    }
}

fn safe_relative_path(value: &str) -> bool {
    let path = Path::new(value);
    !path.as_os_str().is_empty()
        && !value.contains("//")
        && path
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir))
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
    let mut settings: Settings = serde_json::from_str(&text)
        .map_err(|_| CliError("Local settings JSON is invalid".into()))?;
    if settings.schema_version != "baradwatchu.settings.v1"
        || settings
            .requirements
            .values()
            .any(|item| !item.parameters.is_object())
    {
        return Err(CliError(
            "Local settings do not match this Client catalog".into(),
        ));
    }
    // Folder discovery can add or remove controls independently of settings. Ignore
    // settings for folders that no longer exist so a forced refresh can recover.
    settings.requirements.retain(|id, _| {
        catalog
            .requirements
            .iter()
            .any(|requirement| &requirement.id == id)
    });
    for requirement in &catalog.requirements {
        settings
            .requirements
            .entry(requirement.id.clone())
            .or_insert_with(|| RequirementSettings {
                enabled: requirement.enabled,
                priority: requirement.priority,
                parameters: requirement.parameters.clone(),
            });
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

fn remove_local_requirement_setting(id: &str) -> Result<(), CliError> {
    let path = state_dir()?.join("settings.json");
    if !path.exists() {
        return Ok(());
    }
    let text =
        fs::read_to_string(&path).map_err(|_| CliError("Cannot read local settings".into()))?;
    let mut settings: Settings = serde_json::from_str(&text)
        .map_err(|_| CliError("Local settings JSON is invalid".into()))?;
    if settings.schema_version != "baradwatchu.settings.v1" {
        return Err(CliError("Unsupported local settings".into()));
    }
    settings.requirements.remove(id);
    save_settings(&settings)
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
        compliance_status: None,
        summary: summary.into(),
        details: vec![],
        completed_at_unix_ms: now_ms(),
        provenance: None,
    }
}

fn execute(
    requirement: &Requirement,
    priority: Priority,
    parameters: &serde_json::Value,
) -> ResultRecord {
    execute_with_timeout(requirement, priority, parameters, TOOL_TIMEOUT)
}

fn execute_with_timeout(
    requirement: &Requirement,
    priority: Priority,
    parameters: &serde_json::Value,
    timeout: Duration,
) -> ResultRecord {
    let Some(relative) = requirement.tools.get(platform_key()) else {
        return ResultRecord {
            id: requirement.id.clone(),
            name: requirement.name.clone(),
            priority,
            status: ResultStatus::NotApplicable,
            compliance_status: None,
            summary: "No tool is available for this operating system".into(),
            details: vec![],
            completed_at_unix_ms: now_ms(),
            provenance: None,
        };
    };
    if !safe_relative_path(relative) {
        return error_result(requirement, priority, "Tool path is invalid");
    }
    let root = match if requirement.origin == ControlOrigin::Builtin {
        install_root()
    } else {
        state_dir()
    } {
        Ok(root) => root,
        Err(_) => return error_result(requirement, priority, "Cannot locate Client installation"),
    };
    let root = match root.canonicalize() {
        Ok(root) => root,
        Err(_) => return error_result(requirement, priority, "Cannot locate Client installation"),
    };
    if requirement.origin != ControlOrigin::Builtin {
        let managed_tools = root.join("custom-tools");
        if fs::symlink_metadata(&managed_tools)
            .map(|m| !m.is_dir() || m.file_type().is_symlink())
            .unwrap_or(true)
        {
            return error_result(
                requirement,
                priority,
                "Custom tool directory is missing or unsafe",
            );
        }
    }
    let tool_path = root.join(relative);
    let original_metadata = match fs::symlink_metadata(&tool_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        _ => return error_result(requirement, priority, "Required tool is missing or unsafe"),
    };
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
    let metadata = original_metadata;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return error_result(requirement, priority, "Required tool is not executable");
        }
    }
    // Custom imports are single-file tools: execute a private snapshot of the exact bytes hashed.
    // Builtins stay at their package-owned paths so their verified sibling helpers remain usable.
    let (execution_path, execution_provenance, _snapshot) = if requirement.origin
        == ControlOrigin::Custom
    {
        let bytes = match fs::read(&canonical_tool) {
            Ok(bytes) if !bytes.is_empty() && bytes.len() <= 4 * 1024 * 1024 => bytes,
            _ => return error_result(requirement, priority, "Custom tool is missing or too large"),
        };
        let actual = sha256_bytes(&bytes);
        let mut provenance = control_provenance(requirement);
        provenance.actual_sha256 = actual.clone();
        provenance.integrity_status = match (&provenance.expected_sha256, &actual) {
            (Some(expected), Some(actual)) if expected.eq_ignore_ascii_case(actual) => {
                IntegrityStatus::Verified
            }
            (Some(_), Some(_)) => IntegrityStatus::Mismatch,
            _ => IntegrityStatus::Unknown,
        };
        let Some(parent) = canonical_tool.parent() else {
            return error_result(requirement, priority, "Invalid custom tool path");
        };
        let snapshot = parent.join(format!(".run-{}-{}", std::process::id(), now_ms()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o700);
        }
        let mut file = match options.open(&snapshot) {
            Ok(file) => file,
            Err(_) => {
                return error_result(
                    requirement,
                    priority,
                    "Cannot create custom tool execution snapshot",
                )
            }
        };
        if file
            .write_all(&bytes)
            .and_then(|_| file.sync_all())
            .is_err()
        {
            let _ = fs::remove_file(&snapshot);
            return error_result(
                requirement,
                priority,
                "Cannot write custom tool execution snapshot",
            );
        }
        (snapshot.clone(), provenance, Some(TemporaryTool(snapshot)))
    } else {
        (
            canonical_tool.clone(),
            control_provenance(requirement),
            None,
        )
    };
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
    let mut command = Command::new(&execution_path);
    command.args(&requirement.arguments);
    let mut executable_path = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
    if requirement.origin == ControlOrigin::Custom {
        if let Some(home) = std::env::var_os("HOME") {
            let user_bin = PathBuf::from(home).join(".local/bin");
            if user_bin.is_absolute()
                && fs::symlink_metadata(&user_bin)
                    .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
            {
                executable_path.push(user_bin);
            }
        }
    }
    let executable_path =
        std::env::join_paths(executable_path).unwrap_or_else(|_| OsString::from("/usr/bin:/bin"));
    command
        .stdin(if parameter_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .env_clear()
        .env("PATH", executable_path);
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
    let deadline = std::time::Instant::now() + timeout;
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
    let (result_status, summary, mut details) = if requirement.origin == ControlOrigin::Custom {
        let result: CustomToolResult = match serde_json::from_str(text) {
            Ok(result) => result,
            Err(_) => return error_result(
                requirement,
                priority,
                "Custom tool returned invalid JSON or fields; expected status, summary and details",
            ),
        };
        (
            ResultStatus::from(result.status),
            result.summary,
            result
                .details
                .map(CustomToolDetails::into_vec)
                .unwrap_or_default(),
        )
    } else {
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
        if result.id != requirement.id {
            return error_result(
                requirement,
                priority,
                "Requirement tool returned a mismatched requirement ID",
            );
        }
        (result.status, result.summary, result.details)
    };
    if summary.trim().is_empty() || details.len() > 64 {
        return error_result(
            requirement,
            priority,
            "Requirement tool returned an invalid result",
        );
    }
    details.insert(0, format!("Tool eseguito: {}", canonical_tool.display()));
    details.insert(1, "Codice uscita tool: 0".into());
    ResultRecord {
        id: requirement.id.clone(),
        name: requirement.name.clone(),
        priority,
        status: result_status,
        compliance_status: None,
        summary,
        details,
        completed_at_unix_ms: now_ms(),
        provenance: Some(execution_provenance),
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
    fs::create_dir_all(directory)
        .map_err(|_| CliError("Cannot create audit history directory".into()))?;
    secure_dir(directory)?;
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
            if path.extension().map_or(true, |ext| ext != "json") {
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
    if let Some(provenance) = &result.provenance {
        text.push_str(&format!(
            "    - Provenienza: {:?}; integrità: {:?}; SHA-256 atteso: {}; effettivo: {}\n",
            provenance.origin,
            provenance.integrity_status,
            provenance.expected_sha256.as_deref().unwrap_or("UNKNOWN"),
            provenance.actual_sha256.as_deref().unwrap_or("UNKNOWN")
        ));
        if let Some(path) = &provenance.tool_path {
            text.push_str(&format!("    - Tool: {path}\n"));
        }
        if let Some(id) = &provenance.override_builtin_id {
            text.push_str(&format!("    - OVERRIDE del controllo integrato: {id}\n"));
        }
    }
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
        [command] if command == "refresh" => {
            Ok(CliOutput { text: format!("Discovery aggiornata: {} controlli rilevati ({} integrati, {} personalizzati).\n", catalog.requirements.len(), catalog.requirements.iter().filter(|item| item.origin == ControlOrigin::Builtin).count(), catalog.requirements.iter().filter(|item| item.origin == ControlOrigin::Custom).count()), code: 0 })
        }
        [command] if command == "list" => {
            let list = catalog.requirements.iter().map(|r| {
                let local = settings.requirements.get(&r.id);
                let mut item = r.clone();
                if let Some(local) = local { item.enabled = local.enabled; item.priority = local.priority; item.parameters = local.parameters.clone(); }
                item
            }).collect::<Vec<_>>();
            let text = list.iter().map(|r| {
                let evidence = control_provenance(r);
                format!("{}  {:<8} {:<7} {} [{}{}]\n    Tool: {}\n    Integrity: {:?} expected={} actual={}\n",
                    r.id, if r.enabled { "enabled" } else { "disabled" }, r.priority, r.name,
                    match r.origin { ControlOrigin::Builtin => "BUILTIN", ControlOrigin::Custom => "CUSTOM" },
                    if r.replaces_builtin.is_some() { " OVERRIDE" } else { "" },
                    evidence.tool_path.as_deref().unwrap_or("non disponibile"), evidence.integrity_status,
                    evidence.expected_sha256.as_deref().unwrap_or("UNKNOWN"), evidence.actual_sha256.as_deref().unwrap_or("UNKNOWN"))
            }).collect();
            Ok(CliOutput { text, code: 0 })
        }
        [command, flag] if command == "list" && flag == "--json" => {
            let mut list = catalog.requirements.iter().map(|r| { let mut item=r.clone(); if let Some(local)=settings.requirements.get(&r.id) {item.enabled=local.enabled;item.priority=local.priority;item.parameters=local.parameters.clone();} item }).collect::<Vec<_>>();
            for item in &mut list { populate_current_integrity(item); }
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
        _ => Err(CliError("Usage: refresh | list [--json] | enable ID | disable ID | priority ID HIGHEST|HIGH|MEDIUM|LOW|OPTIONAL | configure ID JSON_OBJECT | check ID [--log] | audit [--json] [--notify] [--log] | status [--json] | dashboard | --version".into())),
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
    let mut result = if local.is_some_and(|value| !value.enabled) {
        ResultRecord {
            id: requirement.id.clone(),
            name: requirement.name.clone(),
            priority,
            status: ResultStatus::Disabled,
            compliance_status: None,
            summary: "Requirement is disabled".into(),
            details: vec![],
            completed_at_unix_ms: now_ms(),
            provenance: None,
        }
    } else {
        execute(
            requirement,
            priority,
            local.map_or(&requirement.parameters, |value| &value.parameters),
        )
    };
    attach_provenance(&mut result, requirement);
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
        let mut result = if enabled {
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
                compliance_status: None,
                summary: "Requirement is disabled".into(),
                details: vec![],
                completed_at_unix_ms: now_ms(),
                provenance: None,
            }
        };
        attach_provenance(&mut result, requirement);
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
            populate_current_integrity(&mut item);
            item
        })
        .collect::<Vec<_>>();
    output_json(
        &serde_json::json!({"schemaVersion":"baradwatchu.dashboard.v1","requirements":requirements}),
    )
}

pub(crate) fn dashboard_refresh_json() -> Result<String, CliError> {
    // The inventory has no cache: this endpoint deliberately rescans folders now.
    dashboard_data_json()
}

fn populate_current_integrity(item: &mut Requirement) {
    let evidence = control_provenance(item);
    item.actual_sha256 = evidence.actual_sha256;
    item.integrity_status = evidence.integrity_status;
    let root = if item.origin == ControlOrigin::Builtin {
        install_root().ok()
    } else {
        state_dir().ok()
    };
    if let Some(root) = root {
        for path in item.tools.values_mut() {
            *path = root.join(&*path).display().to_string();
        }
    }
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
    let mut result = if local.is_some_and(|v| !v.enabled) {
        ResultRecord {
            id: requirement.id.clone(),
            name: requirement.name.clone(),
            priority,
            status: ResultStatus::Disabled,
            compliance_status: None,
            summary: "Requisito disabilitato".into(),
            details: vec![],
            completed_at_unix_ms: now_ms(),
            provenance: None,
        }
    } else {
        execute(
            requirement,
            priority,
            local.map_or(&requirement.parameters, |v| &v.parameters),
        )
    };
    attach_provenance(&mut result, requirement);
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
    format!("BaradWatchU Client {}\n\nUsage:\n  baradwatchu-agent refresh\n  baradwatchu-agent list [--json]\n  baradwatchu-agent enable ID\n  baradwatchu-agent disable ID\n  baradwatchu-agent priority ID HIGHEST|HIGH|MEDIUM|LOW|OPTIONAL\n  baradwatchu-agent configure ID JSON_OBJECT\n  baradwatchu-agent check ID [--log]\n  baradwatchu-agent audit [--json] [--notify] [--log]\n  baradwatchu-agent status [--json]\n  baradwatchu-agent dashboard\n  baradwatchu-agent --version\n\nUse --log to write a plain-text audit log; structured reports are kept locally. Audits run without the dashboard or Server. REQ-001 may contact Arch mirrors via checkupdates. Tools run directly as the current user.\n", env!("CARGO_PKG_VERSION"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base64_encode(input: &[u8]) -> String {
        const TABLE: &[u8; 64] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let mut out = String::new();
        for chunk in input.chunks(3) {
            let a = chunk[0];
            let b = *chunk.get(1).unwrap_or(&0);
            let c = *chunk.get(2).unwrap_or(&0);
            out.push(TABLE[(a >> 2) as usize] as char);
            out.push(TABLE[(((a & 3) << 4) | (b >> 4)) as usize] as char);
            out.push(if chunk.len() > 1 {
                TABLE[(((b & 15) << 2) | (c >> 6)) as usize] as char
            } else {
                '='
            });
            out.push(if chunk.len() > 2 {
                TABLE[(c & 63) as usize] as char
            } else {
                '='
            });
        }
        out
    }

    #[test]
    fn custom_import_rejects_malformed_base64_padding() {
        for value in ["=AAA", "AA=A", "AA==AAAA", "AB==", "AAB="] {
            assert!(decode_base64(value).is_err(), "accepted {value}");
        }
        assert_eq!(decode_base64("YQ==").unwrap(), b"a");
        assert_eq!(decode_base64("YWI=").unwrap(), b"ab");
        assert_eq!(decode_base64("YWJj").unwrap(), b"abc");
    }

    #[test]
    fn custom_result_contract_omits_id_and_normalizes_warning() {
        let output: CustomToolResult = serde_json::from_str(
            r#"{"status":"WARNING","summary":"partial","details":"method unavailable"}"#,
        )
        .unwrap();
        assert_eq!(ResultStatus::from(output.status), ResultStatus::Warn);
        assert_eq!(output.summary, "partial");
        assert_eq!(
            output.details.unwrap().into_vec(),
            vec!["method unavailable"]
        );
        assert!(serde_json::from_str::<CustomToolResult>(
            r#"{"id":"CUSTOM-001","status":"PASS","summary":"ok","details":[]}"#
        )
        .is_err());
        let fail: CustomToolStatus = serde_json::from_str("\"FAIL\"").unwrap();
        assert_eq!(ResultStatus::from(fail), ResultStatus::Fail);
    }

    #[test]
    fn folder_discovery_reads_configuration_and_direct_arguments() {
        let root =
            std::env::temp_dir().join(format!("bwu-discovery-{}-{}", std::process::id(), now_ms()));
        let check = root.join("CUSTOM-ARG");
        fs::create_dir_all(&check).unwrap();
        fs::write(check.join("configuration.json"), serde_json::json!({
            "schemaVersion":"baradwatchu.custom-checks.v1", "id":"CUSTOM-ARG",
            "name":"Argument check", "description":"test", "priority":"HIGH",
            "enabled":true, "toolPath":"./check.sh", "arguments":["one value", "two"],
            "expectedSha256":"0".repeat(64), "version":1, "parameters":{}, "overrideBuiltinId":null
        }).to_string()).unwrap();
        let found = discover_check_folders(&root).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].1.arguments, vec!["one value", "two"]);
        assert_eq!(found[0].1.tool_path, "./check.sh");
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn custom_tool_arguments_are_passed_as_direct_argv() {
        let temp =
            std::env::temp_dir().join(format!("bwu-argv-{}-{}", std::process::id(), now_ms()));
        fs::create_dir_all(&temp).unwrap();
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", &temp);
        let bytes = b"#!/bin/sh\nprintf '{\\\"status\\\":\\\"PASS\\\",\\\"summary\\\":\\\"%s\\\",\\\"details\\\":[]}' \"$1\"";
        let (path, hash) = store_custom_tool("CUSTOM-ARGV", bytes).unwrap();
        let requirement = Requirement {
            id: "CUSTOM-ARGV".into(),
            name: "Arguments".into(),
            description: "test".into(),
            enabled: true,
            priority: Priority::High,
            parameters: serde_json::json!({}),
            arguments: vec!["one value".into()],
            tools: BTreeMap::from([("linux".into(), path)]),
            origin: ControlOrigin::Custom,
            expected_sha256: Some(hash),
            replaces_builtin: None,
            custom_tool_id: Some("CUSTOM-ARGV".into()),
            custom_tool_version: Some(1),
            builtin_tool_path: None,
            actual_sha256: None,
            integrity_status: IntegrityStatus::Unknown,
        };
        let result = execute(&requirement, Priority::High, &requirement.parameters);
        assert_eq!(result.status, ResultStatus::Pass);
        assert_eq!(result.summary, "one value");
        match old_config {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        fs::remove_dir_all(temp).unwrap();
    }

    fn import_request(id: &str, override_id: Option<&str>) -> String {
        let bytes =
            "#!/bin/sh\nprintf '{\"status\":\"PASS\",\"summary\":\"custom pass\",\"details\":[]}'";
        output_json(&serde_json::json!({
            "id": id, "name": "Custom check", "description": "Local custom check",
            "priority": "HIGH", "enabled": true, "overrideBuiltinId": override_id,
            "cloneFrom": override_id, "fileName": "check.sh", "fileBase64": base64_encode(bytes.as_bytes())
        })).unwrap()
    }

    #[test]
    fn shipped_catalog_has_unique_ids_safe_paths_and_nine_requirements() {
        let temp = std::env::temp_dir().join(format!(
            "bwu-catalog-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        fs::create_dir_all(&temp).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &temp);
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
        assert!(catalog.requirements.iter().all(|r| r
            .expected_sha256
            .as_ref()
            .is_some_and(|hash| hash.len() == 64)));
        match old_config {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn settings_for_removed_folders_do_not_block_discovery_refresh() {
        let temp = std::env::temp_dir().join(format!(
            "bwu-stale-settings-{}-{}",
            std::process::id(),
            now_ms()
        ));
        fs::create_dir_all(&temp).unwrap();
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        std::env::set_var("XDG_CONFIG_HOME", &temp);
        let directory = state_dir().unwrap();
        fs::create_dir_all(&directory).unwrap();
        let settings = serde_json::json!({
            "schema_version":"baradwatchu.settings.v1",
            "requirements":{"CUSTOM-REMOVED":{"enabled":false,"priority":"LOW","parameters":{}}}
        });
        fs::write(directory.join("settings.json"), settings.to_string()).unwrap();
        let current = catalog().unwrap();
        let loaded = load_settings(&current).unwrap();
        assert!(!loaded.requirements.contains_key("CUSTOM-REMOVED"));
        match old_config {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn builtin_tool_hashes_match_distribution_manifest_and_legacy_reports_remain_unknown() {
        let temp = std::env::temp_dir().join(format!(
            "bwu-builtin-test-{}-{}",
            std::process::id(),
            now_ms()
        ));
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        fs::create_dir_all(&temp).unwrap();
        std::env::set_var("XDG_CONFIG_HOME", &temp);
        let catalog = catalog().unwrap();
        for requirement in &catalog.requirements {
            let evidence = control_provenance(requirement);
            assert_eq!(evidence.origin, ControlOrigin::Builtin);
            assert_eq!(
                evidence.integrity_status,
                IntegrityStatus::Verified,
                "{}",
                requirement.id
            );
            assert_eq!(evidence.actual_sha256, evidence.expected_sha256);
        }
        let legacy: ResultRecord = serde_json::from_str(
            r#"{"id":"REQ-001","name":"x","priority":"HIGH","status":"PASS","summary":"x","details":[],"completedAtUnixMs":1}"#,
        ).unwrap();
        assert!(legacy.provenance.is_none());
        match old_config {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn custom_import_mismatch_explicit_update_remove_and_historical_provenance() {
        let temp =
            std::env::temp_dir().join(format!("bwu-custom-{}-{}", std::process::id(), now_ms()));
        fs::create_dir_all(&temp).unwrap();
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        let old_state = std::env::var_os("XDG_STATE_HOME");
        std::env::set_var("XDG_CONFIG_HOME", temp.join("config"));
        std::env::set_var("XDG_STATE_HOME", temp.join("state"));
        let request = import_request("CUSTOM-001", None);
        let mut spoof: serde_json::Value = serde_json::from_str(&request).unwrap();
        spoof["origin"] = serde_json::json!("BUILTIN");
        assert!(dashboard_import_custom(&spoof.to_string()).is_err());
        dashboard_import_custom(&request).unwrap();
        let config_path = state_dir()
            .unwrap()
            .join("custom-tools/CUSTOM-001/configuration.json");
        let original_config = fs::read(&config_path).unwrap();
        let mut forged_config: serde_json::Value =
            serde_json::from_slice(&original_config).unwrap();
        forged_config["origin"] = serde_json::json!("BUILTIN");
        fs::write(&config_path, forged_config.to_string()).unwrap();
        assert!(
            catalog().is_err(),
            "custom configuration accepted a BUILTIN origin"
        );
        fs::write(&config_path, original_config).unwrap();
        let current_catalog = catalog().unwrap();
        let mut local_settings = load_settings(&current_catalog).unwrap();
        local_settings
            .requirements
            .get_mut("CUSTOM-001")
            .unwrap()
            .enabled = false;
        save_settings(&local_settings).unwrap();
        let disabled: AuditReport =
            serde_json::from_str(&dashboard_check_json("CUSTOM-001").unwrap()).unwrap();
        assert_eq!(disabled.results[0].status, ResultStatus::Disabled);
        assert_eq!(
            disabled.results[0]
                .provenance
                .as_ref()
                .unwrap()
                .integrity_status,
            IntegrityStatus::Verified
        );
        local_settings
            .requirements
            .get_mut("CUSTOM-001")
            .unwrap()
            .enabled = true;
        save_settings(&local_settings).unwrap();
        thread::sleep(Duration::from_millis(3));
        let mut report: AuditReport =
            serde_json::from_str(&dashboard_check_json("CUSTOM-001").unwrap()).unwrap();
        let first_hash = report.results[0]
            .provenance
            .as_ref()
            .unwrap()
            .actual_sha256
            .clone()
            .unwrap();
        assert_eq!(
            report.results[0].compliance_status,
            Some(ResultStatus::Pass)
        );
        assert_eq!(
            report.results[0]
                .provenance
                .as_ref()
                .unwrap()
                .integrity_status,
            IntegrityStatus::Verified
        );
        let tool = state_dir()
            .unwrap()
            .join("custom-tools/CUSTOM-001/CUSTOM-001.tool");
        fs::write(&tool, b"#!/bin/sh\nprintf '{\"status\":\"WARNING\",\"summary\":\"changed\",\"details\":[\"second method unavailable\"]}'").unwrap();
        thread::sleep(Duration::from_millis(3));
        report = serde_json::from_str(&dashboard_check_json("CUSTOM-001").unwrap()).unwrap();
        assert_eq!(report.results[0].status, ResultStatus::Warn);
        assert_eq!(
            report.results[0]
                .provenance
                .as_ref()
                .unwrap()
                .integrity_status,
            IntegrityStatus::Mismatch
        );
        let before_update_stamp = report.completed_at_unix_ms;
        thread::sleep(Duration::from_millis(3));
        let update_bytes =
            b"#!/bin/sh\nprintf '{\"status\":\"WARNING\",\"summary\":\"updated\",\"details\":[]}'";
        let update =
            output_json(&serde_json::json!({"fileBase64":base64_encode(update_bytes)})).unwrap();
        dashboard_update_custom("CUSTOM-001", &update).unwrap();
        report = serde_json::from_str(&dashboard_check_json("CUSTOM-001").unwrap()).unwrap();
        assert_eq!(report.results[0].status, ResultStatus::Warn);
        assert_eq!(
            report.results[0].provenance.as_ref().unwrap().tool_version,
            Some(2)
        );
        assert_eq!(
            report.results[0]
                .provenance
                .as_ref()
                .unwrap()
                .integrity_status,
            IntegrityStatus::Verified
        );
        assert_ne!(
            report.results[0]
                .provenance
                .as_ref()
                .unwrap()
                .actual_sha256
                .as_deref(),
            Some(first_hash.as_str())
        );
        let historic = dashboard_history_report_json(&before_update_stamp.to_string()).unwrap();
        let historic: AuditReport = serde_json::from_str(&historic).unwrap();
        assert_eq!(
            historic.results[0]
                .provenance
                .as_ref()
                .unwrap()
                .integrity_status,
            IntegrityStatus::Mismatch
        );
        dashboard_remove_custom("CUSTOM-001").unwrap();
        assert!(!catalog()
            .unwrap()
            .requirements
            .iter()
            .any(|r| r.id == "CUSTOM-001"));
        match old_config {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match old_state {
            Some(value) => std::env::set_var("XDG_STATE_HOME", value),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn override_is_reported_as_custom_and_builtin_restore_keeps_custom_entry() {
        let temp =
            std::env::temp_dir().join(format!("bwu-override-{}-{}", std::process::id(), now_ms()));
        fs::create_dir_all(&temp).unwrap();
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        let old_state = std::env::var_os("XDG_STATE_HOME");
        std::env::set_var("XDG_CONFIG_HOME", temp.join("config"));
        std::env::set_var("XDG_STATE_HOME", temp.join("state"));
        dashboard_import_custom(&import_request("CUSTOM-OVR-001", Some("REQ-001"))).unwrap();
        let report: AuditReport =
            serde_json::from_str(&dashboard_check_json("REQ-001").unwrap()).unwrap();
        let provenance = report.results[0].provenance.as_ref().unwrap();
        assert_eq!(provenance.origin, ControlOrigin::Custom);
        assert!(provenance.is_override);
        assert_eq!(provenance.tool_id, "CUSTOM-OVR-001");
        assert_eq!(provenance.override_builtin_id.as_deref(), Some("REQ-001"));
        assert!(provenance.builtin_expected_sha256.is_some());
        assert!(provenance.builtin_tool_path.is_some());
        dashboard_restore_builtin("REQ-001").unwrap();
        let catalog = catalog().unwrap();
        assert_eq!(
            catalog
                .requirements
                .iter()
                .find(|r| r.id == "REQ-001")
                .unwrap()
                .origin,
            ControlOrigin::Builtin
        );
        assert!(catalog
            .requirements
            .iter()
            .any(|r| r.id == "CUSTOM-OVR-001" && r.origin == ControlOrigin::Custom));
        match old_config {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match old_state {
            Some(value) => std::env::set_var("XDG_STATE_HOME", value),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn custom_tool_missing_non_executable_bad_output_and_timeout_are_errors() {
        let temp =
            std::env::temp_dir().join(format!("bwu-exec-{}-{}", std::process::id(), now_ms()));
        fs::create_dir_all(&temp).unwrap();
        let old_config = std::env::var_os("XDG_CONFIG_HOME");
        let old_state = std::env::var_os("XDG_STATE_HOME");
        std::env::set_var("XDG_CONFIG_HOME", temp.join("config"));
        std::env::set_var("XDG_STATE_HOME", temp.join("state"));
        let no_id_error = b"#!/bin/sh\nprintf '%s\\n' '{\"status\":\"ERROR\",\"summary\":\"check failed\",\"details\":\"version unavailable\"}'";
        let (path, hash) = store_custom_tool("CUSTOM-ERR", no_id_error).unwrap();
        let mut tools = BTreeMap::new();
        tools.insert("linux".into(), path.clone());
        let requirement = Requirement {
            id: "CUSTOM-ERR".into(),
            name: "Custom".into(),
            description: "Test".into(),
            enabled: true,
            priority: Priority::High,
            parameters: serde_json::json!({}),
            arguments: vec![],
            tools: tools.clone(),
            origin: ControlOrigin::Custom,
            expected_sha256: Some(hash),
            replaces_builtin: None,
            custom_tool_id: Some("CUSTOM-ERR".into()),
            custom_tool_version: Some(1),
            builtin_tool_path: None,
            actual_sha256: None,
            integrity_status: IntegrityStatus::Unknown,
        };
        let path = state_dir().unwrap().join(&path);
        let declared_error_result = execute(&requirement, Priority::High, &requirement.parameters);
        assert_eq!(declared_error_result.status, ResultStatus::Error);
        assert!(declared_error_result.summary.contains("check failed"));
        assert!(declared_error_result
            .details
            .iter()
            .any(|d| d == "version unavailable"));

        let with_forbidden_id = b"#!/bin/sh\nprintf '%s\\n' '{\"id\":\"CUSTOM-ERR\",\"status\":\"PASS\",\"summary\":\"not allowed\",\"details\":[]}'";
        let (_, hash) = store_custom_tool("CUSTOM-ERR", with_forbidden_id).unwrap();
        let id_result = Requirement {
            expected_sha256: Some(hash),
            ..requirement.clone()
        };
        assert!(execute(&id_result, Priority::High, &id_result.parameters)
            .summary
            .contains("invalid JSON or fields"));

        let (_, hash) = store_custom_tool("CUSTOM-ERR", b"#!/bin/sh\nprintf 'not-json'").unwrap();
        let invalid_json = Requirement {
            expected_sha256: Some(hash),
            ..requirement.clone()
        };
        assert_eq!(
            execute(&invalid_json, Priority::High, &invalid_json.parameters).status,
            ResultStatus::Error
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert_eq!(
            execute(&requirement, Priority::High, &requirement.parameters).status,
            ResultStatus::Error
        );
        let missing = Requirement {
            tools: BTreeMap::from([("linux".into(), "custom-tools/missing.tool".into())]),
            ..requirement.clone()
        };
        assert_eq!(
            execute(&missing, Priority::High, &missing.parameters).status,
            ResultStatus::Error
        );
        let (_, hash) = store_custom_tool("CUSTOM-ERR", b"#!/bin/sh\nwhile :; do :; done").unwrap();
        let timeout_req = Requirement {
            expected_sha256: Some(hash),
            ..requirement
        };
        let timed = execute_with_timeout(
            &timeout_req,
            Priority::High,
            &timeout_req.parameters,
            Duration::from_millis(40),
        );
        assert_eq!(timed.status, ResultStatus::Error);
        assert!(timed.summary.contains("timed out"));
        match old_config {
            Some(value) => std::env::set_var("XDG_CONFIG_HOME", value),
            None => std::env::remove_var("XDG_CONFIG_HOME"),
        }
        match old_state {
            Some(value) => std::env::set_var("XDG_STATE_HOME", value),
            None => std::env::remove_var("XDG_STATE_HOME"),
        }
        fs::remove_dir_all(temp).unwrap();
    }

    #[test]
    fn tool_path_cannot_escape_installation() {
        for path in ["../tool", "/usr/bin/bash", "tools/../x", "", "tools//check"] {
            assert!(!safe_relative_path(path), "{path}");
        }
        assert!(safe_relative_path(
            "share/baradwatchu-client/catalog/checks/REQ-001/check.sh"
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
            compliance_status: None,
            summary: "Secure Boot non determinabile".into(),
            details: vec![
                "Tool eseguito: /opt/baradwatchu/catalog/checks/REQ-009/check.sh".into(),
                "Comando: /usr/bin/mokutil --sb-state".into(),
                "Codice uscita: 127".into(),
                "Output: mokutil non è installato".into(),
            ],
            completed_at_unix_ms: 1,
            provenance: None,
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
                    compliance_status: None,
                    summary: "Fixture result".into(),
                    details: vec!["Diagnostic fixture".into()],
                    completed_at_unix_ms: stamp,
                    provenance: None,
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
