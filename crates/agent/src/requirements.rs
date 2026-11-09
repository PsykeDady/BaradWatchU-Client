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
const MAX_TOOL_STDERR: usize = 4 * 1024;
const DEFAULT_TIMEOUT_SECONDS: u64 = 20;
const MAX_TIMEOUT_SECONDS: u64 = 300;
/// Folder (under `$XDG_CONFIG_HOME/baradwatchu/`) holding one sub-folder per custom check.
const CUSTOM_DIR: &str = "custom-checks";
/// Pre-release name of [`CUSTOM_DIR`]; migrated once by renaming it.
const LEGACY_CUSTOM_DIR: &str = "custom-tools";
const CHECK_SCHEMA: &str = "baradwatchu.custom-checks.v1";
/// Package-owned builtin check folders for this OS, relative to the installation root.
#[cfg(windows)]
const BUILTIN_CATALOG_DIR: &str = "share/baradwatchu-client/catalog/checks-windows";
#[cfg(not(windows))]
const BUILTIN_CATALOG_DIR: &str = "share/baradwatchu-client/catalog/checks";
/// Summary of a result blocked by the SHA-256 gate (also used to classify events).
pub(crate) const INTEGRITY_GATE_SUMMARY: &str = "Integrità non verificata: lo SHA-256 del tool non corrisponde a quello atteso; il tool non è stato eseguito";

fn default_timeout_seconds() -> u64 {
    DEFAULT_TIMEOUT_SECONDS
}

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

/// In-memory control; serialized in camelCase for `list --json` and the dashboard API.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
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
    #[serde(default = "default_timeout_seconds")]
    pub timeout_seconds: u64,
    pub tools: BTreeMap<String, String>,
    /// Set when a custom check folder exists but cannot be used; the check reports ERROR.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub configuration_error: Option<String>,
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

#[derive(Clone, Debug, Default)]
struct CustomRegistry {
    checks: Vec<CustomEntry>,
    /// Custom folders whose configuration cannot be used: (folder ID, name, reason).
    broken: Vec<BrokenCustom>,
    /// Folders with a configuration.json but a name that is not a valid custom ID.
    ignored: Vec<String>,
}

#[derive(Clone, Debug)]
struct BrokenCustom {
    id: String,
    name: Option<String>,
    priority: Option<Priority>,
    reason: String,
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
    #[serde(default)]
    timeout_seconds: Option<u64>,
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
    #[serde(default)]
    timeout_seconds: Option<u64>,
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
pub(crate) struct AuditHistoryEntry {
    pub(crate) completed_at_unix_ms: u64,
    pub(crate) overall_status: String,
    pub(crate) pass: usize,
    pub(crate) fail: usize,
    pub(crate) warn: usize,
    pub(crate) error: usize,
    pub(crate) other: usize,
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

fn broken_requirement(broken: BrokenCustom) -> Requirement {
    Requirement {
        id: broken.id.clone(),
        name: broken.name.unwrap_or_else(|| broken.id.clone()),
        description: "Configurazione del controllo personalizzato non utilizzabile.".into(),
        enabled: true,
        priority: broken.priority.unwrap_or(Priority::Optional),
        parameters: empty_parameters(),
        arguments: vec![],
        timeout_seconds: DEFAULT_TIMEOUT_SECONDS,
        tools: BTreeMap::new(),
        configuration_error: Some(broken.reason),
        origin: ControlOrigin::Custom,
        expected_sha256: None,
        replaces_builtin: None,
        custom_tool_id: Some(broken.id),
        custom_tool_version: None,
        builtin_tool_path: None,
        actual_sha256: None,
        integrity_status: IntegrityStatus::Unknown,
    }
}

fn catalog() -> Result<Catalog, CliError> {
    catalog_with_registry().map(|(catalog, _)| catalog)
}

/// Discover controls from their folders on every call. `refresh` deliberately calls this
/// same scanner; there is no persisted/in-memory registry to go stale. A broken custom
/// folder becomes an ERROR control of its own and never hides the other controls.
fn catalog_with_registry() -> Result<(Catalog, CustomRegistry), CliError> {
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
    let mut seen_overrides = std::collections::BTreeSet::new();
    let mut broken = registry.broken.clone();
    for entry in registry.checks.iter().cloned() {
        if let Some(target) = entry.override_builtin_id.clone() {
            let problem = if !builtin_ids.contains(&target) {
                Some(format!(
                    "overrideBuiltinId \"{target}\" non corrisponde a un controllo integrato"
                ))
            } else if !seen_overrides.insert(target.clone()) {
                Some(format!(
                    "il controllo integrato {target} è già sostituito da un altro controllo personalizzato"
                ))
            } else {
                None
            };
            if let Some(reason) = problem {
                broken.push(BrokenCustom {
                    id: entry.id,
                    name: Some(entry.name),
                    priority: Some(entry.priority),
                    reason,
                });
                continue;
            }
            let builtin = value
                .requirements
                .iter_mut()
                .find(|r| r.id == target)
                .expect("override target was checked against builtin IDs");
            builtin.builtin_tool_path = builtin.tools.get(platform_key()).cloned();
            builtin.tools.insert(platform_key().into(), entry.tool_path);
            builtin.expected_sha256 = Some(entry.expected_sha256);
            builtin.arguments = entry.arguments;
            builtin.timeout_seconds = entry.timeout_seconds.unwrap_or(builtin.timeout_seconds);
            builtin.origin = ControlOrigin::Custom;
            builtin.replaces_builtin = Some(target);
            builtin.custom_tool_id = Some(entry.id);
            builtin.custom_tool_version = Some(entry.version);
            builtin.enabled = entry.enabled;
        } else {
            value.requirements.push(Requirement {
                id: entry.id.clone(),
                name: entry.name,
                description: entry.description,
                enabled: entry.enabled,
                priority: entry.priority,
                parameters: entry.parameters,
                arguments: entry.arguments,
                timeout_seconds: entry.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS),
                tools: BTreeMap::from([(platform_key().into(), entry.tool_path)]),
                configuration_error: None,
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
    value
        .requirements
        .extend(broken.into_iter().map(broken_requirement));
    // Built-in IDs (including overridden ones) first, then custom controls by ID.
    value.requirements.sort_by(|a, b| {
        (!builtin_ids.contains(&a.id), &a.id).cmp(&(!builtin_ids.contains(&b.id), &b.id))
    });
    let mut ids = std::collections::BTreeSet::new();
    for requirement in &value.requirements {
        if requirement.id.is_empty()
            || !ids.insert(requirement.id.as_str())
            || (requirement.configuration_error.is_none() && requirement.tools.is_empty())
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
    Ok((value, registry))
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
    #[serde(default)]
    timeout_seconds: Option<u64>,
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Validate one parsed `configuration.json`; the message is shown to the user as-is.
fn validate_configuration(folder: &str, config: &CheckConfiguration) -> Result<(), String> {
    if config.schema_version != CHECK_SCHEMA {
        return Err(format!("schemaVersion deve essere \"{CHECK_SCHEMA}\""));
    }
    if config.id != folder {
        return Err(format!(
            "id \"{}\" diverso dal nome della cartella \"{folder}\"",
            config.id
        ));
    }
    if config.name.trim().is_empty() || config.name.len() > 160 {
        return Err("name è obbligatorio (massimo 160 caratteri)".into());
    }
    if config.description.len() > 2048 {
        return Err("description supera 2048 caratteri".into());
    }
    if !config.parameters.is_object() {
        return Err("parameters deve essere un oggetto JSON".into());
    }
    if config.arguments.len() > 64 || config.arguments.iter().any(|arg| arg.len() > 4096) {
        return Err("arguments ammette al massimo 64 stringhe di 4096 caratteri".into());
    }
    if !safe_relative_path(&config.tool_path) {
        return Err(
            "toolPath deve essere un percorso relativo alla cartella del controllo (es. ./check.sh)"
                .into(),
        );
    }
    if config
        .timeout_seconds
        .is_some_and(|value| value == 0 || value > MAX_TIMEOUT_SECONDS)
    {
        return Err(format!(
            "timeoutSeconds deve essere compreso tra 1 e {MAX_TIMEOUT_SECONDS}"
        ));
    }
    if config
        .expected_sha256
        .as_deref()
        .is_some_and(|hash| !valid_sha256(hash))
    {
        return Err("expectedSha256 deve contenere 64 cifre esadecimali".into());
    }
    Ok(())
}

type DiscoveredFolder = (PathBuf, String, Result<CheckConfiguration, String>);

/// Scan `parent` for `<ID>/configuration.json`. Root-level problems are errors; problems
/// with one folder are reported per folder so callers can decide how strict to be.
fn discover_check_folders(parent: &Path) -> Result<Vec<DiscoveredFolder>, CliError> {
    match fs::symlink_metadata(parent) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(CliError("Check folder root is unsafe".into())),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(CliError("Cannot inspect check folders".into())),
    }
    let mut discovered = Vec::new();
    for entry in fs::read_dir(parent).map_err(|_| CliError("Cannot scan check folders".into()))? {
        let entry = entry.map_err(|_| CliError("Cannot read check folder".into()))?;
        let folder = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let Ok(meta) = fs::symlink_metadata(&folder) else {
            continue;
        };
        if !meta.is_dir() || meta.file_type().is_symlink() || name.starts_with('.') {
            continue;
        }
        let config = folder.join("configuration.json");
        let parsed = match fs::symlink_metadata(&config) {
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => Err("configuration.json non è ispezionabile".to_owned()),
            Ok(meta) if !meta.is_file() || meta.file_type().is_symlink() => {
                Err("configuration.json deve essere un file regolare, non un link".to_owned())
            }
            Ok(meta) if meta.len() > 64 * 1024 => {
                Err("configuration.json supera 64 KiB".to_owned())
            }
            Ok(_) => fs::read(&config)
                .map_err(|_| "configuration.json non è leggibile".to_owned())
                .and_then(|bytes| {
                    serde_json::from_slice::<CheckConfiguration>(&bytes)
                        .map_err(|error| format!("configuration.json non valido: {error}"))
                })
                .and_then(|parsed| validate_configuration(&name, &parsed).map(|_| parsed)),
        };
        discovered.push((folder, name, parsed));
    }
    discovered.sort_by(|a, b| a.1.cmp(&b.1));
    Ok(discovered)
}

fn discover_builtin_checks(install: &Path) -> Result<Vec<Requirement>, CliError> {
    let parent = install.join(BUILTIN_CATALOG_DIR);
    let root = install
        .canonicalize()
        .map_err(|_| CliError("Cannot locate Client installation".into()))?;
    let mut requirements = Vec::new();
    for (folder, name, parsed) in discover_check_folders(&parent)? {
        // Built-ins are package-owned: any defect is an installation error, not a skip.
        let config = parsed.map_err(|reason| {
            CliError(format!("Invalid check configuration for {name}: {reason}"))
        })?;
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
        if !tool.starts_with(&root) || !tool.is_file() {
            return Err(CliError(format!("Unsafe tool path for {}", config.id)));
        }
        let relative = tool
            .strip_prefix(&root)
            .expect("tool is inside the installation root")
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
            timeout_seconds: config.timeout_seconds.unwrap_or(DEFAULT_TIMEOUT_SECONDS),
            tools: BTreeMap::from([(platform_key().into(), relative)]),
            configuration_error: None,
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
        && id.len() > 7
        && id.len() <= 64
        && id[7..]
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'-')
}

/// `$XDG_CONFIG_HOME/baradwatchu/custom-checks`, migrating the pre-release
/// `custom-tools` folder in place (one rename, contents untouched) when needed.
fn custom_root() -> Result<PathBuf, CliError> {
    let base = state_dir()?;
    let current = base.join(CUSTOM_DIR);
    let legacy = base.join(LEGACY_CUSTOM_DIR);
    if fs::symlink_metadata(&current).is_err() {
        if let Ok(metadata) = fs::symlink_metadata(&legacy) {
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                fs::rename(&legacy, &current).map_err(|_| {
                    CliError(format!(
                        "Cannot migrate {} to {}",
                        legacy.display(),
                        current.display()
                    ))
                })?;
            }
        }
    }
    Ok(current)
}

fn load_custom_registry() -> Result<CustomRegistry, CliError> {
    let root = custom_root()?;
    let mut registry = CustomRegistry::default();
    for (_, name, parsed) in discover_check_folders(&root)? {
        if !valid_custom_id(&name) {
            registry.ignored.push(name);
            continue;
        }
        let config = match parsed {
            Ok(config) => config,
            Err(reason) => {
                registry.broken.push(BrokenCustom {
                    id: name,
                    name: None,
                    priority: None,
                    reason,
                });
                continue;
            }
        };
        let Some(expected_sha256) = config.expected_sha256.clone() else {
            registry.broken.push(BrokenCustom {
                reason: format!(
                    "expectedSha256 mancante: fissa l'hash del tool con `baradwatchu-agent custom accept {name}` oppure dalla dashboard"
                ),
                id: name,
                name: Some(config.name),
                priority: Some(config.priority),
            });
            continue;
        };
        let local_tool = config
            .tool_path
            .strip_prefix("./")
            .unwrap_or(&config.tool_path);
        registry.checks.push(CustomEntry {
            tool_path: format!("{CUSTOM_DIR}/{name}/{local_tool}"),
            id: name,
            name: config.name,
            description: config.description,
            priority: config.priority,
            enabled: config.enabled,
            arguments: config.arguments,
            expected_sha256,
            version: config.version.unwrap_or(1),
            parameters: config.parameters,
            override_builtin_id: config.override_builtin_id,
            timeout_seconds: config.timeout_seconds,
        });
    }
    if registry.checks.len() + registry.broken.len() > 256 {
        return Err(CliError("Too many custom check folders".into()));
    }
    Ok(registry)
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

/// On-disk `configuration.json`, serialized in the documented field order.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ConfigurationFile<'a> {
    schema_version: &'a str,
    id: &'a str,
    name: &'a str,
    description: &'a str,
    priority: Priority,
    enabled: bool,
    tool_path: &'a str,
    arguments: &'a [String],
    expected_sha256: Option<&'a str>,
    version: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_seconds: Option<u64>,
    parameters: &'a serde_json::Value,
    override_builtin_id: Option<&'a str>,
}

fn valid_tool_file_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 255
        && !name.starts_with('.')
        && name != "configuration.json"
        && !name.contains(['/', '\\', '\0'])
        && Path::new(name).file_name().and_then(|n| n.to_str()) == Some(name)
}

fn custom_folder(id: &str) -> Result<PathBuf, CliError> {
    if !valid_custom_id(id) {
        return Err(CliError("Invalid custom check ID".into()));
    }
    Ok(custom_root()?.join(id))
}

fn prepare_custom_folder(id: &str) -> Result<PathBuf, CliError> {
    let folder = custom_folder(id)?;
    fs::create_dir_all(&folder)
        .map_err(|_| CliError("Cannot create custom check folder".into()))?;
    secure_dir(&state_dir()?)?;
    secure_dir(folder.parent().expect("custom folder has a parent"))?;
    secure_dir(&folder)?;
    Ok(folder)
}

fn local_tool_path(entry: &CustomEntry) -> Result<&str, CliError> {
    let prefix = format!("{CUSTOM_DIR}/{}/", entry.id);
    entry
        .tool_path
        .strip_prefix(&prefix)
        .filter(|local| safe_relative_path(local))
        .ok_or_else(|| CliError("Invalid custom tool path".into()))
}

fn save_custom_entry(entry: &CustomEntry) -> Result<(), CliError> {
    let folder = prepare_custom_folder(&entry.id)?;
    let tool_path = format!("./{}", local_tool_path(entry)?);
    let config = ConfigurationFile {
        schema_version: CHECK_SCHEMA,
        id: &entry.id,
        name: &entry.name,
        description: &entry.description,
        priority: entry.priority,
        enabled: entry.enabled,
        tool_path: &tool_path,
        arguments: &entry.arguments,
        expected_sha256: Some(&entry.expected_sha256),
        version: entry.version,
        timeout_seconds: entry.timeout_seconds,
        parameters: &entry.parameters,
        override_builtin_id: entry.override_builtin_id.as_deref(),
    };
    atomic_json(&folder.join("configuration.json"), &config)
}

/// Atomically write `bytes` as `<custom-checks>/<id>/<local>` (mode 0700) and return the
/// state-relative path plus its SHA-256.
fn store_custom_tool(id: &str, local: &str, bytes: &[u8]) -> Result<(String, String), CliError> {
    if !safe_relative_path(local) || local.ends_with("configuration.json") {
        return Err(CliError("Invalid custom tool file name".into()));
    }
    let folder = prepare_custom_folder(id)?;
    let path = folder.join(local);
    let parent = path
        .parent()
        .filter(|parent| parent.is_dir())
        .ok_or_else(|| CliError("Custom tool directory is missing".into()))?;
    let temp = parent.join(format!(".tmp-{}-{}", std::process::id(), now_ms()));
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
    if file.write_all(bytes).and_then(|_| file.sync_all()).is_err() {
        let _ = fs::remove_file(&temp);
        return Err(CliError("Cannot write custom tool".into()));
    }
    fs::rename(&temp, &path).map_err(|_| {
        let _ = fs::remove_file(&temp);
        CliError("Cannot install custom tool".into())
    })?;
    let local = local.strip_prefix("./").unwrap_or(local);
    Ok((
        format!("{CUSTOM_DIR}/{id}/{local}"),
        sha256_bytes(bytes).ok_or_else(|| CliError("Cannot calculate SHA-256".into()))?,
    ))
}

pub(crate) fn dashboard_import_custom(text: &str) -> Result<String, CliError> {
    if text.len() > 2 * 1024 * 1024 {
        return Err(CliError("Import request exceeds 2 MiB".into()));
    }
    let request: ImportRequest = serde_json::from_str(text)
        .map_err(|_| CliError("Custom-check import is invalid".into()))?;
    if !valid_custom_id(&request.id) {
        return Err(CliError(
            "L'ID deve iniziare con CUSTOM- seguito da lettere maiuscole, cifre o trattini".into(),
        ));
    }
    if request.name.trim().is_empty()
        || request.name.len() > 160
        || request.description.len() > 2048
    {
        return Err(CliError(
            "Nome obbligatorio (max 160 caratteri), descrizione max 2048 caratteri".into(),
        ));
    }
    if !valid_tool_file_name(&request.file_name) {
        return Err(CliError("Nome del file del tool non valido".into()));
    }
    if request.arguments.len() > 64 || request.arguments.iter().any(|arg| arg.len() > 4096) {
        return Err(CliError(
            "Troppi argomenti o argomenti troppo lunghi".into(),
        ));
    }
    if request
        .timeout_seconds
        .is_some_and(|value| value == 0 || value > MAX_TIMEOUT_SECONDS)
    {
        return Err(CliError(format!(
            "timeoutSeconds deve essere compreso tra 1 e {MAX_TIMEOUT_SECONDS}"
        )));
    }
    let bytes = decode_base64(&request.file_base64)?;
    let (catalog, _) = catalog_with_registry()?;
    if catalog.requirements.iter().any(|r| r.id == request.id)
        || custom_folder(&request.id)?.exists()
    {
        return Err(CliError("Custom-check ID already exists".into()));
    }
    if let Some(target) = request.override_builtin_id.as_deref() {
        let overridable = catalog
            .requirements
            .iter()
            .any(|r| r.id == target && r.origin == ControlOrigin::Builtin);
        if !overridable {
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
    let (tool_path, expected_sha256) = store_custom_tool(&request.id, &request.file_name, &bytes)?;
    let entry = CustomEntry {
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
        timeout_seconds: request.timeout_seconds,
    };
    save_custom_entry(&entry)?;
    dashboard_data_json()
}

/// Delete a custom check folder. Works for broken folders too, so a bad configuration
/// can always be cleaned up from the CLI or dashboard.
fn remove_custom(id: &str) -> Result<(), CliError> {
    let folder = custom_folder(id)?;
    match fs::symlink_metadata(&folder) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(CliError("Custom check folder is unsafe".into())),
        Err(_) => return Err(CliError("Custom check not found".into())),
    }
    fs::remove_dir_all(&folder)
        .map_err(|_| CliError("Cannot remove custom check folder".into()))?;
    remove_local_requirement_setting(id)
}

pub(crate) fn dashboard_remove_custom(id: &str) -> Result<String, CliError> {
    remove_custom(id)?;
    dashboard_data_json()
}

/// Pin the current bytes of a custom tool: write its SHA-256 as `expectedSha256` and
/// bump `version` when the hash changes. This is the explicit "I trust this edit" step
/// for checks written or edited by hand.
fn accept_custom(id: &str) -> Result<(String, u64), CliError> {
    let folder = custom_folder(id)?;
    let config_path = folder.join("configuration.json");
    let metadata = fs::symlink_metadata(&config_path)
        .map_err(|_| CliError("Custom check not found".into()))?;
    if !metadata.is_file() || metadata.file_type().is_symlink() || metadata.len() > 64 * 1024 {
        return Err(CliError("configuration.json is unsafe or too large".into()));
    }
    let bytes =
        fs::read(&config_path).map_err(|_| CliError("Cannot read configuration.json".into()))?;
    let config: CheckConfiguration = serde_json::from_slice(&bytes)
        .map_err(|error| CliError(format!("configuration.json non valido: {error}")))?;
    validate_configuration(id, &config).map_err(CliError)?;
    let root = folder
        .canonicalize()
        .map_err(|_| CliError("Cannot locate custom check folder".into()))?;
    let tool = folder.join(&config.tool_path);
    let tool_metadata = fs::symlink_metadata(&tool)
        .map_err(|_| CliError(format!("Tool {} non trovato", config.tool_path)))?;
    if !tool_metadata.is_file()
        || tool_metadata.file_type().is_symlink()
        || tool_metadata.len() > 4 * 1024 * 1024
        || !tool
            .canonicalize()
            .is_ok_and(|path| path.starts_with(&root))
    {
        return Err(CliError("Custom tool is unsafe or too large".into()));
    }
    let hash = sha256_bytes(&fs::read(&tool).map_err(|_| CliError("Cannot read tool".into()))?)
        .ok_or_else(|| CliError("Cannot calculate SHA-256".into()))?;
    let current = config.version.unwrap_or(1);
    let version = match config.expected_sha256.as_deref() {
        Some(previous) if !previous.eq_ignore_ascii_case(&hash) => current.saturating_add(1),
        _ => current,
    };
    let file = ConfigurationFile {
        schema_version: CHECK_SCHEMA,
        id: &config.id,
        name: &config.name,
        description: &config.description,
        priority: config.priority,
        enabled: config.enabled,
        tool_path: &config.tool_path,
        arguments: &config.arguments,
        expected_sha256: Some(&hash),
        version,
        timeout_seconds: config.timeout_seconds,
        parameters: &config.parameters,
        override_builtin_id: config.override_builtin_id.as_deref(),
    };
    atomic_json(&config_path, &file)?;
    Ok((hash, version))
}

pub(crate) fn dashboard_accept_custom(id: &str) -> Result<String, CliError> {
    accept_custom(id)?;
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
    // Replace the configured entrypoint in place so hand-made folders keep their layout.
    let local = local_tool_path(entry)?.to_owned();
    let (path, hash) = store_custom_tool(id, &local, &bytes)?;
    entry.tool_path = path;
    if !entry.expected_sha256.eq_ignore_ascii_case(&hash) {
        entry.version = entry.version.saturating_add(1);
    }
    entry.expected_sha256 = hash;
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
    // Canonical root, so it compares with canonical tool paths (`\\?\` prefix on Windows).
    let root = root.map(|root| root.canonicalize().unwrap_or(root));
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
    let tool_path = resolved.as_ref().map(|path| shown(path));
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

/// Per-user base folder: the XDG variable when set (also used by tests on every OS), then
/// on Windows the known folder variable (`%APPDATA%` / `%LOCALAPPDATA%` plus `windows_sub`),
/// then `$HOME/home_sub`. The returned path already ends in `baradwatchu`.
fn user_base(xdg: &str, windows_var: &str, windows_sub: &str, home_sub: &str) -> Option<PathBuf> {
    if let Some(base) = std::env::var_os(xdg).filter(|value| !value.is_empty()) {
        return Some(PathBuf::from(base).join("baradwatchu"));
    }
    if cfg!(windows) {
        if let Some(base) = std::env::var_os(windows_var).filter(|value| !value.is_empty()) {
            let base = PathBuf::from(base).join("baradwatchu");
            return Some(if windows_sub.is_empty() {
                base
            } else {
                base.join(windows_sub)
            });
        }
    }
    std::env::var_os("HOME").map(|home| PathBuf::from(home).join(home_sub).join("baradwatchu"))
}

/// `$XDG_CONFIG_HOME/baradwatchu` (Windows: `%APPDATA%\baradwatchu`): settings, custom checks.
pub(crate) fn state_dir() -> Result<PathBuf, CliError> {
    user_base("XDG_CONFIG_HOME", "APPDATA", "", ".config")
        .ok_or_else(|| CliError("Cannot locate the user configuration directory".into()))
}

/// `$XDG_STATE_HOME/baradwatchu` (Windows: `%LOCALAPPDATA%\baradwatchu\state`): application
/// events, consent requests (audit history lives in the cache folder, see `history_dir`).
pub(crate) fn state_home() -> Result<PathBuf, CliError> {
    user_base("XDG_STATE_HOME", "LOCALAPPDATA", "state", ".local/state")
        .ok_or_else(|| CliError("Cannot locate the user state directory".into()))
}

/// Per-session runtime files (dashboard session, tray lock): `$XDG_RUNTIME_DIR/baradwatchu`,
/// falling back to `state_home()/run`. The tray companion uses the same rule.
pub(crate) fn runtime_dir() -> Result<PathBuf, CliError> {
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(base) if !base.is_empty() => Ok(PathBuf::from(base).join("baradwatchu")),
        _ => Ok(state_home()?.join("run")),
    }
}

/// Creates `path` (and parents) and restricts it to the current user.
pub(crate) fn ensure_private_dir(path: &Path) -> Result<(), CliError> {
    fs::create_dir_all(path).map_err(|_| CliError("Cannot create local data directory".into()))?;
    secure_dir(path)
}

/// `$XDG_CACHE_HOME/baradwatchu/audit`: audit reports and `--log` files. Disposable by
/// design (operator choice): deleting it only clears the history and the last result.
/// The previous `$XDG_STATE_HOME/baradwatchu/audits` folder is moved here once.
fn history_dir() -> Result<PathBuf, CliError> {
    let current = user_base("XDG_CACHE_HOME", "LOCALAPPDATA", "cache", ".cache")
        .ok_or_else(|| CliError("Cannot locate the user cache directory".into()))?
        .join("audit");
    if fs::symlink_metadata(&current).is_err() {
        let legacy = state_home()?.join("audits");
        if fs::symlink_metadata(&legacy)
            .is_ok_and(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        {
            if let Some(parent) = current.parent() {
                ensure_private_dir(parent)?;
            }
            // Best effort: on failure (e.g. another filesystem) the old history stays where
            // it was and new audits start in the cache folder.
            let _ = fs::rename(&legacy, &current);
        }
    }
    Ok(current)
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

pub(crate) fn secure_dir(path: &Path) -> Result<(), CliError> {
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

/// Unique per process and call, so concurrent writers never share a temporary file.
fn temp_name() -> String {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let sequence = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!(".tmp-{}-{sequence}", std::process::id())
}

pub(crate) fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError("Invalid local data path".into()))?;
    let temp = parent.join(temp_name());
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

pub(crate) fn atomic_text(path: &Path, value: &str) -> Result<(), CliError> {
    let parent = path
        .parent()
        .ok_or_else(|| CliError("Invalid local log path".into()))?;
    let temp = parent.join(temp_name());
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

pub(crate) fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .min(u64::MAX as u128) as u64
}

/// Explains why the OS refused to start a tool, so the author can fix it from the report.
fn spawn_failure(error: &std::io::Error, tool: &Path) -> (&'static str, Vec<String>) {
    #[cfg(unix)]
    if error.raw_os_error() == Some(libc::ENOEXEC) {
        return (
            "Requirement tool has no valid interpreter line",
            vec![
                format!(
                    "Il sistema non sa come eseguire {}: gli script devono iniziare con una riga #! (es. #!/bin/sh). Dopo la modifica aggiorna expectedSha256.",
                    tool.display()
                ),
            ],
        );
    }
    (
        "Could not start requirement tool",
        vec![format!("Avvio di {} non riuscito: {error}", shown(tool))],
    )
}

fn error_result(requirement: &Requirement, priority: Priority, summary: &str) -> ResultRecord {
    error_with_details(requirement, priority, summary, vec![])
}

fn error_with_details(
    requirement: &Requirement,
    priority: Priority,
    summary: &str,
    details: Vec<String>,
) -> ResultRecord {
    ResultRecord {
        id: requirement.id.clone(),
        name: requirement.name.clone(),
        priority,
        status: ResultStatus::Error,
        compliance_status: None,
        summary: summary.into(),
        details,
        completed_at_unix_ms: now_ms(),
        provenance: None,
    }
}

fn execute(
    requirement: &Requirement,
    priority: Priority,
    parameters: &serde_json::Value,
) -> ResultRecord {
    let seconds = requirement.timeout_seconds.clamp(1, MAX_TIMEOUT_SECONDS);
    execute_with_timeout(
        requirement,
        priority,
        parameters,
        Duration::from_secs(seconds),
    )
}

/// Read at most `limit + 1` bytes, then keep draining so the writer never blocks on a
/// full pipe. Returns the kept bytes and whether the stream exceeded `limit`.
fn bounded_reader<R: Read + Send + 'static>(
    mut stream: R,
    limit: usize,
) -> thread::JoinHandle<io::Result<(Vec<u8>, bool)>> {
    thread::spawn(move || {
        let mut data = Vec::new();
        (&mut stream)
            .take((limit + 1) as u64)
            .read_to_end(&mut data)?;
        let oversized = data.len() > limit;
        if oversized {
            data.truncate(limit);
            io::copy(&mut stream, &mut io::sink())?;
        }
        Ok((data, oversized))
    })
}

/// The tool and every helper it starts, ended together on timeout and after exit.
/// Unix: the tool's own process group (SIGKILL to the group).
#[cfg(unix)]
struct ProcessTree(libc::pid_t);

#[cfg(unix)]
impl ProcessTree {
    fn new(child: &std::process::Child) -> Self {
        Self(libc::pid_t::try_from(child.id()).unwrap_or(0))
    }

    fn kill(&self) {
        if self.0 > 1 {
            // SAFETY: plain syscall; a negative PID addresses the group created for the tool.
            unsafe {
                libc::kill(-self.0, libc::SIGKILL);
            }
        }
    }
}

/// Windows: a Job Object that kills its processes when terminated or closed, so helpers are
/// ended even after the tool itself exited. If the job cannot be set up, `taskkill /T`
/// (absolute path, no shell) is the fallback while the tool is still running.
#[cfg(windows)]
struct ProcessTree {
    job: windows_sys::Win32::Foundation::HANDLE,
    pid: u32,
}

#[cfg(windows)]
impl ProcessTree {
    fn new(child: &std::process::Child) -> Self {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::{
            Foundation::CloseHandle,
            System::JobObjects::{
                AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
                SetInformationJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            },
        };
        // SAFETY: plain Win32 calls on a job handle this function owns and on the child's
        // live process handle; the limit structure outlives the call that reads it.
        let job = unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                std::ptr::null_mut()
            } else {
                let mut limits: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
                limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
                let configured = SetInformationJobObject(
                    job,
                    JobObjectExtendedLimitInformation,
                    std::ptr::addr_of!(limits).cast(),
                    std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                ) != 0;
                if configured && AssignProcessToJobObject(job, child.as_raw_handle()) != 0 {
                    job
                } else {
                    CloseHandle(job);
                    std::ptr::null_mut()
                }
            }
        };
        Self {
            job,
            pid: child.id(),
        }
    }

    fn kill(&self) {
        if self.job.is_null() {
            use std::os::windows::process::CommandExt;
            let _ = Command::new(windows_system_dir().join("taskkill.exe"))
                .args(["/T", "/F", "/PID", &self.pid.to_string()])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .creation_flags(CREATE_NO_WINDOW)
                .status();
        } else {
            // SAFETY: `job` is a valid job handle owned by this value.
            unsafe {
                windows_sys::Win32::System::JobObjects::TerminateJobObject(self.job, 1);
            }
        }
    }
}

#[cfg(windows)]
impl Drop for ProcessTree {
    fn drop(&mut self) {
        if !self.job.is_null() {
            // SAFETY: closing the job handle owned by this value (kills what is left).
            unsafe {
                windows_sys::Win32::Foundation::CloseHandle(self.job);
            }
        }
    }
}

#[cfg(not(any(unix, windows)))]
struct ProcessTree;

#[cfg(not(any(unix, windows)))]
impl ProcessTree {
    fn new(_child: &std::process::Child) -> Self {
        Self
    }

    fn kill(&self) {}
}

/// `CREATE_NO_WINDOW`: console tools started by the tray or dashboard never flash a window.
#[cfg(windows)]
const CREATE_NO_WINDOW: u32 = 0x0800_0000;

/// `%SystemRoot%` (default `C:\Windows`), used to reach system programs by absolute path.
#[cfg(windows)]
pub(crate) fn windows_root() -> PathBuf {
    std::env::var_os("SystemRoot")
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.is_absolute())
        .unwrap_or_else(|| PathBuf::from(r"C:\Windows"))
}

#[cfg(windows)]
fn windows_system_dir() -> PathBuf {
    windows_root().join("System32")
}

/// Windows PowerShell 5.1, present on every supported Windows release.
#[cfg(windows)]
fn windows_powershell() -> PathBuf {
    windows_system_dir().join(r"WindowsPowerShell\v1.0\powershell.exe")
}

/// `canonicalize` returns `\\?\C:\…` paths, which Windows PowerShell 5.1 does not accept
/// for `-File`; plain drive paths are returned without the prefix.
#[cfg(windows)]
fn plain_windows_path(path: &Path) -> PathBuf {
    let text = path.as_os_str().to_string_lossy();
    match text.strip_prefix(r"\\?\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

/// Path as shown to people (reports, CLI): without the Windows `\\?\` prefix.
fn shown(path: &Path) -> String {
    #[cfg(windows)]
    {
        plain_windows_path(path).display().to_string()
    }
    #[cfg(not(windows))]
    {
        path.display().to_string()
    }
}

/// How a tool is started: on Windows `.ps1` scripts go through Windows PowerShell and
/// `.exe` files run directly; anything else is refused. On Unix the tool is executed
/// directly and its `#!` line selects the interpreter.
fn tool_command(tool: &Path) -> Result<Command, (String, Vec<String>)> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        let tool = plain_windows_path(tool);
        let extension = tool
            .extension()
            .map(|value| value.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        let mut command = match extension.as_str() {
            "ps1" => {
                let mut command = Command::new(windows_powershell());
                command
                    .args([
                        "-NoLogo",
                        "-NoProfile",
                        "-NonInteractive",
                        "-ExecutionPolicy",
                        "Bypass",
                        "-File",
                    ])
                    .arg(&tool);
                command
            }
            "exe" => Command::new(&tool),
            _ => {
                return Err((
                    "Requirement tool type is not supported on Windows".into(),
                    vec![format!(
                        "Su Windows i tool devono essere script PowerShell (.ps1) o eseguibili (.exe): {}",
                        tool.display()
                    )],
                ))
            }
        };
        command.creation_flags(CREATE_NO_WINDOW);
        Ok(command)
    }
    #[cfg(not(windows))]
    {
        Ok(Command::new(tool))
    }
}

/// Minimal clean environment for a tool: fixed system search path plus the session
/// variables the platform's own tools need.
fn tool_environment(command: &mut Command, origin: ControlOrigin) {
    command.env_clear();
    #[cfg(windows)]
    {
        let _ = origin;
        let root = windows_root();
        let system = windows_system_dir();
        let path = std::env::join_paths([
            system.clone(),
            root.clone(),
            system.join("Wbem"),
            system.join(r"WindowsPowerShell\v1.0"),
        ])
        .unwrap_or_default();
        command
            .env("PATH", path)
            .env("SystemRoot", &root)
            .env("windir", &root);
        for name in [
            "SystemDrive",
            "ComSpec",
            "PATHEXT",
            "TEMP",
            "TMP",
            "USERPROFILE",
            "USERNAME",
            "USERDOMAIN",
            "COMPUTERNAME",
            "APPDATA",
            "LOCALAPPDATA",
            "ProgramData",
            "ProgramFiles",
            "ProgramFiles(x86)",
            "ProgramW6432",
            "CommonProgramFiles",
            "CommonProgramFiles(x86)",
            "PROCESSOR_ARCHITECTURE",
            "NUMBER_OF_PROCESSORS",
            "OS",
            "PUBLIC",
            "ALLUSERSPROFILE",
        ] {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
    }
    #[cfg(not(windows))]
    {
        let mut executable_path = vec![PathBuf::from("/usr/bin"), PathBuf::from("/bin")];
        if origin == ControlOrigin::Custom {
            if let Some(home) = std::env::var_os("HOME") {
                let user_bin = PathBuf::from(home).join(".local/bin");
                if user_bin.is_absolute()
                    && fs::symlink_metadata(&user_bin).is_ok_and(|metadata| {
                        metadata.is_dir() && !metadata.file_type().is_symlink()
                    })
                {
                    executable_path.push(user_bin);
                }
            }
        }
        let executable_path = std::env::join_paths(executable_path)
            .unwrap_or_else(|_| OsString::from("/usr/bin:/bin"));
        command.env("PATH", executable_path);
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
    }
}

fn stderr_excerpt(stderr: &[u8]) -> Option<String> {
    let text = String::from_utf8_lossy(stderr);
    let text = text.trim();
    if text.is_empty() {
        return None;
    }
    let mut excerpt: String = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" | ");
    if excerpt.chars().count() > 512 {
        excerpt = excerpt.chars().take(512).collect::<String>() + "…";
    }
    Some(format!("stderr del tool: {excerpt}"))
}

fn integrity_hint(requirement: &Requirement) -> String {
    match requirement.origin {
        ControlOrigin::Custom => format!(
            "Se la modifica è voluta, fissa il nuovo hash con `baradwatchu-agent custom accept {}` oppure con «Accetta versione attuale» nella dashboard",
            requirement.custom_tool_id.as_deref().unwrap_or(&requirement.id)
        ),
        ControlOrigin::Builtin => {
            "Il file installato è stato modificato: reinstalla BaradWatchU Client".into()
        }
    }
}

fn execute_with_timeout(
    requirement: &Requirement,
    priority: Priority,
    parameters: &serde_json::Value,
    timeout: Duration,
) -> ResultRecord {
    if let Some(reason) = &requirement.configuration_error {
        return error_with_details(
            requirement,
            priority,
            "Configurazione del controllo non valida: il tool non è stato eseguito",
            vec![
                reason.clone(),
                "Correggi configuration.json nella cartella del controllo oppure eliminalo".into(),
            ],
        );
    }
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
        let managed_tools = root.join(CUSTOM_DIR);
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
    let metadata = match fs::symlink_metadata(&tool_path) {
        Ok(metadata) if metadata.is_file() && !metadata.file_type().is_symlink() => metadata,
        _ => {
            return error_with_details(
                requirement,
                priority,
                "Required tool is missing or unsafe",
                vec![format!("Tool atteso: {}", tool_path.display())],
            )
        }
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
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o111 == 0 {
            return error_with_details(
                requirement,
                priority,
                "Required tool is not executable",
                vec![format!(
                    "Rendi eseguibile il file: chmod +x {}",
                    shown(&canonical_tool)
                )],
            );
        }
    }
    // Only Unix has an executable bit to inspect.
    #[cfg(not(unix))]
    let _ = metadata;
    let Some(working_dir) = canonical_tool.parent().map(Path::to_path_buf) else {
        return error_result(requirement, priority, "Invalid tool path");
    };
    // Integrity gate for every origin: hash the exact bytes and refuse to run on mismatch.
    let bytes = match fs::read(&canonical_tool) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= 4 * 1024 * 1024 => bytes,
        _ => {
            return error_result(
                requirement,
                priority,
                "Tool is unreadable, empty or too large",
            )
        }
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
    if provenance.integrity_status != IntegrityStatus::Verified {
        let mut result = error_with_details(
            requirement,
            priority,
            INTEGRITY_GATE_SUMMARY,
            vec![
                format!(
                    "SHA-256 atteso: {}",
                    provenance
                        .expected_sha256
                        .as_deref()
                        .unwrap_or("non disponibile")
                ),
                format!(
                    "SHA-256 attuale: {}",
                    actual.as_deref().unwrap_or("non disponibile")
                ),
                integrity_hint(requirement),
            ],
        );
        result.provenance = Some(provenance);
        return result;
    }
    // Custom tools run from a private snapshot of the exact bytes hashed (no swap between
    // hash and exec). Built-ins stay at their package-owned path so sibling helpers work.
    let (execution_path, _snapshot) = if requirement.origin == ControlOrigin::Custom {
        // Keep the extension: on Windows it selects how the tool is started.
        let extension = canonical_tool
            .extension()
            .map(|value| format!(".{}", value.to_string_lossy()))
            .unwrap_or_default();
        let snapshot = working_dir.join(format!(
            ".run-{}-{}{extension}",
            std::process::id(),
            now_ms()
        ));
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
        drop(file);
        (snapshot.clone(), Some(TemporaryTool(snapshot)))
    } else {
        (canonical_tool.clone(), None)
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
    let mut command = match tool_command(&execution_path) {
        Ok(command) => command,
        Err((summary, details)) => {
            return error_with_details(requirement, priority, &summary, details)
        }
    };
    #[cfg(windows)]
    let working_dir = plain_windows_path(&working_dir);
    command
        .args(&requirement.arguments)
        .current_dir(&working_dir);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // Own process group: a timeout kills the tool and every helper it started.
        command.process_group(0);
    }
    tool_environment(&mut command, requirement.origin);
    command
        .stdin(if parameter_input.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = match command.spawn() {
        Ok(child) => child,
        Err(error) => {
            let (summary, details) = spawn_failure(&error, &canonical_tool);
            return error_with_details(requirement, priority, summary, details);
        }
    };
    let tree = ProcessTree::new(&child);
    let (Some(stdout), Some(stderr)) = (child.stdout.take(), child.stderr.take()) else {
        tree.kill();
        let _ = child.kill();
        let _ = child.wait();
        return error_result(
            requirement,
            priority,
            "Could not read requirement tool result",
        );
    };
    let stdout_reader = bounded_reader(stdout, MAX_TOOL_OUTPUT);
    let stderr_reader = bounded_reader(stderr, MAX_TOOL_STDERR);
    if let Some(input) = parameter_input {
        // A tool may legitimately ignore stdin; a closed pipe is not an error by itself.
        if let Some(mut stdin) = child.stdin.take() {
            let _ = stdin.write_all(&input);
        }
    }
    let deadline = std::time::Instant::now() + timeout;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if std::time::Instant::now() < deadline => {
                thread::sleep(Duration::from_millis(20))
            }
            Ok(None) => {
                timed_out = true;
                tree.kill();
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Err(_) => {
                tree.kill();
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
        }
    };
    // Helpers left in the background would hold the pipes open: end the whole group.
    tree.kill();
    let stderr_text = match stderr_reader.join() {
        Ok(Ok((data, _))) => stderr_excerpt(&data),
        _ => None,
    };
    let with_stderr = |mut details: Vec<String>| {
        details.extend(stderr_text.clone());
        details
    };
    let stdout_result = stdout_reader.join();
    if timed_out {
        return error_with_details(
            requirement,
            priority,
            &format!(
                "Il tool ha superato il timeout di {} s ed è stato terminato",
                timeout.as_secs_f32()
            ),
            with_stderr(vec![format!("Tool: {}", shown(&canonical_tool))]),
        );
    }
    let output = match stdout_result {
        Ok(Ok((output, false))) => output,
        Ok(Ok((_, true))) => {
            return error_with_details(
                requirement,
                priority,
                "Requirement tool output is too large",
                with_stderr(vec![format!("Limite stdout: {MAX_TOOL_OUTPUT} byte")]),
            )
        }
        _ => return error_result(requirement, priority, "Requirement tool output is invalid"),
    };
    match status {
        Some(status) if status.success() => {}
        Some(status) => {
            let code = status.code().map_or_else(
                || "terminato da un segnale".to_owned(),
                |code| code.to_string(),
            );
            return error_with_details(
                requirement,
                priority,
                &format!("Il tool è terminato con un errore (codice uscita {code})"),
                with_stderr(vec![
                    format!("Tool: {}", shown(&canonical_tool)),
                    "Un controllo deve uscire con codice 0 e riportare l'esito nel JSON".into(),
                ]),
            );
        }
        None => {
            return error_result(
                requirement,
                priority,
                "Requirement tool could not be awaited",
            )
        }
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
            Err(error) => {
                return error_with_details(
                    requirement,
                    priority,
                    "Custom tool returned invalid JSON or fields; expected status, summary and details",
                    with_stderr(vec![
                        format!("Errore di parsing: {error}"),
                        "Formato atteso: {\"status\":\"PASS|FAIL|WARNING|ERROR\",\"summary\":\"…\",\"details\":[\"…\"]}".into(),
                    ]),
                )
            }
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
                return error_with_details(
                    requirement,
                    priority,
                    "Requirement tool returned invalid JSON",
                    with_stderr(vec![]),
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
    details.insert(0, format!("Tool eseguito: {}", shown(&canonical_tool)));
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
        provenance: Some(provenance),
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

pub(crate) fn load_last_audit() -> Result<Option<AuditReport>, CliError> {
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

pub(crate) fn history_entry(report: &AuditReport) -> AuditHistoryEntry {
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

pub(crate) fn output_json<T: Serialize>(value: &T) -> Result<String, CliError> {
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

const USAGE: &str = "Usage: refresh | list [--json] | enable ID | disable ID | priority ID HIGHEST|HIGH|MEDIUM|LOW|OPTIONAL | configure ID JSON_OBJECT | check ID [--log] | audit [--json] [--notify] [--log] | status [--json] | custom accept ID | custom remove ID | dashboard [--no-browser] [--open ROUTE] | notifications [--json] | notifications set enabled|informative on|off | events --json [--after ID] | consent simulate|list|accept|reject … | --version";

pub fn run(args: &[OsString]) -> Result<CliOutput, CliError> {
    // Custom-check maintenance must work even when the catalog cannot be built.
    match args {
        [command, action, id] if command == "custom" && action == "remove" => {
            let id = id.to_str().unwrap_or("");
            remove_custom(id)?;
            return Ok(CliOutput {
                text: format!("Controllo personalizzato {id} eliminato.\n"),
                code: 0,
            });
        }
        [command, action, id] if command == "custom" && action == "accept" => {
            let id = id.to_str().unwrap_or("");
            let (hash, version) = accept_custom(id)?;
            return Ok(CliOutput {
                text: format!("{id}: SHA-256 atteso aggiornato a {hash} (versione {version}).\n"),
                code: 0,
            });
        }
        [command, ..] if command == "custom" => {
            return Err(CliError(
                "Usage: custom accept ID | custom remove ID".into(),
            ));
        }
        _ => {}
    }
    // Reject unknown commands before touching configuration or state on disk.
    const COMMANDS: [&str; 9] = [
        "refresh",
        "list",
        "enable",
        "disable",
        "priority",
        "configure",
        "check",
        "audit",
        "status",
    ];
    if !args
        .first()
        .and_then(|command| command.to_str())
        .is_some_and(|command| COMMANDS.contains(&command))
    {
        return Err(CliError(USAGE.into()));
    }
    match args {
        [command, options @ ..] if command == "audit" => {
            parse_audit_options(options)?;
        }
        [command, _] | [command, _, _] if command == "check" => {
            if args.len() == 3 && args[2] != "--log" {
                return Err(CliError("Usage: check ID [--log]".into()));
            }
        }
        [command, ..] if command == "check" => {
            return Err(CliError("Usage: check ID [--log]".into()))
        }
        _ => {}
    }
    let (catalog, registry) = catalog_with_registry()?;
    let mut settings = load_settings(&catalog)?;
    fn id_of(value: &OsString) -> &str {
        value.to_str().unwrap_or("")
    }
    match args {
        [command] if command == "refresh" => {
            let builtin = catalog
                .requirements
                .iter()
                .filter(|item| {
                    item.origin == ControlOrigin::Builtin || item.replaces_builtin.is_some()
                })
                .count();
            let broken = catalog
                .requirements
                .iter()
                .filter(|item| item.configuration_error.is_some())
                .collect::<Vec<_>>();
            let mut text = format!("Discovery aggiornata: {} controlli rilevati ({} integrati, {} personalizzati).\nCartella controlli personalizzati: {}\n", catalog.requirements.len(), builtin, catalog.requirements.len() - builtin, custom_root()?.display());
            for item in broken {
                text.push_str(&format!(
                    "  [NON VALIDO] {}: {}\n",
                    item.id,
                    item.configuration_error.as_deref().unwrap_or("")
                ));
            }
            for name in &registry.ignored {
                text.push_str(&format!(
                    "  [IGNORATA] cartella {name}: il nome deve essere un ID CUSTOM-…\n"
                ));
            }
            Ok(CliOutput { text, code: 0 })
        }
        [command] if command == "list" => {
            let list = catalog
                .requirements
                .iter()
                .map(|r| {
                    let local = settings.requirements.get(&r.id);
                    let mut item = r.clone();
                    if let Some(local) = local {
                        item.enabled = local.enabled;
                        item.priority = local.priority;
                        item.parameters = local.parameters.clone();
                    }
                    item
                })
                .collect::<Vec<_>>();
            let text = list.iter().map(|r| {
                if let Some(reason) = &r.configuration_error {
                    return format!("{}  NON VALIDO {} [CUSTOM]\n    Errore: {}\n", r.id, r.name, reason);
                }
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
            let mut list = catalog
                .requirements
                .iter()
                .map(|r| {
                    let mut item = r.clone();
                    if let Some(local) = settings.requirements.get(&r.id) {
                        item.enabled = local.enabled;
                        item.priority = local.priority;
                        item.parameters = local.parameters.clone();
                    }
                    item
                })
                .collect::<Vec<_>>();
            for item in &mut list {
                populate_current_integrity(item);
            }
            Ok(CliOutput {
                text: output_json(&list)?,
                code: 0,
            })
        }
        [command, id] if (command == "enable" || command == "disable") => {
            let id = id_of(id);
            if !catalog.requirements.iter().any(|r| r.id == id) {
                return Err(CliError(format!("Unknown requirement: {id}")));
            }
            let local = settings
                .requirements
                .entry(id.into())
                .or_insert(RequirementSettings {
                    enabled: true,
                    priority: Priority::High,
                    parameters: serde_json::json!({}),
                });
            local.enabled = command == "enable";
            let enabled = local.enabled;
            save_settings(&settings)?;
            Ok(CliOutput {
                text: format!("{} {}\n", if enabled { "Enabled" } else { "Disabled" }, id),
                code: 0,
            })
        }
        [command, id, priority] if command == "priority" => {
            let id = id_of(id);
            if !catalog.requirements.iter().any(|r| r.id == id) {
                return Err(CliError(format!("Unknown requirement: {id}")));
            }
            let priority = parse_priority(priority).ok_or_else(|| {
                CliError("Priority must be HIGHEST, HIGH, MEDIUM, LOW or OPTIONAL".into())
            })?;
            let local = settings
                .requirements
                .entry(id.into())
                .or_insert(RequirementSettings {
                    enabled: true,
                    priority,
                    parameters: serde_json::json!({}),
                });
            local.priority = priority;
            save_settings(&settings)?;
            Ok(CliOutput {
                text: format!("Priority for {id}: {priority}\n"),
                code: 0,
            })
        }
        [command, id, value] if command == "configure" => {
            let id = id_of(id);
            if !catalog.requirements.iter().any(|r| r.id == id) {
                return Err(CliError(format!("Unknown requirement: {id}")));
            }
            if value.to_string_lossy().len() > 16 * 1024 {
                return Err(CliError("Parameters JSON exceeds 16 KiB".into()));
            }
            let raw = value
                .to_str()
                .ok_or_else(|| CliError("Parameters must be UTF-8 JSON".into()))?;
            let parameters: serde_json::Value = serde_json::from_str(raw)
                .map_err(|_| CliError("Parameters must be a JSON object".into()))?;
            if !parameters.is_object() {
                return Err(CliError("Parameters must be a JSON object".into()));
            }
            let local = settings
                .requirements
                .entry(id.into())
                .or_insert(RequirementSettings {
                    enabled: true,
                    priority: Priority::High,
                    parameters: serde_json::json!({}),
                });
            local.parameters = parameters;
            save_settings(&settings)?;
            Ok(CliOutput {
                text: format!("Parameters saved for {id}\n"),
                code: 0,
            })
        }
        [command, id] if command == "check" => run_check(&catalog, &settings, id_of(id), false),
        [command, id, flag] if command == "check" && flag == "--log" => {
            run_check(&catalog, &settings, id_of(id), true)
        }
        [command, options @ ..] if command == "audit" => {
            let (json, notify, include_log) = parse_audit_options(options)?;
            run_audit(&catalog, &settings, json, notify, include_log)
        }
        [command] if command == "status" => match load_last_audit()? {
            Some(report) => {
                let mut text = report.results.iter().map(human_result).collect::<String>();
                if let Some(path) = report.log_file {
                    text.push_str(&format!("\nLog audit: {path}\n"));
                }
                Ok(CliOutput { text, code: 0 })
            }
            None => Ok(CliOutput {
                text: "No audit results saved yet. Run `baradwatchu-agent audit`.\n".into(),
                code: 0,
            }),
        },
        [command, flag] if command == "status" && flag == "--json" => Ok(CliOutput {
            text: match load_last_audit()? {
                Some(report) => output_json(&report)?,
                None => "null\n".into(),
            },
            code: 0,
        }),
        _ => Err(CliError(USAGE.into())),
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
    // The event log feeds the tray companion and the dashboard; failing to record it
    // must not discard a completed audit.
    let _ = crate::events::record_audit(&report);
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
    let (catalog, registry) = catalog_with_registry()?;
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
    output_json(&serde_json::json!({
        "schemaVersion":"baradwatchu.dashboard.v1",
        "requirements":requirements,
        "customChecksDir":custom_root()?.display().to_string(),
        "ignoredFolders":registry.ignored,
    }))
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
    // Desktop notifications are owned by the tray companion (it reads the event log).
    Ok(run_audit(&catalog, &settings, true, false, false)?.text)
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
    format!("BaradWatchU Client {}\n\nUsage:\n  baradwatchu-agent refresh\n  baradwatchu-agent list [--json]\n  baradwatchu-agent enable ID\n  baradwatchu-agent disable ID\n  baradwatchu-agent priority ID HIGHEST|HIGH|MEDIUM|LOW|OPTIONAL\n  baradwatchu-agent configure ID JSON_OBJECT\n  baradwatchu-agent check ID [--log]\n  baradwatchu-agent audit [--json] [--notify] [--log]\n  baradwatchu-agent status [--json]\n  baradwatchu-agent custom accept ID\n  baradwatchu-agent custom remove ID\n  baradwatchu-agent dashboard [--no-browser] [--open status|custom|history|notifications]\n  baradwatchu-agent notifications [--json]\n  baradwatchu-agent notifications set enabled|informative on|off\n  baradwatchu-agent events --json [--after ID]\n  baradwatchu-agent consent simulate [--server ID] [--account NAME] [--account-id ID] [--device NAME] [--ttl SECONDS]\n  baradwatchu-agent consent list [--json]\n  baradwatchu-agent consent accept|reject ID\n  baradwatchu-agent --version\n\nCustom checks live in $XDG_CONFIG_HOME/baradwatchu/custom-checks/CUSTOM-*/ (configuration.json + tool); `custom accept` pins the current tool SHA-256 after an intentional edit. Use --log to write a plain-text audit log; structured reports are kept locally. Audits run without the dashboard or Server. REQ-001 may contact Arch mirrors via checkupdates. Tools run directly as the current user. Desktop notifications and the consent window are provided by the optional baradwatchu-tray companion; consent requests are local simulations only (no remote requests yet) and only an explicit accept authorizes one request.\n", env!("CARGO_PKG_VERSION"))
}

/// Serialises tests that change process-wide environment variables and points every
/// XDG location at a private temporary tree, so tests never touch the real user data.
#[cfg(test)]
pub(crate) struct TestEnv {
    pub(crate) root: PathBuf,
    saved: Vec<(&'static str, Option<OsString>)>,
    _guard: std::sync::MutexGuard<'static, ()>,
}

#[cfg(test)]
static TEST_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
impl TestEnv {
    pub(crate) fn new(label: &str) -> Self {
        let guard = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("bwu-{label}-{}-{nanos}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut env = Self {
            root: root.clone(),
            saved: vec![],
            _guard: guard,
        };
        env.set("XDG_CONFIG_HOME", root.join("config"));
        env.set("XDG_STATE_HOME", root.join("state"));
        env.set("XDG_CACHE_HOME", root.join("cache"));
        env.set("XDG_RUNTIME_DIR", root.join("run"));
        env
    }

    pub(crate) fn set(&mut self, key: &'static str, value: impl Into<OsString>) {
        if !self.saved.iter().any(|(saved, _)| *saved == key) {
            self.saved.push((key, std::env::var_os(key)));
        }
        std::env::set_var(key, value.into());
    }

    pub(crate) fn custom_dir(&self) -> PathBuf {
        self.root.join("config/baradwatchu").join(CUSTOM_DIR)
    }
}

#[cfg(test)]
impl Drop for TestEnv {
    fn drop(&mut self) {
        for (key, value) in self.saved.drain(..).rev() {
            match value {
                Some(value) => std::env::set_var(key, value),
                None => std::env::remove_var(key),
            }
        }
        let _ = fs::remove_dir_all(&self.root);
    }
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

    /// Create `<custom-checks>/<id>/` with an executable tool and a configuration whose
    /// fields can be overridden; returns the folder.
    fn write_custom_folder(
        env: &TestEnv,
        id: &str,
        tool_name: &str,
        tool: &[u8],
        overrides: serde_json::Value,
    ) -> PathBuf {
        let folder = env.custom_dir().join(id);
        fs::create_dir_all(&folder).unwrap();
        let tool_path = folder.join(tool_name);
        fs::write(&tool_path, tool).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tool_path, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let mut config = serde_json::json!({
            "schemaVersion": CHECK_SCHEMA, "id": id, "name": format!("Check {id}"),
            "description": "test", "priority": "HIGH", "enabled": true,
            "toolPath": format!("./{tool_name}"), "arguments": [],
            "expectedSha256": sha256_bytes(tool).unwrap(), "version": 1,
            "parameters": {}, "overrideBuiltinId": null
        });
        for (key, value) in overrides.as_object().unwrap() {
            if value.is_null() && key == "expectedSha256" {
                config.as_object_mut().unwrap().remove(key);
            } else {
                config[key] = value.clone();
            }
        }
        fs::write(folder.join("configuration.json"), config.to_string()).unwrap();
        folder
    }

    fn find(catalog: &Catalog, id: &str) -> Requirement {
        catalog
            .requirements
            .iter()
            .find(|r| r.id == id)
            .unwrap_or_else(|| panic!("{id} not in catalog"))
            .clone()
    }

    /// Entrypoint names for test tools: a shell script on Unix, PowerShell on Windows.
    #[cfg(not(windows))]
    const TOOL: &str = "c.sh";
    #[cfg(windows)]
    const TOOL: &str = "c.ps1";
    #[cfg(not(windows))]
    const CHECK: &str = "check.sh";
    #[cfg(windows)]
    const CHECK: &str = "check.ps1";

    /// A test tool that prints `stdout` verbatim (must not contain single quotes).
    fn print_tool(stdout: &str) -> Vec<u8> {
        assert!(!stdout.contains('\''));
        if cfg!(windows) {
            format!("[Console]::Out.Write('{stdout}')\r\n")
        } else {
            format!("#!/bin/sh\nprintf '%s\\n' '{stdout}'\n")
        }
        .into_bytes()
    }

    /// A test tool reporting `status` with `summary` (custom contract).
    fn status_tool(status: &str, summary: &str) -> Vec<u8> {
        print_tool(&format!(
            "{{\"status\":\"{status}\",\"summary\":\"{summary}\",\"details\":[]}}"
        ))
    }

    fn pass_tool(summary: &str) -> Vec<u8> {
        status_tool("PASS", summary)
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
        // WARN is the report status; tools must write WARNING.
        assert!(
            serde_json::from_str::<CustomToolResult>(r#"{"status":"WARN","summary":"ok"}"#)
                .is_err()
        );
        let fail: CustomToolStatus = serde_json::from_str("\"FAIL\"").unwrap();
        assert_eq!(ResultStatus::from(fail), ResultStatus::Fail);
    }

    /// The operator's own model check (copied verbatim from
    /// ~/.config/baradwatchu/custom-tools/CUSTOM-001) must be accepted as designed.
    // Shell-script fixture; the Windows runner has its own tests (windows_*).
    #[cfg(unix)]
    #[test]
    fn operator_model_custom_001_runs_as_designed() {
        const SCRIPT: &[u8] = b"#!/bin/bash\n\nexists=$(ricordatichedevicambiare -V >/dev/null 2>/dev/null; echo $?);\nif ((exists==0)); then \n\tdetails=\"version: $(ricordatichedevicambiare -V | awk '{print $2}')\";\n\tsummary=\"software installato correttamente\"\n\tstatus='\"PASS\"'\nelse\n\tdetails=\"version: N/D\";\n\tsummary=\"software non installato\"\n\tstatus='\"FAIL\"';\nfi\n\necho '{\n\t\"status\":'$status',\n\t\"summary\":\"'\"$summary\"'\",\n\t\"details\":\"'\"$details\"'\"\n}'\n\n\n\n";
        let mut env = TestEnv::new("operator-model");
        let home = env.root.join("home");
        fs::create_dir_all(home.join(".local/bin")).unwrap();
        env.set("HOME", &home);
        let folder = env.custom_dir().join("CUSTOM-001");
        fs::create_dir_all(&folder).unwrap();
        fs::write(folder.join("CUSTOM-001.sh"), SCRIPT).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                folder.join("CUSTOM-001.sh"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
        }
        // Verbatim configuration layout, including tabs and `"arguments":[""]`.
        fs::write(
            folder.join("configuration.json"),
            format!(
                "{{\n  \t\"schemaVersion\": \"baradwatchu.custom-checks.v1\",\n\t\"id\": \"CUSTOM-001\",\n\t\"name\": \"Password Reminder\",\n\t\"description\": \"Verifica se è installato \\\"ricordatichedevicambiare\\\" per monitorare il cambio della password\",\n\t\"priority\": \"OPTIONAL\",\n\t\"enabled\": true,\n\t\"toolPath\": \"./CUSTOM-001.sh\",\n\t\"arguments\":[\"\"],\n\t\"expectedSha256\": \"{}\",\n\t\"version\": 1,\n\t\"parameters\": {{}},\n\t\"overrideBuiltinId\": null\n}}\n",
                sha256_bytes(SCRIPT).unwrap()
            ),
        )
        .unwrap();
        let catalog = catalog().unwrap();
        let check = find(&catalog, "CUSTOM-001");
        assert!(
            check.configuration_error.is_none(),
            "{:?}",
            check.configuration_error
        );
        assert_eq!(check.priority, Priority::Optional);
        assert_eq!(check.arguments, vec![""]);
        let missing = execute(&check, check.priority, &check.parameters);
        assert_eq!(missing.status, ResultStatus::Fail, "{missing:?}");
        assert_eq!(missing.summary, "software non installato");
        // Provide the program in ~/.local/bin, which custom tools get on PATH.
        let fake = home.join(".local/bin/ricordatichedevicambiare");
        fs::write(&fake, "#!/bin/sh\necho 'ricordatichedevicambiare 1.0.0'\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&fake, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let present = execute(&check, check.priority, &check.parameters);
        assert_eq!(present.status, ResultStatus::Pass, "{present:?}");
        assert!(present.details.iter().any(|d| d == "version: 1.0.0"));
        assert_eq!(
            present.provenance.unwrap().integrity_status,
            IntegrityStatus::Verified
        );
    }

    #[test]
    fn audit_history_moves_from_state_to_cache_once() {
        let env = TestEnv::new("history-move");
        let legacy = env.root.join("state/baradwatchu/audits/reports");
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("1.json"), "{}").unwrap();
        let current = history_dir().unwrap();
        assert_eq!(current, env.root.join("cache/baradwatchu/audit"));
        assert!(current.join("reports/1.json").is_file());
        assert!(!env.root.join("state/baradwatchu/audits").exists());
        // Once the cache folder exists a stale legacy folder is left alone.
        fs::create_dir_all(env.root.join("state/baradwatchu/audits")).unwrap();
        assert_eq!(history_dir().unwrap(), current);
        assert!(env.root.join("state/baradwatchu/audits").exists());
    }

    #[test]
    fn legacy_custom_tools_folder_is_migrated_once() {
        let env = TestEnv::new("migration");
        let legacy = env.root.join("config/baradwatchu/custom-tools/CUSTOM-OLD");
        fs::create_dir_all(&legacy).unwrap();
        fs::write(legacy.join("marker"), "keep").unwrap();
        let root = custom_root().unwrap();
        assert_eq!(root, env.custom_dir());
        assert_eq!(
            fs::read_to_string(root.join("CUSTOM-OLD/marker")).unwrap(),
            "keep"
        );
        assert!(!env.root.join("config/baradwatchu/custom-tools").exists());
        // An existing custom-checks folder is never replaced by a later legacy folder.
        fs::create_dir_all(env.root.join("config/baradwatchu/custom-tools/CUSTOM-NEW")).unwrap();
        custom_root().unwrap();
        assert!(env
            .root
            .join("config/baradwatchu/custom-tools/CUSTOM-NEW")
            .exists());
        assert!(root.join("CUSTOM-OLD").exists());
    }

    #[test]
    fn broken_custom_folders_are_isolated_reported_and_removable() {
        let env = TestEnv::new("broken");
        fs::create_dir_all(env.custom_dir().join("CUSTOM-BADJSON")).unwrap();
        fs::write(
            env.custom_dir().join("CUSTOM-BADJSON/configuration.json"),
            "{ not json",
        )
        .unwrap();
        write_custom_folder(
            &env,
            "CUSTOM-WRONGID",
            TOOL,
            &pass_tool("x"),
            serde_json::json!({"id":"CUSTOM-OTHER"}),
        );
        write_custom_folder(
            &env,
            "CUSTOM-NOHASH",
            TOOL,
            &pass_tool("x"),
            serde_json::json!({"expectedSha256": null}),
        );
        write_custom_folder(
            &env,
            "CUSTOM-BADOVR",
            TOOL,
            &pass_tool("x"),
            serde_json::json!({"overrideBuiltinId":"REQ-999"}),
        );
        write_custom_folder(
            &env,
            "CUSTOM-TIMEOUT",
            TOOL,
            &pass_tool("x"),
            serde_json::json!({"timeoutSeconds": 0}),
        );
        write_custom_folder(
            &env,
            "lowercase-name",
            TOOL,
            &pass_tool("x"),
            serde_json::json!({"id":"lowercase-name"}),
        );
        write_custom_folder(
            &env,
            "CUSTOM-GOOD",
            TOOL,
            &pass_tool("good"),
            serde_json::json!({}),
        );
        let (catalog, registry) = catalog_with_registry().unwrap();
        // All nine built-ins and the healthy custom check survive the broken neighbours.
        assert_eq!(
            catalog
                .requirements
                .iter()
                .filter(|r| r.origin == ControlOrigin::Builtin)
                .count(),
            9
        );
        assert!(find(&catalog, "CUSTOM-GOOD").configuration_error.is_none());
        assert_eq!(registry.ignored, vec!["lowercase-name"]);
        for (id, needle) in [
            ("CUSTOM-BADJSON", "non valido"),
            ("CUSTOM-WRONGID", "diverso dal nome della cartella"),
            ("CUSTOM-NOHASH", "custom accept CUSTOM-NOHASH"),
            ("CUSTOM-BADOVR", "REQ-999"),
            ("CUSTOM-TIMEOUT", "timeoutSeconds"),
        ] {
            let broken = find(&catalog, id);
            let reason = broken.configuration_error.clone().unwrap();
            assert!(reason.contains(needle), "{id}: {reason}");
            let result = execute(&broken, broken.priority, &broken.parameters);
            assert_eq!(result.status, ResultStatus::Error);
            assert!(result.details.iter().any(|d| d == &reason));
        }
        // A full audit still runs and stores ERROR for the broken folders.
        let settings = load_settings(&catalog).unwrap();
        let output = run_audit(&catalog, &settings, true, false, false).unwrap();
        let report: AuditReport = serde_json::from_str(&output.text).unwrap();
        assert_eq!(
            report
                .results
                .iter()
                .find(|r| r.id == "CUSTOM-GOOD")
                .unwrap()
                .status,
            ResultStatus::Pass
        );
        assert_eq!(
            report
                .results
                .iter()
                .find(|r| r.id == "CUSTOM-BADJSON")
                .unwrap()
                .status,
            ResultStatus::Error
        );
        // Broken folders can be deleted through the same path the dashboard uses.
        let data: serde_json::Value =
            serde_json::from_str(&dashboard_remove_custom("CUSTOM-BADJSON").unwrap()).unwrap();
        assert!(!data["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r["id"] == "CUSTOM-BADJSON"));
        assert!(!env.custom_dir().join("CUSTOM-BADJSON").exists());
        assert!(dashboard_remove_custom("CUSTOM-BADJSON").is_err());
        assert!(dashboard_remove_custom("../config").is_err());
        assert!(dashboard_remove_custom("REQ-001").is_err());
    }

    #[test]
    fn accept_pins_hand_written_tool_and_mismatch_never_executes() {
        let env = TestEnv::new("accept");
        let marker = env.root.join("executed");
        let tool = if cfg!(windows) {
            format!(
                "New-Item -ItemType File -Force -Path '{}' | Out-Null\r\n[Console]::Out.Write('{{\"status\":\"PASS\",\"summary\":\"ran\"}}')\r\n",
                marker.display()
            )
        } else {
            format!(
                "#!/bin/sh\ntouch '{}'\nprintf '{{\"status\":\"PASS\",\"summary\":\"ran\"}}'\n",
                marker.display()
            )
        };
        let folder = write_custom_folder(
            &env,
            "CUSTOM-PIN",
            CHECK,
            tool.as_bytes(),
            serde_json::json!({"expectedSha256": null}),
        );
        assert!(find(&catalog().unwrap(), "CUSTOM-PIN")
            .configuration_error
            .is_some());
        let (hash, version) = accept_custom("CUSTOM-PIN").unwrap();
        assert_eq!(hash, sha256_bytes(tool.as_bytes()).unwrap());
        assert_eq!(version, 1);
        let check = find(&catalog().unwrap(), "CUSTOM-PIN");
        assert_eq!(
            execute(&check, check.priority, &check.parameters).status,
            ResultStatus::Pass
        );
        assert!(marker.exists());
        fs::remove_file(&marker).unwrap();
        // Editing the tool by hand without accepting it blocks execution.
        let edited = tool.replace("ran", "edited");
        fs::write(folder.join(CHECK), &edited).unwrap();
        let check = find(&catalog().unwrap(), "CUSTOM-PIN");
        let blocked = execute(&check, check.priority, &check.parameters);
        assert_eq!(blocked.status, ResultStatus::Error);
        assert!(blocked.summary.contains("Integrità non verificata"));
        assert_eq!(
            blocked.provenance.as_ref().unwrap().integrity_status,
            IntegrityStatus::Mismatch
        );
        assert!(!marker.exists(), "a mismatched tool must not run");
        let (_, version) = accept_custom("CUSTOM-PIN").unwrap();
        assert_eq!(version, 2);
        let check = find(&catalog().unwrap(), "CUSTOM-PIN");
        let accepted = execute(&check, check.priority, &check.parameters);
        assert_eq!(accepted.summary, "edited");
        // The rewritten configuration keeps the documented field order.
        let text = fs::read_to_string(folder.join("configuration.json")).unwrap();
        let order = [
            "schemaVersion",
            "\"id\"",
            "\"name\"",
            "toolPath",
            "expectedSha256",
            "\"version\"",
            "overrideBuiltinId",
        ];
        let positions: Vec<_> = order.iter().map(|key| text.find(key).unwrap()).collect();
        assert!(positions.windows(2).all(|pair| pair[0] < pair[1]), "{text}");
    }

    #[test]
    fn requirement_api_uses_camel_case_for_the_dashboard() {
        let env = TestEnv::new("camel");
        write_custom_folder(
            &env,
            "CUSTOM-CAMEL",
            TOOL,
            &pass_tool("x"),
            serde_json::json!({"timeoutSeconds": 7}),
        );
        let data: serde_json::Value =
            serde_json::from_str(&dashboard_data_json().unwrap()).unwrap();
        let custom = data["requirements"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["id"] == "CUSTOM-CAMEL")
            .unwrap()
            .clone();
        for key in [
            "customToolId",
            "integrityStatus",
            "expectedSha256",
            "actualSha256",
            "timeoutSeconds",
        ] {
            assert!(custom.get(key).is_some(), "missing {key}: {custom}");
        }
        assert!(custom.get("custom_tool_id").is_none());
        assert_eq!(custom["customToolId"], "CUSTOM-CAMEL");
        assert_eq!(custom["timeoutSeconds"], 7);
        assert_eq!(custom["integrityStatus"], "VERIFIED");
        assert!(data["customChecksDir"]
            .as_str()
            .unwrap()
            .ends_with(CUSTOM_DIR));
    }

    // Shell-script fixture; the Windows runner has its own tests (windows_*).
    #[cfg(unix)]
    #[test]
    fn tools_run_in_their_folder_and_report_stderr_on_failure() {
        let env = TestEnv::new("cwd");
        let folder = write_custom_folder(
            &env,
            "CUSTOM-CWD",
            "check.sh",
            b"#!/bin/sh\nprintf '{\"status\":\"PASS\",\"summary\":\"%s\"}' \"$(cat ./data.txt)\"\n",
            serde_json::json!({}),
        );
        fs::write(folder.join("data.txt"), "from-folder").unwrap();
        let check = find(&catalog().unwrap(), "CUSTOM-CWD");
        assert_eq!(
            execute(&check, check.priority, &check.parameters).summary,
            "from-folder"
        );
        write_custom_folder(
            &env,
            "CUSTOM-EXIT",
            "check.sh",
            b"#!/bin/sh\necho 'missing dependency xyz' >&2\nexit 3\n",
            serde_json::json!({}),
        );
        let check = find(&catalog().unwrap(), "CUSTOM-EXIT");
        let failed = execute(&check, check.priority, &check.parameters);
        assert_eq!(failed.status, ResultStatus::Error);
        assert!(
            failed.summary.contains("codice uscita 3"),
            "{}",
            failed.summary
        );
        assert!(failed
            .details
            .iter()
            .any(|d| d.contains("missing dependency xyz")));
    }

    // Shell-script fixture; the Windows runner has its own tests (windows_*).
    #[cfg(unix)]
    #[test]
    fn timeout_kills_background_helpers_without_hanging() {
        let env = TestEnv::new("timeout");
        write_custom_folder(
            &env,
            "CUSTOM-SLOW",
            "check.sh",
            b"#!/bin/sh\nsleep 30 &\nsleep 30\n",
            serde_json::json!({"timeoutSeconds": 1}),
        );
        let check = find(&catalog().unwrap(), "CUSTOM-SLOW");
        assert_eq!(check.timeout_seconds, 1);
        let started = std::time::Instant::now();
        let result = execute(&check, check.priority, &check.parameters);
        assert_eq!(result.status, ResultStatus::Error);
        assert!(result.summary.contains("timeout"), "{}", result.summary);
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "background helper kept the pipe open for {:?}",
            started.elapsed()
        );
        // A tool that succeeds but leaves a helper behind does not block either.
        write_custom_folder(
            &env,
            "CUSTOM-BG",
            "check.sh",
            b"#!/bin/sh\nsleep 30 &\nprintf '{\"status\":\"PASS\",\"summary\":\"done\"}'\n",
            serde_json::json!({}),
        );
        let check = find(&catalog().unwrap(), "CUSTOM-BG");
        let started = std::time::Instant::now();
        assert_eq!(
            execute(&check, check.priority, &check.parameters).status,
            ResultStatus::Pass
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    /// Windows runner: `.ps1` tools go through Windows PowerShell with the folder as cwd,
    /// direct arguments and JSON parameters on stdin; failures, timeouts and unsupported
    /// tool types are reported as errors.
    #[cfg(windows)]
    #[test]
    fn windows_powershell_tools_run_with_folder_arguments_parameters_and_errors() {
        let env = TestEnv::new("win-ps1");
        let folder = write_custom_folder(
            &env,
            "CUSTOM-PS1",
            "check.ps1",
            b"$p = [Console]::In.ReadToEnd() | ConvertFrom-Json\r\n$d = (Get-Content -Raw .\\data.txt).Trim()\r\n[Console]::Out.Write((@{ status = 'PASS'; summary = \"$d|$($args[0])|$($args[1])|$($p.parameters.level)\" } | ConvertTo-Json -Compress))\r\n",
            serde_json::json!({"arguments": ["one value", "two"], "parameters": {"level": 3}}),
        );
        fs::write(folder.join("data.txt"), "from-folder").unwrap();
        let check = find(&catalog().unwrap(), "CUSTOM-PS1");
        let result = execute(&check, check.priority, &check.parameters);
        assert_eq!(result.status, ResultStatus::Pass, "{result:?}");
        assert_eq!(result.summary, "from-folder|one value|two|3");
        // The snapshot used for custom tools keeps the extension and is removed afterwards.
        assert!(fs::read_dir(&folder).unwrap().all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".run-")));

        write_custom_folder(
            &env,
            "CUSTOM-PS1EXIT",
            "check.ps1",
            b"[Console]::Error.WriteLine('missing dependency xyz')\r\nexit 3\r\n",
            serde_json::json!({}),
        );
        let check = find(&catalog().unwrap(), "CUSTOM-PS1EXIT");
        let failed = execute(&check, check.priority, &check.parameters);
        assert_eq!(failed.status, ResultStatus::Error);
        assert!(
            failed.summary.contains("codice uscita 3"),
            "{}",
            failed.summary
        );
        assert!(failed
            .details
            .iter()
            .any(|d| d.contains("missing dependency xyz")));

        write_custom_folder(
            &env,
            "CUSTOM-SH",
            "check.sh",
            b"#!/bin/sh\necho no\n",
            serde_json::json!({}),
        );
        let check = find(&catalog().unwrap(), "CUSTOM-SH");
        let refused = execute(&check, check.priority, &check.parameters);
        assert_eq!(refused.status, ResultStatus::Error);
        assert!(
            refused.summary.contains("not supported on Windows"),
            "{}",
            refused.summary
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_timeout_kills_the_whole_tool_tree() {
        let env = TestEnv::new("win-timeout");
        // A helper process inherits the output pipe: only killing the tree ends the read.
        let helper = "Start-Process -NoNewWindow -FilePath \"$env:SystemRoot\\System32\\WindowsPowerShell\\v1.0\\powershell.exe\" -ArgumentList '-NoProfile','-Command','Start-Sleep -Seconds 40'";
        write_custom_folder(
            &env,
            "CUSTOM-PS1SLOW",
            "check.ps1",
            format!("{helper}\r\nStart-Sleep -Seconds 40\r\n").as_bytes(),
            serde_json::json!({"timeoutSeconds": 2}),
        );
        let check = find(&catalog().unwrap(), "CUSTOM-PS1SLOW");
        let started = std::time::Instant::now();
        let result = execute(&check, check.priority, &check.parameters);
        assert_eq!(result.status, ResultStatus::Error);
        assert!(result.summary.contains("timeout"), "{}", result.summary);
        assert!(
            started.elapsed() < Duration::from_secs(20),
            "helper kept the pipe open for {:?}",
            started.elapsed()
        );
        write_custom_folder(
            &env,
            "CUSTOM-PS1BG",
            "check.ps1",
            format!("{helper}\r\n[Console]::Out.Write('{{\"status\":\"PASS\",\"summary\":\"done\"}}')\r\n").as_bytes(),
            serde_json::json!({}),
        );
        let check = find(&catalog().unwrap(), "CUSTOM-PS1BG");
        let started = std::time::Instant::now();
        let result = execute(&check, check.priority, &check.parameters);
        assert_eq!(result.status, ResultStatus::Pass, "{result:?}");
        assert!(started.elapsed() < Duration::from_secs(20));
    }

    // Shell-script fixture; the Windows runner has its own tests (windows_*).
    #[cfg(unix)]
    #[test]
    fn folder_discovery_reads_configuration_and_direct_arguments() {
        let env = TestEnv::new("discovery");
        write_custom_folder(
            &env,
            "CUSTOM-ARG",
            "check.sh",
            b"#!/bin/sh\nprintf '{\"status\":\"PASS\",\"summary\":\"%s|%s\"}' \"$1\" \"$2\"\n",
            serde_json::json!({"arguments":["one value", "two"]}),
        );
        let found = discover_check_folders(&env.custom_dir()).unwrap();
        assert_eq!(found.len(), 1);
        let config = found[0].2.as_ref().unwrap();
        assert_eq!(config.arguments, vec!["one value", "two"]);
        assert_eq!(config.tool_path, "./check.sh");
        let check = find(&catalog().unwrap(), "CUSTOM-ARG");
        assert_eq!(
            execute(&check, check.priority, &check.parameters).summary,
            "one value|two"
        );
    }

    fn import_request(id: &str, override_id: Option<&str>) -> String {
        let bytes = pass_tool("custom pass");
        output_json(&serde_json::json!({
            "id": id, "name": "Custom check", "description": "Local custom check",
            "priority": "HIGH", "enabled": true, "overrideBuiltinId": override_id,
            "cloneFrom": override_id, "fileName": CHECK, "fileBase64": base64_encode(&bytes)
        }))
        .unwrap()
    }

    #[test]
    fn shipped_catalog_has_unique_ids_safe_paths_and_nine_requirements() {
        let _env = TestEnv::new("catalog");
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
        // checkupdates contacts mirrors: REQ-001 gets a longer timeout than the default.
        assert!(find(&catalog, "REQ-001").timeout_seconds > DEFAULT_TIMEOUT_SECONDS);
    }

    #[test]
    fn settings_for_removed_folders_do_not_block_discovery_refresh() {
        let _env = TestEnv::new("stale-settings");
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
    }

    #[test]
    fn builtin_tool_hashes_match_distribution_manifest_and_legacy_reports_remain_unknown() {
        let _env = TestEnv::new("builtin");
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
    }

    #[test]
    fn custom_import_update_remove_and_historical_provenance() {
        let _env = TestEnv::new("custom");
        let request = import_request("CUSTOM-001", None);
        let mut spoof: serde_json::Value = serde_json::from_str(&request).unwrap();
        spoof["origin"] = serde_json::json!("BUILTIN");
        assert!(dashboard_import_custom(&spoof.to_string()).is_err());
        let mut traversal: serde_json::Value = serde_json::from_str(&request).unwrap();
        traversal["fileName"] = serde_json::json!("../evil.sh");
        assert!(dashboard_import_custom(&traversal.to_string()).is_err());
        dashboard_import_custom(&request).unwrap();
        assert!(
            dashboard_import_custom(&request).is_err(),
            "duplicate ID accepted"
        );
        let folder = custom_root().unwrap().join("CUSTOM-001");
        // The imported file keeps its name inside the check folder.
        assert!(folder.join(CHECK).is_file());
        let config_path = folder.join("configuration.json");
        let original_config = fs::read(&config_path).unwrap();
        let mut forged_config: serde_json::Value =
            serde_json::from_slice(&original_config).unwrap();
        forged_config["origin"] = serde_json::json!("BUILTIN");
        fs::write(&config_path, forged_config.to_string()).unwrap();
        let forged = find(&catalog().unwrap(), "CUSTOM-001");
        assert_eq!(forged.origin, ControlOrigin::Custom);
        assert!(
            forged
                .configuration_error
                .as_deref()
                .unwrap()
                .contains("origin"),
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
        fs::write(
            folder.join(CHECK),
            print_tool("{\"status\":\"WARNING\",\"summary\":\"changed\",\"details\":[\"second method unavailable\"]}"),
        )
        .unwrap();
        thread::sleep(Duration::from_millis(3));
        report = serde_json::from_str(&dashboard_check_json("CUSTOM-001").unwrap()).unwrap();
        assert_eq!(report.results[0].status, ResultStatus::Error);
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
        let update_bytes = status_tool("WARNING", "updated");
        let update =
            output_json(&serde_json::json!({"fileBase64":base64_encode(&update_bytes)})).unwrap();
        dashboard_update_custom("CUSTOM-001", &update).unwrap();
        assert_eq!(fs::read(folder.join(CHECK)).unwrap(), update_bytes);
        report = serde_json::from_str(&dashboard_check_json("CUSTOM-001").unwrap()).unwrap();
        assert_eq!(report.results[0].status, ResultStatus::Warn);
        let provenance = report.results[0].provenance.as_ref().unwrap();
        assert_eq!(provenance.tool_version, Some(2));
        assert_eq!(provenance.integrity_status, IntegrityStatus::Verified);
        assert_ne!(
            provenance.actual_sha256.as_deref(),
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
        assert!(!load_settings(&catalog().unwrap())
            .unwrap()
            .requirements
            .contains_key("CUSTOM-001"));
    }

    #[test]
    fn override_is_reported_as_custom_and_restore_or_remove_brings_builtin_back() {
        let _env = TestEnv::new("override");
        dashboard_import_custom(&import_request("CUSTOM-OVR-001", Some("REQ-001"))).unwrap();
        assert!(
            dashboard_import_custom(&import_request("CUSTOM-OVR-002", Some("REQ-001"))).is_err(),
            "second override of the same builtin accepted"
        );
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
        let catalog_after = catalog().unwrap();
        assert_eq!(
            find(&catalog_after, "REQ-001").origin,
            ControlOrigin::Builtin
        );
        assert_eq!(
            find(&catalog_after, "CUSTOM-OVR-001").origin,
            ControlOrigin::Custom
        );
        dashboard_import_custom(&import_request("CUSTOM-OVR-003", Some("REQ-002"))).unwrap();
        assert_eq!(
            find(&catalog().unwrap(), "REQ-002").origin,
            ControlOrigin::Custom
        );
        dashboard_remove_custom("CUSTOM-OVR-003").unwrap();
        assert_eq!(
            find(&catalog().unwrap(), "REQ-002").origin,
            ControlOrigin::Builtin
        );
    }

    #[test]
    fn custom_tool_missing_non_executable_bad_output_and_timeout_are_errors() {
        let env = TestEnv::new("exec");
        let no_id_error = print_tool(
            "{\"status\":\"ERROR\",\"summary\":\"check failed\",\"details\":\"version unavailable\"}",
        );
        let folder = write_custom_folder(
            &env,
            "CUSTOM-ERR",
            CHECK,
            &no_id_error,
            serde_json::json!({}),
        );
        let requirement = find(&catalog().unwrap(), "CUSTOM-ERR");
        let declared_error_result = execute(&requirement, Priority::High, &requirement.parameters);
        assert_eq!(declared_error_result.status, ResultStatus::Error);
        assert!(declared_error_result.summary.contains("check failed"));
        assert!(declared_error_result
            .details
            .iter()
            .any(|d| d == "version unavailable"));
        let rewrite = |bytes: &[u8]| -> Requirement {
            let (_, hash) = store_custom_tool("CUSTOM-ERR", CHECK, bytes).unwrap();
            Requirement {
                expected_sha256: Some(hash),
                ..requirement.clone()
            }
        };
        let id_result = rewrite(&print_tool(
            "{\"id\":\"CUSTOM-ERR\",\"status\":\"PASS\",\"summary\":\"not allowed\",\"details\":[]}",
        ));
        let rejected = execute(&id_result, Priority::High, &id_result.parameters);
        assert!(rejected.summary.contains("invalid JSON or fields"));
        assert!(rejected.details.iter().any(|d| d.contains("unknown field")));
        let invalid_json = rewrite(&print_tool("not-json"));
        assert_eq!(
            execute(&invalid_json, Priority::High, &invalid_json.parameters).status,
            ResultStatus::Error
        );
        #[cfg(unix)]
        {
            let no_shebang = rewrite(
                b"printf '%s\\n' '{\"status\":\"PASS\",\"summary\":\"ok\",\"details\":[]}'\n",
            );
            let refused = execute(&no_shebang, Priority::High, &no_shebang.parameters);
            assert_eq!(refused.status, ResultStatus::Error);
            assert!(refused.summary.contains("no valid interpreter line"));
            assert!(refused.details.iter().any(|d| d.contains("#!")));
        }
        let large = rewrite(if cfg!(windows) {
            b"[Console]::Out.Write('x' * 200000)\r\n".as_slice()
        } else {
            b"#!/bin/sh\nhead -c 200000 /dev/zero | tr '\\0' 'x'\n".as_slice()
        });
        assert!(execute(&large, Priority::High, &large.parameters)
            .summary
            .contains("too large"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(folder.join("check.sh"), fs::Permissions::from_mode(0o600))
                .unwrap();
            let not_executable = execute(&large, Priority::High, &large.parameters);
            assert_eq!(not_executable.status, ResultStatus::Error);
            assert!(not_executable.summary.contains("not executable"));
            fs::set_permissions(folder.join("check.sh"), fs::Permissions::from_mode(0o700))
                .unwrap();
        }
        // The executable-bit check above exists only on Unix.
        #[cfg(not(unix))]
        let _ = &folder;
        let missing = Requirement {
            tools: BTreeMap::from([(platform_key().into(), format!("{CUSTOM_DIR}/missing.tool"))]),
            ..requirement.clone()
        };
        assert_eq!(
            execute(&missing, Priority::High, &missing.parameters).status,
            ResultStatus::Error
        );
        let timeout_req = rewrite(if cfg!(windows) {
            b"while ($true) { }\r\n".as_slice()
        } else {
            b"#!/bin/sh\nwhile :; do :; done".as_slice()
        });
        let timed = execute_with_timeout(
            &timeout_req,
            Priority::High,
            &timeout_req.parameters,
            Duration::from_millis(40),
        );
        assert_eq!(timed.status, ResultStatus::Error);
        assert!(timed.summary.contains("timeout"));
    }

    #[test]
    fn cli_custom_commands_work_without_a_valid_catalog_entry() {
        let env = TestEnv::new("cli-custom");
        write_custom_folder(
            &env,
            "CUSTOM-CLI",
            TOOL,
            &pass_tool("cli"),
            serde_json::json!({"expectedSha256": null}),
        );
        let accept = run(&["custom", "accept", "CUSTOM-CLI"].map(OsString::from)).unwrap();
        assert!(accept.text.contains("SHA-256 atteso aggiornato"));
        let refreshed = run(&[OsString::from("refresh")]).unwrap();
        assert!(
            refreshed.text.contains("1 personalizzati"),
            "{}",
            refreshed.text
        );
        let check = run(&["check", "CUSTOM-CLI"].map(OsString::from)).unwrap();
        assert_eq!(check.code, 0, "{}", check.text);
        run(&["custom", "remove", "CUSTOM-CLI"].map(OsString::from)).unwrap();
        assert!(!env.custom_dir().join("CUSTOM-CLI").exists());
        assert!(run(&["custom", "remove", "CUSTOM-CLI"].map(OsString::from)).is_err());
        assert!(run(&["custom", "drop", "CUSTOM-CLI"].map(OsString::from)).is_err());
        assert!(run(&[OsString::from("bogus")]).is_err());
    }

    #[test]
    fn tool_path_cannot_escape_installation() {
        for path in ["../tool", "/usr/bin/bash", "tools/../x", "", "tools//check"] {
            assert!(!safe_relative_path(path), "{path}");
        }
        assert!(safe_relative_path(
            "share/baradwatchu-client/catalog/checks/REQ-001/check.sh"
        ));
        for name in ["check.sh", "my tool"] {
            assert!(valid_tool_file_name(name), "{name}");
        }
        for name in ["", ".hidden", "configuration.json", "a/b", "..", "x\\y"] {
            assert!(!valid_tool_file_name(name), "{name}");
        }
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
                "Comando: /usr/bin/od -An -tu1 -j4 -N1 /sys/firmware/efi/efivars/SecureBoot".into(),
                "Codice uscita: 1".into(),
            ],
            completed_at_unix_ms: 1,
            provenance: None,
        };
        let log = human_result(&result);
        assert!(log.starts_with("REQ-009  WARN"));
        assert!(log.contains("Comando: /usr/bin/od"));
        assert!(log.contains("Codice uscita: 1"));
        assert!(!log.trim_start().starts_with('{'));
    }

    #[test]
    fn audit_report_is_saved_without_text_log_unless_requested() {
        let env = TestEnv::new("log-option");
        let directory = env.root.join("audits");
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
    }

    #[test]
    fn audit_exit_codes_follow_error_fail_warn_precedence() {
        let env = TestEnv::new("exit-codes");
        for (id, status) in [("CUSTOM-A", "PASS"), ("CUSTOM-B", "WARNING")] {
            write_custom_folder(
                &env,
                id,
                TOOL,
                &status_tool(status, "s"),
                serde_json::json!({}),
            );
        }
        let mut catalog = catalog().unwrap();
        // Keep only the two custom checks so the host's real tools do not affect the code.
        catalog.requirements.retain(|r| r.id.starts_with("CUSTOM-"));
        let settings = load_settings(&catalog).unwrap();
        assert_eq!(
            run_audit(&catalog, &settings, true, false, false)
                .unwrap()
                .code,
            4
        );
        write_custom_folder(
            &env,
            "CUSTOM-C",
            TOOL,
            &status_tool("FAIL", "s"),
            serde_json::json!({}),
        );
        let mut catalog = super::catalog().unwrap();
        catalog.requirements.retain(|r| r.id.starts_with("CUSTOM-"));
        let settings = load_settings(&catalog).unwrap();
        assert_eq!(
            run_audit(&catalog, &settings, true, false, false)
                .unwrap()
                .code,
            3
        );
        fs::create_dir_all(env.custom_dir().join("CUSTOM-D")).unwrap();
        fs::write(env.custom_dir().join("CUSTOM-D/configuration.json"), "{}").unwrap();
        let mut catalog = super::catalog().unwrap();
        catalog.requirements.retain(|r| r.id.starts_with("CUSTOM-"));
        let settings = load_settings(&catalog).unwrap();
        let output = run_audit(&catalog, &settings, true, false, false).unwrap();
        assert_eq!(output.code, 1);
        // Every audit is persisted for `status` and the dashboard history.
        let history = history_reports_at(&history_dir().unwrap()).unwrap();
        assert_eq!(history.len(), 3);
        assert_eq!(history_entry(&history[0]).overall_status, "ERROR");
    }

    #[test]
    fn dashboard_history_lists_reports_newest_first_and_validates_selected_report() {
        let env = TestEnv::new("dashboard-history");
        let directory = env.root.join("history");
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
    }
}
