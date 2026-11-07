//! Typed probe facts, independent of organizational requirements.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Observation {
    Updates(Updates),
    RootEncryption(RootEncryption),
    SecureBoot(SecureBoot),
    Tpm(Tpm),
    Firewall(Firewall),
    ScreenLock(ScreenLock),
    EncryptionCoverage(EncryptionCoverage),
    PasswordAging(PasswordAging),
    PasswordComplexity(PasswordComplexity),
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AgingValues {
    pub maximum_days: Option<i64>,
    pub minimum_days: Option<i64>,
    pub warning_days: Option<i64>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountAging {
    /// Report-local ordinal, never a login name, UID or home directory.
    pub id: String,
    pub quality: Quality,
    pub values: AgingValues,
    pub expires: Option<bool>,
    pub reason: String,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordAging {
    pub quality: Quality,
    pub scope: String,
    pub creation_defaults: AgingValues,
    pub accounts: Vec<AccountAging>,
    pub excluded_accounts: usize,
    pub external_authority_configured: Option<bool>,
}
#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordRequirements {
    pub minimum_length: Option<i32>,
    pub minimum_classes: Option<i32>,
    /// Negative values require characters; positive values are length credits.
    pub credits: [Option<i32>; 4],
    pub enforcing: Option<bool>,
    pub enforce_for_root: Option<bool>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordStack {
    pub id: String,
    pub quality: Quality,
    pub enforcement_proven: bool,
    pub password_changes_denied: bool,
    pub requirements: Option<PasswordRequirements>,
    pub reason: String,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordComplexity {
    pub quality: Quality,
    pub scope: String,
    pub stacks: Vec<PasswordStack>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Protection {
    Protected,
    Unprotected,
    Inconclusive,
    NotApplicable,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoverageItem {
    pub id: String,
    pub protection: Protection,
    pub technology: Option<String>,
    pub mounted: Option<bool>,
    pub at_rest: Option<bool>,
    pub source: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptionCoverage {
    pub quality: Quality,
    pub items: Vec<CoverageItem>,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateClass {
    NoPending,
    OrdinaryPending,
    SecurityPending,
    UnknownSecurity,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MetadataState {
    Available,
    Missing,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RepositoryMetadata {
    pub id: String,
    pub timestamp_unix_seconds: Option<u64>,
    pub expires_after_seconds: Option<i64>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Updates {
    pub classification: UpdateClass,
    pub pending_packages: Option<usize>,
    pub security_advisories: Option<usize>,
    pub ordinary_pending: Option<bool>,
    pub classification_complete: bool,
    pub metadata_state: MetadataState,
    pub coverage_complete: bool,
    pub repositories: Vec<RepositoryMetadata>,
}
impl Default for Updates {
    fn default() -> Self {
        Self {
            classification: UpdateClass::Unknown,
            pending_packages: None,
            security_advisories: None,
            ordinary_pending: None,
            classification_complete: false,
            metadata_state: MetadataState::Unknown,
            coverage_complete: false,
            repositories: vec![],
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BackingPath {
    /// Major:minor identifiers only; no labels, serials or encryption UUIDs.
    pub devices: Vec<String>,
    pub luks_protected: bool,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RootEncryption {
    pub root_filesystem: String,
    pub root_device: String,
    pub topology_complete: bool,
    pub paths: Vec<BackingPath>,
}

/// Quality is independent of organizational requirements. Unknown states cannot certify compliance.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Quality {
    Verified,
    Missing,
    Inconclusive,
    Unsupported,
    NotApplicable,
    Restricted,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum BootState {
    Enabled,
    Disabled,
    NonUefiBoot,
    VariablesUnavailable,
    Inconsistent,
    Restricted,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecureBoot {
    pub quality: Quality,
    pub state: BootState,
    pub secure_boot: Option<bool>,
    pub setup_mode: Option<bool>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TpmDevice {
    pub version_major: Option<u32>,
    pub character_device_verified: bool,
    /// Permission metadata/access() only; the TPM is never opened or sent commands.
    pub read_permission: Option<bool>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Tpm {
    pub quality: Quality,
    pub devices: Vec<TpmDevice>,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FirewallManager {
    pub name: String,
    pub installed: Option<bool>,
    pub active: Option<bool>,
    pub running: Option<bool>,
}
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Filtering {
    VerifiedInputFiltering,
    NoFilteringInInspectedInputBackends,
    Unknown,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Firewall {
    pub quality: Quality,
    pub managers: Vec<FirewallManager>,
    pub filtering: Filtering,
    pub ipv4_verified: bool,
    pub ipv6_verified: bool,
    pub multiple_managers: bool,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScreenLock {
    pub quality: Quality,
    pub session_scope: String,
    pub capability: Option<bool>,
    pub configuration_enabled: Option<bool>,
    pub automatic_lock: Option<bool>,
    pub idle_timeout_seconds: Option<u32>,
    pub grace_seconds: Option<u32>,
    pub password_required: Option<bool>,
    pub lock_on_resume: Option<bool>,
    /// Screensaver GetActive, not an assertion that the password grace period has elapsed.
    pub current_screen_saver_active: Option<bool>,
}
