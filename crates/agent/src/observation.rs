//! Typed probe facts, independent of organizational requirements.
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(tag = "kind", content = "data", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Observation {
    Updates(Updates),
    RootEncryption(RootEncryption),
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum UpdateClass { NoPending, OrdinaryPending, SecurityPending, UnknownSecurity, Unknown }

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum MetadataState { Available, Missing, Unknown }

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
        Self { classification: UpdateClass::Unknown, pending_packages: None, security_advisories: None,
            ordinary_pending: None, classification_complete: false,
            metadata_state: MetadataState::Unknown, coverage_complete: false, repositories: vec![] }
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
