//! Local additive monitoring targets. This is not an authenticated policy.
use crate::policy::{
    validate_targets, EvidencePolicy, Policy, SensitivePolicy, SensitiveTarget, POLICY_SCHEMA_V3,
};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Read, path::Path};

pub const LOCAL_SCHEMA: &str = "baradwatchu.local-monitoring.v1";

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct LocalConfig {
    pub schema_version: String,
    #[serde(default)]
    pub sensitive_targets: Vec<SensitiveTarget>,
}
impl LocalConfig {
    pub fn from_json(text: &str) -> Result<Self, String> {
        if text.len() > 65536 {
            return Err("Local configuration exceeds 64 KiB".into());
        }
        let config: Self = serde_json::from_str(text)
            .map_err(|_| "Invalid local configuration JSON".to_owned())?;
        if config.schema_version != LOCAL_SCHEMA {
            return Err("Unsupported local configuration schema".into());
        }
        validate_targets(&config.sensitive_targets)?;
        Ok(config)
    }
    pub fn load(path: &Path) -> Result<Self, String> {
        let file = File::open(path).map_err(|_| "Cannot read local configuration".to_owned())?;
        if !file
            .metadata()
            .map_err(|_| "Cannot inspect local configuration".to_owned())?
            .is_file()
        {
            return Err("Local configuration must be a regular file".into());
        }
        let mut text = String::new();
        file.take(65537)
            .read_to_string(&mut text)
            .map_err(|_| "Cannot read local configuration as UTF-8".to_owned())?;
        Self::from_json(&text)
    }
    /// Adds targets to a copy; IDs are unique across both sources. No local
    /// field can disable a control, replace a required target, or alter policy.
    pub fn effective_policy(&self, policy: &Policy) -> Result<Policy, String> {
        policy.validate()?;
        if policy.schema_version != POLICY_SCHEMA_V3 {
            return Err("Local monitoring requires policy v3".into());
        }
        validate_targets(&self.sensitive_targets)?;
        let mut effective = policy.clone();
        if self.sensitive_targets.is_empty() {
            return Ok(effective);
        }
        if effective
            .checks
            .sensitive_encryption
            .as_ref()
            .is_some_and(|p| !p.enabled)
        {
            return Err("Local targets cannot override a disabled policy check".into());
        }
        let coverage = effective
            .checks
            .sensitive_encryption
            .get_or_insert_with(|| SensitivePolicy {
                enabled: true,
                mandatory: false,
                evidence: EvidencePolicy::default(),
                max_observation_age_seconds: 300,
                targets: Vec::new(),
            });
        coverage
            .targets
            .extend(self.sensitive_targets.iter().cloned());
        validate_targets(&coverage.targets)?;
        effective.validate()?;
        Ok(effective)
    }
}
