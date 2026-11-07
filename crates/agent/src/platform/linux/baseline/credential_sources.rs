//! Bounded, consistency-checked CP5 configuration reads. No shadow access.
use super::files::{text, Files, Node, SystemFiles};
use crate::{audit::Reason, platform::command::ProbeError};
use std::collections::BTreeMap;

pub fn unavailable() -> ProbeError {
    ProbeError::new(
        Reason::EvidenceInconclusive,
        "Credential metadata unavailable or unsupported; raw data omitted",
    )
}
pub fn name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && !s.starts_with('.')
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}

/// Resolve only standard Fedora authselect PAM links. Other symlinks fail closed.
/// Paths are checked again around each operation and by Snapshot at completion.
pub struct CredentialFiles;
fn resolved(path: &str) -> Result<String, ProbeError> {
    if path.starts_with("/etc/pam.d/") {
        let p = match std::fs::canonicalize(path) {
            Ok(p) => p,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(path.into()),
            Err(_) => return Err(unavailable()),
        };
        let s = p.to_str().ok_or_else(unavailable)?;
        if !s.starts_with("/etc/pam.d/") && !s.starts_with("/etc/authselect/") {
            return Err(unavailable());
        }
        Ok(s.into())
    } else {
        Ok(path.into())
    }
}
impl Files for CredentialFiles {
    fn read(&self, p: &str, limit: usize) -> Result<Option<Vec<u8>>, ProbeError> {
        let r = resolved(p)?;
        let data = SystemFiles.read(&r, limit)?;
        if r != resolved(p)? {
            return Err(unavailable());
        }
        Ok(data)
    }
    fn info(&self, p: &str) -> Result<Option<Node>, ProbeError> {
        SystemFiles.info(&resolved(p)?)
    }
    fn entries(&self, p: &str) -> Result<Option<Vec<String>>, ProbeError> {
        SystemFiles.entries(p)
    }
}
type Source = (Option<Node>, Option<String>);
pub struct Snapshot<'a> {
    pub files: &'a dyn Files,
    sources: BTreeMap<String, Source>,
    directories: BTreeMap<String, Option<Vec<String>>>,
}
impl<'a> Snapshot<'a> {
    pub fn new(files: &'a dyn Files) -> Self {
        Self {
            files,
            sources: BTreeMap::new(),
            directories: BTreeMap::new(),
        }
    }
    pub fn read(&mut self, path: &str) -> Result<Option<String>, ProbeError> {
        if let Some((_, data)) = self.sources.get(path) {
            return Ok(data.clone());
        }
        if self.sources.len() >= 128 {
            return Err(unavailable());
        }
        let before = self.files.info(path)?;
        let data = text(self.files, path, 65536)?;
        if before != self.files.info(path)? {
            return Err(unavailable());
        }
        self.sources.insert(path.into(), (before, data.clone()));
        Ok(data)
    }
    pub fn required(&mut self, path: &str) -> Result<String, ProbeError> {
        self.read(path)?.ok_or_else(unavailable)
    }
    pub fn entries(&mut self, path: &str) -> Result<Vec<String>, ProbeError> {
        let entries = self.files.entries(path)?;
        if entries
            .as_ref()
            .is_some_and(|v| v.len() > 64 || v.iter().any(|s| !name(s)))
        {
            return Err(unavailable());
        }
        let mut result = entries.clone().unwrap_or_default();
        result.sort();
        self.directories.insert(path.into(), entries);
        Ok(result)
    }
    pub fn consistent(&self) -> Result<(), ProbeError> {
        for (p, (metadata, data)) in &self.sources {
            if self.files.info(p)? != *metadata
                || text(self.files, p, 65536)? != *data
                || self.files.info(p)? != *metadata
            {
                return Err(unavailable());
            }
        }
        for (p, entries) in &self.directories {
            if self.files.entries(p)? != *entries {
                return Err(unavailable());
            }
        }
        Ok(())
    }
}
