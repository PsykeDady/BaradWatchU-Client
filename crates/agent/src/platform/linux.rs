//! os-release is parsed as data, never sourced/evaluated as shell code.
use super::command::ProbeError;
use crate::audit::{OperatingSystem, Reason};
use std::{
    collections::BTreeMap,
    fs::File,
    io::{self, Read},
    path::Path,
};

fn read(path: &Path) -> io::Result<String> {
    let mut text = String::new();
    File::open(path)?.take(65537).read_to_string(&mut text)?;
    if text.len() > 65536 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "os-release exceeds size limit",
        ));
    }
    Ok(text)
}

pub fn read_identity(
    primary: &Path,
    fallback: &Path,
    atomic: bool,
) -> Result<OperatingSystem, ProbeError> {
    let (text, path) = match read(primary) {
        Ok(text) => (text, primary),
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            let text = read(fallback).map_err(|error| {
                if error.kind() == io::ErrorKind::NotFound {
                    ProbeError::new(
                        Reason::MissingOsRelease,
                        "Neither /etc/os-release nor /usr/lib/os-release is available",
                    )
                } else {
                    ProbeError::io(error)
                }
            })?;
            (text, fallback)
        }
        Err(error) => return Err(ProbeError::io(error)),
    };
    parse_os_release(&text, &path.to_string_lossy(), atomic)
}

pub fn detect() -> Result<OperatingSystem, ProbeError> {
    let atomic = match std::fs::metadata("/run/ostree-booted") {
        Ok(_) => true,
        Err(error) if error.kind() == io::ErrorKind::NotFound => false,
        Err(error) => return Err(ProbeError::io(error)),
    };
    read_identity(
        Path::new("/etc/os-release"),
        Path::new("/usr/lib/os-release"),
        atomic,
    )
}

fn value(raw: &str) -> Result<String, ProbeError> {
    let invalid = || {
        ProbeError::new(
            Reason::InvalidOsRelease,
            "Malformed identity field in os-release",
        )
    };
    if raw.starts_with('\'') && raw.ends_with('\'') && raw.len() >= 2 {
        let inner = &raw[1..raw.len() - 1];
        if inner.contains('\'') {
            return Err(invalid());
        }
        return Ok(inner.to_owned());
    }
    if raw.starts_with('"') && raw.ends_with('"') && raw.len() >= 2 {
        let mut chars = raw[1..raw.len() - 1].chars();
        let mut text = String::new();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                let next = chars.next().ok_or_else(invalid)?;
                if !matches!(next, '$' | '`' | '"' | '\\') {
                    text.push('\\');
                }
                text.push(next);
            } else if matches!(ch, '"' | '$' | '`') {
                return Err(invalid());
            } else {
                text.push(ch);
            }
        }
        return Ok(text);
    }
    if !raw
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || "._-".contains(ch))
    {
        return Err(invalid());
    }
    Ok(raw.to_owned())
}

pub fn parse_os_release(
    text: &str,
    source: &str,
    atomic: bool,
) -> Result<OperatingSystem, ProbeError> {
    let mut fields = BTreeMap::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, raw)) = line.split_once('=') else {
            return Err(ProbeError::new(
                Reason::InvalidOsRelease,
                "Invalid assignment in os-release",
            ));
        };
        if !matches!(
            key,
            "ID" | "NAME" | "PRETTY_NAME" | "VERSION_ID" | "VARIANT_ID"
        ) {
            continue;
        }
        if fields.insert(key.to_owned(), value(raw)?).is_some() {
            return Err(ProbeError::new(
                Reason::InvalidOsRelease,
                "Duplicate identity field in os-release",
            ));
        }
    }
    let id = fields
        .remove("ID")
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            ProbeError::new(
                Reason::InvalidOsRelease,
                "os-release has no distribution ID",
            )
        })?;
    if !id
        .chars()
        .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || "._-".contains(ch))
    {
        return Err(ProbeError::new(
            Reason::InvalidOsRelease,
            "Invalid distribution ID",
        ));
    }
    let version = fields.remove("VERSION_ID").filter(|v| !v.is_empty());
    if id == "fedora"
        && version
            .as_deref()
            .and_then(|v| v.parse::<u32>().ok())
            .is_none()
    {
        return Err(ProbeError::new(
            Reason::InvalidOsRelease,
            "Fedora VERSION_ID is missing or not a numeric release",
        ));
    }
    let variant = fields.remove("VARIANT_ID");
    let image_variant = variant.as_deref().is_some_and(|v| {
        matches!(
            v,
            "coreos" | "silverblue" | "kinoite" | "sericea" | "onyx" | "iot" | "bootc"
        ) || v.contains("atomic")
    });
    let supported = id == "fedora" && !atomic && !image_variant;
    Ok(OperatingSystem {
        family: "linux".to_owned(), architecture: std::env::consts::ARCH.to_owned(),
        distribution_id: Some(id), name: fields.remove("PRETTY_NAME").or_else(|| fields.remove("NAME")),
        version_id: version, variant_id: variant, identity_source: Some(source.to_owned()), supported,
        support_reason: if supported { "Fedora RPM/DNF5 baseline; root-filesystem encryption scope only" }
            else { "Unsupported platform: only Fedora RPM/DNF5; derivatives and image/ostree systems are excluded" }.to_owned(),
    })
}
