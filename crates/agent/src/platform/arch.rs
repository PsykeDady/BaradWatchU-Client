//! Offline pacman query only. Never invoke -S/-y, checkupdates, hooks or downloads.
use super::{
    command::{CommandRunner, CommandSpec, ProbeError},
    probe::{failure, unsuccessful},
};
use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    observation::{MetadataState, Observation, RepositoryMetadata, UpdateClass, Updates},
};
use serde_json::json;
use std::{
    collections::BTreeSet,
    fs,
    path::{Component, Path},
    time::UNIX_EPOCH,
};

const SOURCE: &str = "pacman query upgrades + pacman-conf + existing sync database file metadata";
const SCOPE: &str = "configured Arch repositories, local sync metadata only; no upstream or security-advisory verification";
const CONFIG: &str = "/etc/pacman.conf";

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Stamp {
    pub size: u64,
    pub modified_unix_ns: Option<u128>,
    pub changed_unix_ns: i128,
    pub inode: u64,
    pub device: u64,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Snapshot {
    /// None means missing/empty metadata, never a recently synchronized database.
    pub repositories: Vec<(String, Option<Stamp>)>,
    pub local: Option<Stamp>,
}
pub trait Metadata {
    fn snapshot(&self, database: &Path, repositories: &[String]) -> Result<Snapshot, ProbeError>;
}
pub struct SystemMetadata;
fn stamp(path: &Path, directory: bool) -> Result<Option<Stamp>, ProbeError> {
    use std::os::unix::fs::MetadataExt;
    let metadata = match fs::metadata(path) {
        Ok(data) => data,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(ProbeError::io(error)),
    };
    if directory && !metadata.is_dir() || !directory && !metadata.is_file() {
        return Err(ProbeError::new(
            Reason::InvalidOutput,
            "Unexpected pacman database file type",
        ));
    }
    if !directory {
        // Check caller read access; do not read archives ourselves or follow external commands.
        fs::File::open(path).map_err(ProbeError::io)?;
        if metadata.len() == 0 {
            return Ok(None);
        }
    }
    Ok(Some(Stamp {
        size: metadata.len(),
        modified_unix_ns: metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_nanos()),
        changed_unix_ns: i128::from(metadata.ctime()) * 1_000_000_000
            + i128::from(metadata.ctime_nsec()),
        inode: metadata.ino(),
        device: metadata.dev(),
    }))
}
impl Metadata for SystemMetadata {
    fn snapshot(&self, database: &Path, repositories: &[String]) -> Result<Snapshot, ProbeError> {
        let mut entries = Vec::new();
        for id in repositories {
            if !valid_repository(id) {
                return Err(ProbeError::new(
                    Reason::InvalidOutput,
                    "Unsafe repository identifier",
                ));
            }
            entries.push((
                id.clone(),
                stamp(&database.join("sync").join(format!("{id}.db")), false)?,
            ));
        }
        Ok(Snapshot {
            repositories: entries,
            local: stamp(&database.join("local"), true)?,
        })
    }
}
fn valid_repository(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id != "."
        && id != ".."
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"._+-".contains(&c))
}
fn command(program: &str, args: &[&str]) -> CommandSpec {
    let mut spec = CommandSpec::new(program, args);
    spec.read_only_filesystem = true;
    spec
}
fn config(runner: &dyn CommandRunner, field: &str) -> Result<String, Box<Outcome>> {
    match runner.run(&command(
        "/usr/bin/pacman-conf",
        &["--config", CONFIG, field],
    )) {
        Ok(output) if output.code == Some(0) && output.stderr.trim().is_empty() => {
            Ok(output.stdout)
        }
        Ok(output) => Err(Box::new(unsuccessful(&output, SOURCE, SCOPE))),
        Err(error) => Err(Box::new(failure(error, SOURCE, SCOPE))),
    }
}
fn invalid(message: &str) -> Outcome {
    failure(
        ProbeError::new(Reason::InvalidOutput, message),
        SOURCE,
        SCOPE,
    )
}
fn evidence(outcome: Outcome, facts: Updates, ignored: usize, changed: bool) -> Outcome {
    outcome
        .with_evidence(Evidence::new(
            SOURCE,
            SCOPE,
            &[
                ("offline", json!(true)),
                ("databaseSynchronization", json!(false)),
                (
                    "metadataTimestampSource",
                    json!("local sync database file mtime; not upstream verification"),
                ),
                (
                    "securityClassification",
                    json!("UNKNOWN; no advisory data consulted"),
                ),
                ("coverageVerified", json!(false)),
                ("snapshotChanged", json!(changed)),
                ("ignoredPendingPackages", json!(ignored)),
                (
                    "filesystemGuard",
                    json!("Linux Landlock ABI >=3 required; no unsafe retry"),
                ),
                ("privileges", json!("caller; no elevation")),
            ],
        ))
        .with_observation(Observation::Updates(facts))
}
/// Parse full -Qu lines, including ignored upgrades; never discard IgnorePkg violations.
pub fn parse_upgrades(text: &str) -> Result<(usize, usize), ProbeError> {
    let mut packages = BTreeSet::new();
    let mut ignored = 0;
    for line in text.lines() {
        let parts: Vec<_> = line.split_whitespace().collect();
        if !matches!(parts.len(), 4 | 5)
            || parts[2] != "->"
            || (parts.len() == 5 && parts[4] != "[ignored]")
            || !parts[0]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"@._+-".contains(&c))
            || parts[0].starts_with(['-', '.'])
            || !parts[1]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._+:~^-".contains(&c))
            || !parts[3]
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._+:~^-".contains(&c))
            || parts[1] == parts[3]
            || !packages.insert(parts[0])
        {
            return Err(ProbeError::new(
                Reason::InvalidOutput,
                "Malformed or duplicate pacman upgrade record",
            ));
        }
        if parts.len() == 5 {
            ignored += 1;
        }
    }
    Ok((packages.len(), ignored))
}

fn repository_metadata(snapshot: &Snapshot) -> Vec<RepositoryMetadata> {
    snapshot
        .repositories
        .iter()
        .map(|(id, stamp)| RepositoryMetadata {
            id: id.clone(),
            timestamp_unix_seconds: stamp
                .as_ref()
                .and_then(|s| s.modified_unix_ns)
                .and_then(|n| u64::try_from(n / 1_000_000_000).ok()),
            expires_after_seconds: Some(-1), // no pacman expiry setting; policy age limit still applies
        })
        .collect()
}

pub fn updates(runner: &dyn CommandRunner, metadata: &dyn Metadata) -> Outcome {
    let database = match config(runner, "DBPath") {
        Ok(s) => s,
        Err(e) => return *e,
    };
    let database = database.trim();
    if database.is_empty()
        || database.chars().any(char::is_control)
        || !Path::new(database).is_absolute()
        || Path::new(database)
            .components()
            .any(|c| c == Component::ParentDir)
    {
        return invalid(
            "pacman DBPath must be one absolute path without traversal/control characters",
        );
    }
    let root = match config(runner, "RootDir") {
        Ok(s) => s,
        Err(e) => return *e,
    };
    if root.trim() != "/" {
        return evidence(
            Outcome::new(
                Status::Warn,
                Reason::UpdateScopeInconclusive,
                "Configured pacman RootDir is not /; no endpoint update verdict",
            ),
            Updates::default(),
            0,
            false,
        );
    }
    let repos = match config(runner, "--repo-list") {
        Ok(s) => s,
        Err(e) => return *e,
    };
    let mut repositories = Vec::new();
    let mut seen = BTreeSet::new();
    for id in repos.lines() {
        if !valid_repository(id) || !seen.insert(id) || repositories.len() >= 128 {
            return invalid("Malformed, duplicate or excessive configured repository identifiers");
        }
        repositories.push(id.to_owned());
    }
    if repositories.is_empty() {
        return evidence(
            Outcome::new(
                Status::Warn,
                Reason::NoEnabledRepositories,
                "No configured pacman repositories; update coverage unavailable",
            ),
            Updates {
                metadata_state: MetadataState::Missing,
                ..Updates::default()
            },
            0,
            false,
        );
    }
    let before = match metadata.snapshot(Path::new(database), &repositories) {
        Ok(s) => s,
        Err(e) => return failure(e, SOURCE, SCOPE),
    };
    let missing =
        before.local.is_none() || before.repositories.iter().any(|(_, stamp)| stamp.is_none());
    if missing {
        return evidence(
            Outcome::new(
                Status::Warn,
                Reason::CacheUnavailable,
                "Package metadata missing or empty; no package query or synchronization attempted",
            ),
            Updates {
                metadata_state: MetadataState::Missing,
                repositories: repository_metadata(&before),
                ..Updates::default()
            },
            0,
            false,
        );
    }
    let partial = Updates {
        metadata_state: MetadataState::Available,
        repositories: repository_metadata(&before),
        ..Updates::default()
    };
    let mut query = command(
        "/usr/bin/pacman",
        &[
            "--query",
            "--upgrades",
            "--color",
            "never",
            "--config",
            CONFIG,
            "--dbpath",
            database,
            "--logfile",
            "/dev/null",
        ],
    );
    query.allow_null_device = true;
    let output = match runner.run(&query) {
        Ok(output) => output,
        Err(e) => return evidence(failure(e, SOURCE, SCOPE), partial, 0, false),
    };
    // pacman returns 1 for an empty filtered query. Any diagnostic or other exit
    // remains an execution failure; never interpret a failed command as no updates.
    if !output.stderr.trim().is_empty()
        || !matches!(output.code, Some(0 | 1))
        || output.code == Some(1) && !output.stdout.trim().is_empty()
    {
        let mut outcome = unsuccessful(&output, SOURCE, SCOPE);
        let diagnostic = output.stderr.to_ascii_lowercase();
        let engine_unavailable = diagnostic.contains("gpgme error: invalid crypto engine");
        let missing_signature = diagnostic.contains("missing required signature");
        if engine_unavailable || missing_signature {
            outcome.message = "pacman metadata validation failed: cryptographic engine or required database signature unavailable; verification was not bypassed".to_owned();
            outcome = outcome.with_evidence(Evidence::new(
                "pacman diagnostics (categorized; raw stderr omitted)",
                SCOPE,
                &[
                    ("cryptoEngineUnavailable", json!(engine_unavailable)),
                    ("requiredDatabaseSignatureMissing", json!(missing_signature)),
                ],
            ));
        }
        return evidence(outcome, partial, 0, false);
    }
    let (pending, ignored) = match parse_upgrades(&output.stdout) {
        Ok(s) => s,
        Err(e) => return failure(e, SOURCE, SCOPE),
    };
    let after = match metadata.snapshot(Path::new(database), &repositories) {
        Ok(s) => s,
        Err(e) => return failure(e, SOURCE, SCOPE),
    };
    let changed = before != after;
    let mut facts = Updates {
        classification: if pending == 0 {
            UpdateClass::NoPending
        } else {
            UpdateClass::UnknownSecurity
        },
        pending_packages: Some(pending),
        // Zero observed candidates is not an assertion about unseen advisory data.
        security_advisories: if pending == 0 { Some(0) } else { None },
        ordinary_pending: if pending == 0 { Some(false) } else { None },
        classification_complete: pending == 0,
        metadata_state: if missing {
            MetadataState::Missing
        } else {
            MetadataState::Available
        },
        // Local file mtimes cannot prove present-day upstream completeness or
        // security coverage. Keep this false even for recent, readable databases.
        coverage_complete: false,
        repositories: repository_metadata(&before),
    };
    let (status, reason, message) = if changed {
        // Discard cross-snapshot classifications, not evidence of a stable query.
        facts.classification = UpdateClass::Unknown;
        facts.classification_complete = false;
        (
            Status::Warn,
            Reason::UpdateScopeInconclusive,
            "Package metadata changed during observation; query not an atomic snapshot",
        )
    } else if pending > 0 {
        (
            Status::Fail,
            Reason::UpdatesAvailable,
            "Pending updates found in local pacman metadata; security classification unknown",
        )
    } else {
        (
            Status::Warn,
            Reason::NoCachedUpdates,
            "No updates in available pacman metadata; current upstream/security status unknown",
        )
    };
    facts.repositories.sort_by(|a, b| a.id.cmp(&b.id));
    evidence(
        Outcome::new(status, reason, message),
        facts,
        ignored,
        changed,
    )
}
