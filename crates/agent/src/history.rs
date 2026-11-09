//! Local audit history maintenance: list, disk usage, delete one audit or clear all.
//!
//! An audit is identified by its completion stamp (Unix ms) and owns every file named
//! `<stamp>.json|.log|.pdf` in the history folder or in its `reports/` subfolder (legacy
//! reports lived in the folder itself; PDF reports are planned there too). Only those names
//! are ever touched: nothing is followed, recursed into or removed outside that pattern.
use crate::requirements::{self as req, CliError, CliOutput};
use serde::Serialize;
use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const ARTIFACT_EXTENSIONS: [&str; 3] = ["json", "log", "pdf"];
fn usage_text() -> &'static str {
    baradwatchu_messages::message("history.usage", baradwatchu_messages::configured_language())
}

struct Artifact {
    path: PathBuf,
    stamp: u64,
    bytes: u64,
}

#[derive(Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Usage {
    pub audits: usize,
    pub files: usize,
    pub bytes: u64,
}

#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct Removal {
    removed_audits: usize,
    removed_files: usize,
    freed_bytes: u64,
    usage: Usage,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ListedAudit {
    completed_at_unix_ms: u64,
    overall_status: Option<String>,
    files: usize,
    bytes: u64,
}

fn stamp_of(name: &str) -> Option<u64> {
    let (stem, extension) = name.rsplit_once('.')?;
    if !ARTIFACT_EXTENSIONS.contains(&extension)
        || stem.is_empty()
        || stem.len() > 20
        || !stem.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    stem.parse().ok()
}

fn artifacts_at(directory: &Path) -> Result<Vec<Artifact>, CliError> {
    let mut artifacts = Vec::new();
    for folder in [directory.to_path_buf(), directory.join("reports")] {
        let metadata = match fs::symlink_metadata(&folder) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
            Err(_) => return Err(CliError("Cannot inspect audit history".into())),
        };
        if !metadata.is_dir() || metadata.file_type().is_symlink() {
            return Err(CliError("Audit history directory is unsafe".into()));
        }
        let entries =
            fs::read_dir(&folder).map_err(|_| CliError("Cannot read audit history".into()))?;
        for entry in entries {
            let entry = entry.map_err(|_| CliError("Cannot read an audit history entry".into()))?;
            let Some(stamp) = entry.file_name().to_str().and_then(stamp_of) else {
                continue;
            };
            let metadata = entry
                .path()
                .symlink_metadata()
                .map_err(|_| CliError("Cannot inspect an audit history entry".into()))?;
            // Regular files and stray links (unlinking a link never touches its target).
            if metadata.is_file() || metadata.file_type().is_symlink() {
                artifacts.push(Artifact {
                    path: entry.path(),
                    stamp,
                    bytes: if metadata.is_file() {
                        metadata.len()
                    } else {
                        0
                    },
                });
            }
        }
    }
    Ok(artifacts)
}

fn usage_of(artifacts: &[Artifact]) -> Usage {
    let mut stamps = artifacts.iter().map(|item| item.stamp).collect::<Vec<_>>();
    stamps.sort_unstable();
    stamps.dedup();
    Usage {
        audits: stamps.len(),
        files: artifacts.len(),
        bytes: artifacts.iter().map(|item| item.bytes).sum(),
    }
}

fn remove(directory: &Path, artifacts: Vec<Artifact>) -> Result<Removal, CliError> {
    let removed = usage_of(&artifacts);
    for artifact in &artifacts {
        match fs::remove_file(&artifact.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(_) => {
                return Err(CliError(format!(
                    "Cannot remove {}",
                    artifact.path.display()
                )))
            }
        }
    }
    Ok(Removal {
        removed_audits: removed.audits,
        removed_files: removed.files,
        freed_bytes: removed.bytes,
        usage: usage_of(&artifacts_at(directory)?),
    })
}

fn parse_stamp(value: &str) -> Result<u64, CliError> {
    if value.is_empty() || value.len() > 20 || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CliError("Invalid audit history identifier".into()));
    }
    value
        .parse()
        .map_err(|_| CliError("Invalid audit history identifier".into()))
}

fn delete_at(directory: &Path, stamp: u64) -> Result<Removal, CliError> {
    let artifacts = artifacts_at(directory)?
        .into_iter()
        .filter(|item| item.stamp == stamp)
        .collect::<Vec<_>>();
    if artifacts.is_empty() {
        return Err(CliError("Audit not found in local history".into()));
    }
    remove(directory, artifacts)
}

fn clear_at(directory: &Path) -> Result<Removal, CliError> {
    remove(directory, artifacts_at(directory)?)
}

pub(crate) fn usage() -> Result<Usage, CliError> {
    Ok(usage_of(&artifacts_at(&req::history_dir()?)?))
}

fn json<T: Serialize>(value: &T) -> Result<String, CliError> {
    serde_json::to_string_pretty(value)
        .map(|text| text + "\n")
        .map_err(|_| CliError("Cannot serialize audit history".into()))
}

pub(crate) fn dashboard_usage_json() -> Result<String, CliError> {
    json(&usage()?)
}

pub(crate) fn dashboard_delete_json(stamp: &str) -> Result<String, CliError> {
    json(&delete_at(&req::history_dir()?, parse_stamp(stamp)?)?)
}

pub(crate) fn dashboard_clear_json() -> Result<String, CliError> {
    json(&clear_at(&req::history_dir()?)?)
}

/// Human-readable size: "512 B", "3.4 KiB", "1.2 MiB".
pub(crate) fn size_text(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["KiB", "MiB", "GiB", "TiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64 / 1024.0;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

fn listed(directory: &Path) -> Result<Vec<ListedAudit>, CliError> {
    let mut by_stamp = BTreeMap::<u64, (usize, u64, Option<PathBuf>)>::new();
    for artifact in artifacts_at(directory)? {
        let slot = by_stamp.entry(artifact.stamp).or_default();
        slot.0 += 1;
        slot.1 += artifact.bytes;
        if artifact.path.extension().is_some_and(|ext| ext == "json") {
            slot.2 = Some(artifact.path);
        }
    }
    Ok(by_stamp
        .into_iter()
        .rev()
        .map(|(stamp, (files, bytes, report))| ListedAudit {
            completed_at_unix_ms: stamp,
            // A damaged report is still listed (and deletable), just without an outcome.
            overall_status: report
                .and_then(|path| req::read_history_report(&path, stamp).ok())
                .map(|report| req::history_entry(&report).overall_status),
            files,
            bytes,
        })
        .collect())
}

fn removal_text(removal: &Removal) -> String {
    baradwatchu_messages::message(
        "history.removed",
        baradwatchu_messages::configured_language(),
    )
    .replace("{audits}", &removal.removed_audits.to_string())
    .replace("{files}", &removal.removed_files.to_string())
    .replace("{size}", &size_text(removal.freed_bytes))
    .replace("{remaining}", &removal.usage.audits.to_string())
    .replace("{remaining_size}", &size_text(removal.usage.bytes))
}

pub fn run(args: &[OsString]) -> Result<CliOutput, CliError> {
    let args = args
        .iter()
        .map(|arg| arg.to_str())
        .collect::<Option<Vec<_>>>();
    let Some(args) = args else {
        return Err(CliError(usage_text().into()));
    };
    let text = match args.as_slice() {
        [] | ["--json"] => {
            let directory = req::history_dir()?;
            let audits = listed(&directory)?;
            if args.is_empty() {
                let total = usage_of(&artifacts_at(&directory)?);
                let mut text = baradwatchu_messages::message(
                    "history.header",
                    baradwatchu_messages::configured_language(),
                )
                .replace("{path}", &directory.display().to_string())
                .replace("{audits}", &total.audits.to_string())
                .replace("{size}", &size_text(total.bytes));
                for audit in &audits {
                    let language = baradwatchu_messages::configured_language();
                    let status = match audit.overall_status.as_deref() {
                        Some("PASS") => baradwatchu_messages::message("status.pass", language),
                        Some("FAIL") => baradwatchu_messages::message("status.fail", language),
                        Some("WARN") => baradwatchu_messages::message("status.warning", language),
                        Some("ERROR") => baradwatchu_messages::message("status.error", language),
                        _ => baradwatchu_messages::message("history.status.unknown", language),
                    };
                    text.push_str(
                        &baradwatchu_messages::message("history.entry", language)
                            .replace("{stamp}", &audit.completed_at_unix_ms.to_string())
                            .replace("{status}", &format!("{status:<7}"))
                            .replace("{files}", &audit.files.to_string())
                            .replace("{size}", &size_text(audit.bytes)),
                    );
                }
                text
            } else {
                json(&audits)?
            }
        }
        ["delete", stamp] => removal_text(&delete_at(&req::history_dir()?, parse_stamp(stamp)?)?),
        ["clear", "--yes"] => removal_text(&clear_at(&req::history_dir()?)?),
        _ => return Err(CliError(usage_text().into())),
    };
    Ok(CliOutput { text, code: 0 })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, bytes: usize) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, vec![b'x'; bytes]).unwrap();
    }

    #[test]
    fn stamps_only_match_audit_artifact_names() {
        assert_eq!(stamp_of("1700000000000.json"), Some(1_700_000_000_000));
        assert_eq!(stamp_of("17.log"), Some(17));
        assert_eq!(stamp_of("17.pdf"), Some(17));
        for name in [
            "notes.json",
            "17.txt",
            ".json",
            "17",
            "1a.json",
            "-1.log",
            "17.json.bak",
        ] {
            assert_eq!(stamp_of(name), None, "{name}");
        }
        assert!(parse_stamp("12").is_ok());
        for bad in ["", "1/2", "..", "12a", "123456789012345678901"] {
            assert!(parse_stamp(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn delete_one_and_clear_all_touch_only_audit_files() {
        let env = req::TestEnv::new("history-clear");
        let dir = req::history_dir().unwrap();
        write(&dir.join("reports/100.json"), 10);
        write(&dir.join("100.log"), 5);
        write(&dir.join("100.pdf"), 7);
        write(&dir.join("reports/200.json"), 20);
        write(&dir.join("150.json"), 3); // legacy location
        write(&dir.join("keep.txt"), 1);
        write(&dir.join("reports/notes.json"), 1);
        write(&dir.join("sub/300.json"), 1); // never recursed into

        assert_eq!(
            usage().unwrap(),
            Usage {
                audits: 3,
                files: 5,
                bytes: 45
            }
        );
        assert!(delete_at(&dir, 999).is_err());
        let removal = delete_at(&dir, 100).unwrap();
        assert_eq!(
            (
                removal.removed_audits,
                removal.removed_files,
                removal.freed_bytes
            ),
            (1, 3, 22)
        );
        assert_eq!(
            removal.usage,
            Usage {
                audits: 2,
                files: 2,
                bytes: 23
            }
        );
        assert!(!dir.join("100.log").exists() && !dir.join("100.pdf").exists());
        assert!(dir.join("reports/200.json").exists());

        let removal = clear_at(&dir).unwrap();
        assert_eq!((removal.removed_audits, removal.removed_files), (2, 2));
        assert_eq!(removal.usage, Usage::default());
        assert!(dir.join("keep.txt").exists());
        assert!(dir.join("reports/notes.json").exists());
        assert!(dir.join("sub/300.json").exists());
        assert!(dir.join("reports").is_dir());
        drop(env);
    }

    #[cfg(unix)]
    #[test]
    fn links_are_unlinked_without_touching_their_targets() {
        let env = req::TestEnv::new("history-link");
        let dir = req::history_dir().unwrap();
        let outside = env.root.join("outside.json");
        write(&outside, 4);
        fs::create_dir_all(dir.join("reports")).unwrap();
        std::os::unix::fs::symlink(&outside, dir.join("reports/5.json")).unwrap();
        let removal = clear_at(&dir).unwrap();
        assert_eq!(removal.removed_files, 1);
        assert!(outside.exists());
        assert!(fs::symlink_metadata(dir.join("reports/5.json")).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn unsafe_history_folder_is_refused() {
        let env = req::TestEnv::new("history-unsafe");
        let dir = req::history_dir().unwrap();
        let elsewhere = env.root.join("elsewhere");
        write(&elsewhere.join("7.json"), 1);
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &dir).unwrap();
        assert!(clear_at(&dir).is_err());
        assert!(elsewhere.join("7.json").exists());
    }

    #[test]
    fn listing_keeps_damaged_reports_deletable() {
        let env = req::TestEnv::new("history-list");
        let dir = req::history_dir().unwrap();
        write(&dir.join("reports/42.json"), 3); // not valid JSON
        write(&dir.join("42.log"), 2);
        let audits = listed(&dir).unwrap();
        assert_eq!(audits.len(), 1);
        assert_eq!(audits[0].overall_status, None);
        assert_eq!((audits[0].files, audits[0].bytes), (2, 5));
        let out = run(&["history".into(), "x".into()][1..]).unwrap_err();
        assert!(out.0.starts_with("Usage: history"));
        assert!(
            run(&[OsString::from("clear")]).is_err(),
            "clear needs --yes"
        );
        let out = run(&[OsString::from("delete"), OsString::from("42")]).unwrap();
        assert!(out.text.starts_with("Rimossi 1 audit (2 file"));
        drop(env);
    }

    #[test]
    fn sizes_are_human_readable() {
        assert_eq!(size_text(0), "0 B");
        assert_eq!(size_text(1023), "1023 B");
        assert_eq!(size_text(1536), "1.5 KiB");
        assert_eq!(size_text(5 * 1024 * 1024), "5.0 MiB");
    }
}
