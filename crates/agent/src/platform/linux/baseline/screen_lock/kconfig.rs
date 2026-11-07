//! Standard Linux Qt6/KConfig6 resolution profile. KConfig, not this collector,
//! decides precedence and immutable key/group/file semantics. Upstream contracts:
//! qtbase qstandardpaths_unix.cpp; kconfig core/kconfig.cpp and kreadconfig.cpp.
use super::{configuration, empty, invalid, SessionContext};
use crate::{
    audit::Reason,
    observation::{Quality, ScreenLock},
    platform::{
        command::{CommandRunner, ProbeError},
        linux::baseline::{
            files::{Files, Node, NodeKind},
            guarded,
        },
    },
};
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    path::{Component, Path, PathBuf},
};

const SCHEMA: &str = "/usr/share/config.kcfg/kscreenlockersettings.kcfg";
const LIMIT: usize = 64 * 1024;
const KEYS: [&str; 6] = [
    "Autolock",
    "Timeout",
    "Lock",
    "LockGrace",
    "RequirePassword",
    "LockOnResume",
];

#[derive(Debug)]
struct Source {
    path: String,
    role: &'static str,
    search_index: usize,
}
#[derive(Debug, PartialEq)]
struct Snapshot {
    metadata: Option<Node>,
    // Private temporary bytes only. Never serialized or reported, including hashes.
    bytes: Option<Vec<u8>>,
}
fn path(value: &str) -> Result<String, ProbeError> {
    if value.is_empty()
        || !Path::new(value).is_absolute()
        || value.chars().any(char::is_control)
        || Path::new(value)
            .components()
            .any(|c| c == Component::ParentDir)
    {
        return Err(invalid("Invalid current-user KConfig search path"));
    }
    let normalized: PathBuf = Path::new(value).components().collect();
    Ok(normalized.to_string_lossy().into_owned())
}
fn layout(user: &SessionContext) -> Result<(BTreeMap<String, String>, Vec<Source>), ProbeError> {
    let home = path(
        user.home
            .as_deref()
            .ok_or_else(|| invalid("Current-user HOME unavailable"))?,
    )?;
    let config = path(
        user.config_home
            .as_deref()
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("{home}/.config"))
            .as_str(),
    )?;
    let dirs = user
        .config_dirs
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or("/etc/xdg");
    let split: Vec<_> = dirs.split(':').collect();
    if split.len() > 8 {
        return Err(invalid("Too many XDG configuration directories"));
    }
    // Reject relative/empty components rather than silently guessing their scope.
    let mut system = Vec::new();
    for d in split {
        let d = path(d)?;
        if !system.contains(&d) {
            system.push(d);
        }
    }
    let mut locations = vec![config.clone()];
    for d in &system {
        if !locations.contains(d) {
            locations.push(d.clone());
        }
    }
    let mut sources = Vec::new();
    for (index, directory) in locations.iter().enumerate() {
        for (name, role) in [
            ("kscreenlockerrc", "APPLICATION"),
            ("kdeglobals", "GLOBAL"),
            ("system.kdeglobals", "SYSTEM_GLOBAL"),
        ] {
            sources.push(Source {
                path: format!("{directory}/{name}"),
                role,
                search_index: index,
            });
        }
    }
    // KConfig6 on Linux uses this fixed legacy system RC even though its name contains '5'.
    sources.push(Source {
        path: "/etc/kde5rc".into(),
        role: "SYSTEM_RC",
        search_index: 0,
    });
    sources.push(Source {
        path: SCHEMA.into(),
        role: "INSTALLED_SCHEMA",
        search_index: 0,
    });
    Ok((
        BTreeMap::from([
            ("HOME".into(), home),
            ("XDG_CONFIG_HOME".into(), config),
            ("XDG_CONFIG_DIRS".into(), system.join(":")),
        ]),
        sources,
    ))
}
fn snapshot(files: &dyn Files, sources: &[Source], uid: u32) -> Result<Vec<Snapshot>, ProbeError> {
    sources
        .iter()
        .map(|source| {
            let metadata = files.info(&source.path)?;
            if metadata.as_ref().is_some_and(|n| {
                n.kind != NodeKind::Regular || !n.readable || (n.owner != 0 && n.owner != uid)
            }) {
                return Err(ProbeError::new(
                    Reason::PermissionDenied,
                    "KConfig candidate source is inaccessible, nonregular or belongs to another user",
                ));
            }
            let bytes = files.read(&source.path, LIMIT)?;
            if metadata.is_some() != bytes.is_some() {
                return Err(invalid("KConfig candidate source changed during its snapshot"));
            }
            // Detect creation/removal/retarget/observable mutation during the bounded read too.
            if files.info(&source.path)? != metadata {
                return Err(invalid("KConfig candidate source changed during its snapshot"));
            }
            Ok(Snapshot { metadata, bytes })
        })
        .collect()
}
fn schema_default(schema: &str, key: &str) -> Result<String, ProbeError> {
    let marker = format!("key=\"{key}\"");
    let mut splits = schema.split(&marker);
    splits.next();
    let tail = splits
        .next()
        .ok_or_else(|| invalid("Unsupported installed screen-lock schema"))?;
    if splits.next().is_some() {
        return Err(invalid("Ambiguous KConfig schema key"));
    }
    let entry = tail
        .split_once("</entry>")
        .ok_or_else(|| invalid("Invalid schema entry"))?
        .0;
    let value = entry
        .split_once("<default>")
        .and_then(|(_, s)| s.split_once("</default>"))
        .map(|(v, _)| v.trim())
        .ok_or_else(|| invalid("Schema default unavailable"))?;
    if value.len() > 32 || value.contains(['<', '>', '&']) {
        return Err(invalid("Unsupported schema default"));
    }
    Ok(value.into())
}
pub(super) fn collect(
    files: &dyn Files,
    runner: &dyn CommandRunner,
    user: &SessionContext,
    active: bool,
    provenance: &mut Value,
) -> Result<(ScreenLock, &'static str), ProbeError> {
    let (environment, sources) = layout(user)?;
    if !matches!(files.info(&environment["HOME"])?,Some(n) if n.kind==NodeKind::Directory&&n.owner==user.uid)
    {
        return Err(ProbeError::new(
            Reason::PermissionDenied,
            "HOME is not an established directory owned by the selected session user",
        ));
    }
    *provenance = json!({
        "resolutionProfile":"LINUX_QT6_KCONFIG6_STANDARD_LOCATIONS",
        "sourceSetEstablished":false,"consistency":"NOT_ESTABLISHED",
        "atomicSnapshot":false,"runtimeAppliedVerified":false,"perKeyOriginVerified":false,
        "precedenceAndImmutability":"DELEGATED_TO_KCONFIG",
        "sources":sources.iter().map(|s|json!({"role":s.role,"searchIndex":s.search_index})).collect::<Vec<_>>(),
    });
    let before = snapshot(files, &sources, user.uid)?;
    provenance["sourceSetEstablished"] = json!(true);
    provenance["sources"] = json!(sources
        .iter()
        .zip(&before)
        .map(|(s, b)| json!({
            "role":s.role,"searchIndex":s.search_index,"present":b.metadata.is_some()
        }))
        .collect::<Vec<_>>());
    let Some(schema) = before.last().and_then(|s| s.bytes.as_deref()) else {
        return Ok((
            empty(Quality::Missing),
            "Installed Plasma 6 screen-lock schema unavailable; defaults are not invented",
        ));
    };
    let schema = std::str::from_utf8(schema).map_err(|_| invalid("Invalid UTF8 KConfig schema"))?;
    let mut values = BTreeMap::new();
    for key in KEYS {
        let default = schema_default(schema, key)?;
        let mut spec = guarded(
            "/usr/bin/kreadconfig6",
            &[
                "--file",
                "kscreenlockerrc",
                "--include-globals",
                "--group",
                "Daemon",
                "--key",
                key,
                "--default",
                &default,
            ],
        );
        spec.config_environment = environment.clone();
        let output = runner.run(&spec)?;
        if output.code != Some(0) || !output.stderr.trim().is_empty() {
            return Err(ProbeError::new(Reason::ExecutionFailed,"Read-only KConfig lookup failed; no fallback on inaccessible/unsupported resolution"));
        }
        values.insert(key.to_owned(), output.stdout.trim().to_owned());
    }
    let mut facts = configuration(&values, active)?;
    let after = snapshot(files, &sources, user.uid)?;
    if before != after {
        facts.quality = Quality::Inconclusive;
        provenance["consistency"] = json!("CHANGED");
        return Ok((
            facts,
            "KConfig candidate sources changed during observation; no stable configuration verdict",
        ));
    }
    provenance["consistency"] = json!("UNCHANGED_BOUNDED_SNAPSHOTS");
    Ok((facts,"Plasma 6 configuration observed through KConfig precedence/immutability; source snapshots unchanged within standard Linux resolution profile, not an atomic or runtime guarantee"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::{command::SystemRunner, linux::baseline::files::SystemFiles};

    /// Optional component validation, not a host/session compliance smoke.
    /// Default workspace tests use deterministic mocks without requiring KDE.
    #[test]
    #[ignore = "explicit optional test: installed kreadconfig6, Landlock, schema and no /etc/kde5rc required"]
    fn native_kconfig_fixture_precedence_defaults_and_immutability() {
        use std::{
            fs,
            time::{SystemTime, UNIX_EPOCH},
        };
        assert!(fs::symlink_metadata("/etc/kde5rc").is_err_and(|e| e.kind()==std::io::ErrorKind::NotFound),
            "Native fixture requires absent system RC to isolate all non-fixture defaults; do not change the host RC");
        let directory = std::env::temp_dir().join(format!(
            "baradwatchu-kconfig-fixture-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&directory).unwrap();
        struct Owned(std::path::PathBuf);
        impl Drop for Owned {
            fn drop(&mut self) {
                std::fs::remove_dir_all(&self.0).unwrap();
            }
        }
        let _cleanup = Owned(directory.clone());
        let config = directory.join("user config");
        let system = directory.join("system config");
        fs::create_dir(&config).unwrap();
        fs::create_dir(&system).unwrap();
        // The execution sandbox can expose host files with an unmapped UID. Use an
        // owned copy of the installed schema as fixture data, without relaxing the
        // collector's production ownership checks or changing the host schema.
        let schema = fs::read_to_string(SCHEMA).unwrap();
        let schema_copy = directory.join("fixture.kcfg");
        fs::write(&schema_copy, &schema).unwrap();
        struct FixtureFiles(String);
        impl FixtureFiles {
            fn resolve<'a>(&'a self, path: &'a str) -> &'a str {
                if path == SCHEMA {
                    &self.0
                } else {
                    path
                }
            }
        }
        impl Files for FixtureFiles {
            fn read(&self, path: &str, limit: usize) -> Result<Option<Vec<u8>>, ProbeError> {
                SystemFiles.read(self.resolve(path), limit)
            }
            fn info(&self, path: &str) -> Result<Option<Node>, ProbeError> {
                SystemFiles.info(self.resolve(path))
            }
            fn entries(&self, path: &str) -> Result<Option<Vec<String>>, ProbeError> {
                SystemFiles.entries(self.resolve(path))
            }
        }
        let files = FixtureFiles(schema_copy.to_string_lossy().into_owned());
        let user = SessionContext {
            // SAFETY: read-only caller identity; no arguments or process mutation.
            uid: unsafe { libc::geteuid() },
            home: Some(directory.to_string_lossy().into_owned()),
            config_home: Some(config.to_string_lossy().into_owned()),
            config_dirs: Some(system.to_string_lossy().into_owned()),
            kde_version: Some("6".into()),
        };
        let run = || {
            let mut e = json!({});
            let (f, _) = collect(&files, &SystemRunner, &user, false, &mut e).unwrap();
            assert_eq!(f.quality, Quality::Verified);
            assert_eq!(e["consistency"], "UNCHANGED_BOUNDED_SNAPSHOTS");
            f
        };
        // Defaults come from the installed schema; the tool must not invent zero grace.
        let defaults = run();
        let grace: u32 = schema_default(&schema, "LockGrace")
            .unwrap()
            .parse()
            .unwrap();
        assert_eq!(defaults.grace_seconds, Some(grace));
        fs::write(
            system.join("system.kdeglobals"),
            "[Daemon]\nTimeout=4\nLockGrace=0\n",
        )
        .unwrap();
        assert_eq!(run().idle_timeout_seconds, Some(240));
        assert_eq!(run().grace_seconds, Some(0));
        fs::write(
            config.join("kscreenlockerrc"),
            "[Daemon]\nTimeout=3\nLockGrace=5\n",
        )
        .unwrap();
        assert_eq!(run().idle_timeout_seconds, Some(180));
        // Immutable key, group and whole-file global policy must override the user's 3 minutes.
        for content in [
            "[Daemon]\nTimeout[$i]=2\nLockGrace=0\n",
            "[Daemon][$i]\nTimeout=2\nLockGrace=0\n",
            "[$i]\n[Daemon]\nTimeout=2\nLockGrace=0\n",
        ] {
            fs::write(system.join("system.kdeglobals"), content).unwrap();
            assert_eq!(run().idle_timeout_seconds, Some(120));
        }
    }
}
