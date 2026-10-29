use super::{failure, unsuccessful};
use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    platform::command::{CommandRunner, CommandSpec},
};
use serde_json::json;

// /dev/null is deliberately not a directory: no persistent log/state can be created.
// DNF5 falls back to its null logger when the log directory is unwritable.
const ARGS: &[&str] = &[
    "--cacheonly",
    "--no-plugins",
    "--skip-file-locks",
    "--color=never",
    "--setopt=logdir=/dev/null",
    "--setopt=build_cache=False",
    "--setopt=*.build_cache=False",
    "--setopt=*.skip_if_unavailable=False",
    "check-upgrade",
];

pub fn updates(runner: &dyn CommandRunner) -> Outcome {
    let source =
        "/usr/bin/dnf5 --cacheonly check-upgrade (plugins/log/state/cache writes disabled)";
    let mut command = CommandSpec::new("/usr/bin/dnf5", ARGS);
    command.read_only_filesystem = true;
    let output = match runner.run(&command) {
        Ok(output) => output,
        Err(error) => {
            return failure(
                error,
                source,
                "cached RPM update availability; not cache freshness",
            )
        }
    };
    let stderr = output.stderr.to_ascii_lowercase();
    let stdout = output.stdout.to_ascii_lowercase();
    let (status, reason, message) = match output.code {
        Some(100) => (Status::Fail, Reason::UpdatesAvailable, "DNF5 reports pending updates in existing repository metadata; no packages changed"),
        Some(0) if stdout.contains("no enabled repositories") || stderr.contains("no enabled repositories") =>
            (Status::Warn, Reason::NoEnabledRepositories, "No enabled repositories; update coverage cannot be established"),
        Some(0) => (Status::Warn, Reason::NoCachedUpdates, "DNF5 found no updates in the available cache; freshness and repository coverage are unverified, so this is not PASS"),
        _ if stderr.contains("permission denied") || stderr.contains("operation not permitted") || stderr.contains("superuser") =>
            return unsuccessful(&output, source, "cached RPM update availability"),
        _ if stderr.contains("cache") && (stderr.contains("missing") || stderr.contains("not found") || stderr.contains("no cache") || stderr.contains("cache-only enabled") || stderr.contains("cacheonly enabled")) =>
            (Status::Warn, Reason::CacheUnavailable, "Existing repository metadata is unavailable; no network refresh was attempted"),
        _ => return unsuccessful(&output, source, "cached RPM update availability"),
    };
    Outcome::new(status, reason, message).with_evidence(Evidence::new(
        source,
        "cached RPM updates only",
        &[
            ("exitCode", json!(output.code)),
            ("cacheOnly", json!(true)),
            ("cacheFreshnessVerified", json!(false)),
            ("pluginsEnabled", json!(false)),
            ("systemRepositoryLock", json!(false)),
            (
                "filesystemGuard",
                json!("Linux Landlock ABI >=3; filesystem writes denied"),
            ),
            ("privileges", json!("caller; no elevation")),
        ],
    ))
}
