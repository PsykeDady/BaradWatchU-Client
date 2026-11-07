//! Conservative execution context. Absence of markers alone never establishes a host.
use crate::{
    audit::Reason,
    platform::command::{CommandRunner, CommandSpec, ProbeError},
};
use serde::Serialize;
use std::{
    fs,
    io::{self, Read},
    path::Path,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Kind {
    NativeHost,
    Container,
    Unknown,
}
#[derive(Clone, Debug)]
pub struct Environment {
    pub kind: Kind,
    pub reason: &'static str,
    pub probe_error: Option<Reason>,
}
#[derive(Default)]
pub struct Signals {
    pub container_marker: bool,
    pub native_init: bool,
    pub initial_user_namespace: bool,
    pub same_root_context: bool,
}
pub trait SignalReader {
    fn read(&self) -> Result<Signals, ProbeError>;
}
pub struct SystemSignals;
fn read(path: &str) -> io::Result<String> {
    let mut text = String::new();
    fs::File::open(path)?.take(4097).read_to_string(&mut text)?;
    if text.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Oversized environment signal",
        ));
    }
    Ok(text)
}
fn exists(path: &str) -> io::Result<bool> {
    match fs::metadata(path) {
        Ok(_) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e),
    }
}
fn read_mountinfo(path: &str) -> io::Result<String> {
    let mut text = String::new();
    fs::File::open(path)?
        .take(262145)
        .read_to_string(&mut text)?;
    if text.len() > 262144 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Oversized mountinfo",
        ));
    }
    Ok(text)
}
fn same_mount_roots(a: &str, b: &str) -> bool {
    fn root(text: &str) -> Option<Vec<&str>> {
        let mut root = None;
        for line in text.lines() {
            let (mount, fs) = line.split_once(" - ")?;
            let columns: Vec<_> = mount.split_whitespace().collect();
            if columns.len() < 6 {
                return None;
            }
            if columns[4] == "/" {
                if root.is_some() || !super::topology::valid_device(columns[2]) {
                    return None;
                }
                root = Some(vec![
                    columns[0],
                    columns[1],
                    columns[2],
                    columns[3],
                    fs.split_whitespace().next()?,
                ]);
            }
        }
        root
    }
    match (root(a), root(b)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    }
}
impl SignalReader for SystemSignals {
    fn read(&self) -> Result<Signals, ProbeError> {
        use std::os::unix::fs::MetadataExt;
        let collect = || -> io::Result<Signals> {
            for marker in [
                "/run/systemd/container",
                "/run/host/container-manager",
                "/.dockerenv",
                "/run/.containerenv",
            ] {
                if exists(marker)? {
                    return Ok(Signals {
                        container_marker: true,
                        ..Signals::default()
                    });
                }
            }
            let init = read("/proc/1/comm")?;
            let uid_map = read("/proc/self/uid_map")?;
            let fields: Vec<_> = uid_map.split_whitespace().collect();
            let initial_user_namespace = fields == ["0", "0", "4294967295"];
            let same = |a: &str, b: &str| -> io::Result<bool> {
                let a = fs::metadata(Path::new(a))?;
                let b = fs::metadata(Path::new(b))?;
                Ok(a.dev() == b.dev() && a.ino() == b.ino())
            };
            Ok(Signals {
                container_marker: false,
                native_init: matches!(init.trim(), "systemd" | "init" | "openrc-init"),
                initial_user_namespace,
                same_root_context: match (|| -> io::Result<bool> {
                    Ok(same("/proc/1/ns/mnt", "/proc/self/ns/mnt")? && same("/proc/1/root", "/")?)
                })() {
                    Ok(same) => same,
                    // proc namespace/root symlinks commonly require ptrace access to
                    // root's PID1. Matching readable mountinfo supplies positive root
                    // context without asking the operator for extra privileges.
                    Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                        same_mount_roots(
                            &read_mountinfo("/proc/1/mountinfo")?,
                            &read_mountinfo("/proc/self/mountinfo")?,
                        )
                    }
                    Err(error) => return Err(error),
                },
            })
        };
        collect().map_err(ProbeError::io)
    }
}
pub fn detect(runner: &dyn CommandRunner, signals: &dyn SignalReader) -> Environment {
    let signals = signals.read();
    if signals.as_ref().is_ok_and(|s| s.container_marker) {
        return Environment {
            kind: Kind::Container,
            reason: "EXPLICIT_CONTAINER_MARKER",
            probe_error: None,
        };
    }
    let mut command = CommandSpec::new("/usr/bin/systemd-detect-virt", &["--container"]);
    command.read_only_filesystem = true;
    match runner.run(&command) {
        Ok(output)
            if output.code == Some(0)
                && output.stderr.trim().is_empty()
                && !output.stdout.trim().is_empty()
                && output.stdout.trim() != "none" =>
        {
            Environment {
                kind: Kind::Container,
                reason: "CONTAINER_DETECTOR_POSITIVE",
                probe_error: None,
            }
        }
        Ok(output)
            if output.code == Some(1)
                && output.stderr.trim().is_empty()
                && output.stdout.trim() == "none" =>
        {
            let native = signals
                .as_ref()
                .is_ok_and(|s| s.native_init && s.initial_user_namespace && s.same_root_context);
            Environment {
                kind: if native {
                    Kind::NativeHost
                } else {
                    Kind::Unknown
                },
                reason: if native {
                    "DETECTOR_NONE_WITH_NATIVE_INIT_AND_NAMESPACE_EVIDENCE"
                } else {
                    "NATIVE_HOST_CONTEXT_NOT_ESTABLISHED"
                },
                probe_error: signals.err().map(|e| e.reason),
            }
        }
        Ok(_) => Environment {
            kind: Kind::Unknown,
            reason: "ENVIRONMENT_DETECTOR_INCONCLUSIVE",
            probe_error: Some(Reason::ExecutionFailed),
        },
        Err(error) => Environment {
            kind: Kind::Unknown,
            reason: "ENVIRONMENT_DETECTOR_UNAVAILABLE",
            probe_error: Some(error.reason),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    const ROOT: &str = "20 1 8:2 / / rw - ext4 /dev/fixture rw\n";
    #[test]
    fn matching_mountinfo_can_supply_positive_root_context_without_ptrace_symlinks() {
        assert!(same_mount_roots(ROOT, ROOT));
        assert!(same_mount_roots(
            &(ROOT.to_owned() + "21 20 0:1 / /proc rw - proc proc rw\n"),
            ROOT
        ));
    }
    #[test]
    fn absent_ambiguous_or_mismatched_mount_roots_are_not_positive_context() {
        for other in [
            "".to_owned(),
            "garbage".to_owned(),
            ROOT.replace("20 1", "22 1"),
            ROOT.replace("8:2", "8:3"),
            ROOT.replace("ext4", "xfs"),
            ROOT.to_owned() + ROOT,
        ] {
            assert!(!same_mount_roots(ROOT, &other));
        }
    }
}
