use super::{
    environment::{Environment, Kind},
    topology::{valid_device, KernelTopology, SysfsTopology},
};
use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    observation::{BackingPath, Observation, RootEncryption},
    platform::{
        command::{CommandRunner, CommandSpec, ProbeError},
        probe::{failure, unsuccessful},
    },
};
use serde::Deserialize;
use serde_json::json;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Deserialize)]
struct Mounts {
    filesystems: Vec<Mount>,
}
#[derive(Deserialize)]
struct Mount {
    target: String,
    fstype: String,
    #[serde(rename = "maj:min")]
    device: String,
}
#[derive(Deserialize)]
struct Devices {
    blockdevices: Vec<Device>,
}
#[derive(Deserialize)]
struct Device {
    #[serde(rename = "maj:min")]
    device: String,
    #[serde(rename = "type")]
    kind: String,
    fstype: Option<String>,
    #[serde(default)]
    children: Vec<Device>,
}
#[derive(Default)]
struct Node {
    kind: String,
    fstype: Option<String>,
    parents: BTreeSet<String>,
}
fn index(
    nodes: &[Device],
    parent: Option<&str>,
    graph: &mut BTreeMap<String, Node>,
) -> Result<bool, ()> {
    let mut consistent = true;
    for node in nodes {
        if !valid_device(&node.device) || node.kind.is_empty() {
            return Err(());
        }
        let record = graph.entry(node.device.clone()).or_insert_with(|| Node {
            kind: node.kind.clone(),
            fstype: node.fstype.clone(),
            parents: BTreeSet::new(),
        });
        if record.kind != node.kind || record.fstype != node.fstype {
            consistent = false;
        }
        if let Some(parent) = parent {
            record.parents.insert(parent.to_owned());
        }
        consistent &= index(&node.children, Some(&node.device), graph)?;
    }
    Ok(consistent)
}
fn walk(
    id: &str,
    graph: &BTreeMap<String, Node>,
    stack: &mut Vec<String>,
    paths: &mut Vec<Vec<String>>,
) -> bool {
    if stack.len() >= 64 || paths.len() >= 1024 || stack.iter().any(|seen| seen == id) {
        return false;
    }
    let Some(node) = graph.get(id) else {
        return false;
    };
    stack.push(id.to_owned());
    let mut complete = true;
    if node.parents.is_empty() {
        let mut path = stack.clone();
        path.reverse();
        paths.push(path);
    } else {
        for parent in &node.parents {
            complete &= walk(parent, graph, stack, paths);
        }
    }
    stack.pop();
    complete
}

pub fn encryption(runner: &dyn CommandRunner) -> Outcome {
    encryption_with_topology(runner, &SysfsTopology)
}

pub fn encryption_with_topology(
    runner: &dyn CommandRunner,
    kernel: &dyn KernelTopology,
) -> Outcome {
    inspect_storage(runner, kernel, None, "/", false)
}

/// Native callers must supply an assessed execution environment. The low-level
/// topology API remains available for deterministic fixtures and CP2 compatibility.
pub fn encryption_in_environment(
    runner: &dyn CommandRunner,
    kernel: &dyn KernelTopology,
    environment: &Environment,
) -> Outcome {
    inspect_storage(runner, kernel, Some(environment), "/", false)
}

/// Reuse the root topology verifier for an already-identified mount point.
/// Callers must independently establish mount identity and discard root-labelled
/// evidence before reporting results for a different scope.
pub fn encryption_at_mount(
    runner: &dyn CommandRunner,
    kernel: &dyn KernelTopology,
    environment: &Environment,
    mount: &str,
) -> Outcome {
    inspect_storage(runner, kernel, Some(environment), mount, true)
}

fn inspect_storage(
    runner: &dyn CommandRunner,
    kernel: &dyn KernelTopology,
    environment: Option<&Environment>,
    mount_target: &str,
    guarded: bool,
) -> Outcome {
    let scope = "root filesystem / only; excludes separate home, boot, swap and external volumes";
    let source = "findmnt + lsblk ancestry cross-checked against kernel sysfs backing devices";
    let inspect = |program, args: &[&str]| -> Result<String, Box<Outcome>> {
        let mut command = CommandSpec::new(program, args);
        command.read_only_filesystem = guarded;
        match runner.run(&command) {
            Ok(output) if output.code == Some(0) => Ok(output.stdout),
            Ok(output) => Err(Box::new(unsuccessful(&output, program, scope))),
            Err(error) => Err(Box::new(failure(error, program, scope))),
        }
    };
    let mounts = match inspect(
        "/usr/bin/findmnt",
        &[
            "--json",
            "--target",
            mount_target,
            "--output",
            "TARGET,FSTYPE,MAJ:MIN",
        ],
    ) {
        Ok(text) => text,
        Err(outcome) => return *outcome,
    };
    let devices = match inspect(
        "/usr/bin/lsblk",
        &["--json", "--tree", "--output", "NAME,MAJ:MIN,TYPE,FSTYPE"],
    ) {
        Ok(text) => text,
        Err(outcome) => return *outcome,
    };
    let parse = || -> Result<(Mount, BTreeMap<String, Node>, bool), ()> {
        let devices: Devices = serde_json::from_str(&devices).map_err(|_| ())?;
        let mut mounts: Mounts = serde_json::from_str(&mounts).map_err(|_| ())?;
        if mounts.filesystems.len() != 1
            || mounts.filesystems[0].target != mount_target
            || !valid_device(&mounts.filesystems[0].device)
        {
            return Err(());
        }
        let mount = mounts.filesystems.remove(0);
        let mut graph = BTreeMap::new();
        let consistent = index(&devices.blockdevices, None, &mut graph)?;
        Ok((mount, graph, consistent))
    };
    let (root, graph, consistent) = match parse() {
        Ok(data) => data,
        Err(()) => {
            return failure(
                ProbeError::new(Reason::InvalidOutput, "Invalid filesystem/block JSON"),
                source,
                scope,
            )
        }
    };
    let mut paths = vec![];
    let found = walk(&root.device, &graph, &mut vec![], &mut paths);
    paths.sort();
    paths.dedup();
    let mut complete = found
        && consistent
        && !paths.is_empty()
        && matches!(
            root.fstype.as_str(),
            "ext2" | "ext3" | "ext4" | "xfs" | "f2fs"
        )
        && graph
            .get(&root.device)
            .is_some_and(|node| node.fstype.as_deref().map_or(true, |fs| fs == root.fstype));
    let ids: BTreeSet<_> = paths.iter().flatten().cloned().collect();
    let mut luks = BTreeSet::new();
    if complete {
        for id in ids {
            let node = &graph[&id];
            if !matches!(node.kind.as_str(), "disk" | "part" | "lvm" | "crypt") {
                complete = false;
                continue;
            }
            let info = match kernel.inspect(&id) {
                Ok(Some(info)) => info,
                Ok(None) => {
                    complete = false;
                    continue;
                }
                Err(error) => return failure(error, source, scope),
            };
            let parents: BTreeSet<_> = info.parents.into_iter().collect();
            if parents != node.parents || info.kind != node.kind {
                complete = false;
            }
            if node.kind == "crypt" {
                if info.luks_mapping {
                    luks.insert(id);
                } else {
                    complete = false;
                }
            }
        }
    }
    let mut observed = vec![];
    for path in paths {
        if path.first().map_or(true, |id| graph[id].kind != "disk") {
            complete = false;
        }
        let protected = path.windows(2).any(|pair| {
            graph[&pair[0]].fstype.as_deref() == Some("crypto_LUKS") && luks.contains(&pair[1])
        });
        if path.iter().any(|id| {
            graph[id].kind == "crypt" || graph[id].fstype.as_deref() == Some("crypto_LUKS")
        }) && !protected
        {
            complete = false;
        }
        observed.push(BackingPath {
            devices: path,
            luks_protected: protected,
        });
    }
    let encrypted = observed.iter().filter(|path| path.luks_protected).count();
    let kernel_verified = complete;
    if environment.is_some_and(|env| env.kind != Kind::NativeHost) {
        complete = false;
    }
    let (status, reason, message) = if !complete {
        (
            Status::Warn,
            Reason::EncryptionInconclusive,
            if environment.is_some_and(|env| env.kind != Kind::NativeHost) {
                "Execution environment does not establish trustworthy host root-storage scope"
            } else {
                "Root backing topology is incomplete, unsupported or differs from kernel evidence"
            },
        )
    } else if encrypted != observed.len() {
        (
            Status::Fail,
            Reason::RootUnencrypted,
            "A verified root backing path lacks LUKS block encryption",
        )
    } else {
        (Status::Pass,Reason::RootEncrypted,"All verified root backing paths have active kernel LUKS mappings backed by LUKS metadata")
    };
    let facts = RootEncryption {
        root_filesystem: root.fstype.clone(),
        root_device: root.device.clone(),
        topology_complete: complete,
        paths: observed,
    };
    let mut outcome = Outcome::new(status, reason, message)
        .with_evidence(Evidence::new(
            source,
            scope,
            &[
                ("rootFilesystem", json!(root.fstype)),
                ("rootDevice", json!(root.device)),
                ("rootBackingPaths", json!(facts.paths.len())),
                ("encryptedPaths", json!(encrypted)),
                ("kernelBackingVerified", json!(kernel_verified)),
                ("privileges", json!("caller; no elevation")),
            ],
        ))
        .with_observation(Observation::RootEncryption(facts));
    if let Some(env) = environment {
        outcome = outcome.with_evidence(Evidence::new(
            "Linux execution-environment assessment",
            "host root-storage visibility, not virtualization attestation",
            &[
                ("executionEnvironment", json!(env.kind)),
                ("environmentReason", json!(env.reason)),
                ("environmentProbeError", json!(env.probe_error)),
            ],
        ));
    }
    outcome
}
