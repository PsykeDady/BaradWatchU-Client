use super::{failure, unsuccessful};
use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    platform::command::{CommandRunner, CommandSpec, ProbeError},
};
use serde::Deserialize;
use serde_json::json;

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

fn paths<'a>(
    nodes: &'a [Device],
    root: &str,
    prefix: &mut Vec<&'a Device>,
    found: &mut Vec<Vec<&'a Device>>,
) {
    for node in nodes {
        prefix.push(node);
        if node.device == root {
            found.push(prefix.clone());
        }
        paths(&node.children, root, prefix, found);
        prefix.pop();
    }
}

fn device_id_valid(value: &str) -> bool {
    value.split_once(':').is_some_and(|(major, minor)| {
        !major.is_empty()
            && !minor.is_empty()
            && major.bytes().all(|v| v.is_ascii_digit())
            && minor.bytes().all(|v| v.is_ascii_digit())
            && major.parse::<u32>().is_ok()
            && minor.parse::<u32>().is_ok()
    })
}

fn devices_valid(nodes: &[Device]) -> bool {
    nodes.iter().all(|node| {
        device_id_valid(&node.device) && !node.kind.is_empty() && devices_valid(&node.children)
    })
}

pub fn encryption(runner: &dyn CommandRunner) -> Outcome {
    let scope =
        "root filesystem / only; excludes boot, home on other mounts, swap and external volumes";
    let source = "findmnt root identity + lsblk block ancestry (sysfs/udev metadata)";
    let inspect = |program, args: &[&str]| -> Result<String, Outcome> {
        match runner.run(&CommandSpec::new(program, args)) {
            Ok(output) if output.code == Some(0) => Ok(output.stdout),
            Ok(output) => Err(unsuccessful(&output, program, scope)),
            Err(error) => Err(failure(error, program, scope)),
        }
    };
    let mounts = match inspect(
        "/usr/bin/findmnt",
        &[
            "--json",
            "--target",
            "/",
            "--output",
            "TARGET,FSTYPE,MAJ:MIN",
        ],
    ) {
        Ok(text) => text,
        Err(outcome) => return outcome,
    };
    let devices = match inspect(
        "/usr/bin/lsblk",
        &["--json", "--tree", "--output", "NAME,MAJ:MIN,TYPE,FSTYPE"],
    ) {
        Ok(text) => text,
        Err(outcome) => return outcome,
    };
    let parse = || -> Result<(Mount, Devices), serde_json::Error> {
        let mut mounts: Mounts = serde_json::from_str(&mounts)?;
        let devices: Devices = serde_json::from_str(&devices)?;
        if !devices_valid(&devices.blockdevices)
            || mounts
                .filesystems
                .iter()
                .any(|mount| !device_id_valid(&mount.device))
        {
            return Err(serde::de::Error::custom("Invalid major:minor identifier"));
        }
        // Empty/multiple or non-root records do not establish the root filesystem.
        if mounts.filesystems.len() != 1 || mounts.filesystems[0].target != "/" {
            return Err(serde::de::Error::custom("Expected exactly the root mount"));
        }
        Ok((mounts.filesystems.remove(0), devices))
    };
    let (root, devices) = match parse() {
        Ok(data) => data,
        Err(_) => {
            return failure(
                ProbeError::new(
                    Reason::InvalidOutput,
                    "Invalid or incomplete filesystem/block-device JSON",
                ),
                source,
                scope,
            )
        }
    };
    let mut found = vec![];
    paths(&devices.blockdevices, &root.device, &mut vec![], &mut found);
    let mut encrypted = 0;
    let mut unencrypted = 0;
    let mut inconclusive = 0;
    for path in &found {
        let mut seen = std::collections::BTreeSet::new();
        let consistent = path.iter().all(|node| seen.insert(&node.device))
            && path.last().is_some_and(|node| {
                node.fstype
                    .as_deref()
                    .map_or(true, |fstype| fstype == root.fstype)
            });
        let simple = path.first().is_some_and(|node| node.kind == "disk")
            && consistent
            && path
                .iter()
                .all(|node| matches!(node.kind.as_str(), "disk" | "part" | "crypt" | "lvm"));
        if !simple {
            inconclusive += 1;
            continue;
        }
        if path
            .windows(2)
            .any(|pair| pair[0].fstype.as_deref() == Some("crypto_LUKS") && pair[1].kind == "crypt")
        {
            encrypted += 1;
        } else if path
            .iter()
            .any(|node| node.kind == "crypt" || node.fstype.as_deref() == Some("crypto_LUKS"))
        {
            inconclusive += 1;
        } else {
            unencrypted += 1;
        }
    }
    let interpretable = matches!(
        root.fstype.as_str(),
        "ext2" | "ext3" | "ext4" | "xfs" | "f2fs"
    );
    let (status, reason, message) = if !interpretable || found.is_empty() {
        (Status::Warn, Reason::EncryptionInconclusive, "Root storage coverage is inconclusive (e.g. Btrfs, overlay/network root, or unavailable block ancestry); no encryption assertion")
    } else if unencrypted > 0 {
        (
            Status::Fail,
            Reason::RootUnencrypted,
            "At least one observed root backing path has no block encryption layer",
        )
    } else if encrypted == found.len() && inconclusive == 0 {
        (Status::Pass, Reason::RootEncrypted, "Every observed root backing path contains an active dm-crypt mapping backed by LUKS metadata; scope is / only")
    } else {
        (Status::Warn, Reason::EncryptionInconclusive, "Root backing paths could not all be proven LUKS-encrypted; unsupported or incomplete topology")
    };
    Outcome::new(status, reason, message).with_evidence(Evidence::new(
        source,
        scope,
        &[
            ("rootFilesystem", json!(root.fstype)),
            ("rootDevice", json!(root.device)),
            ("rootBackingPaths", json!(found.len())),
            ("encryptedPaths", json!(encrypted)),
            ("unencryptedPaths", json!(unencrypted)),
            ("inconclusivePaths", json!(inconclusive)),
            ("privileges", json!("caller; no elevation")),
        ],
    ))
}
