//! Policy-scoped Linux mount and swap observations. Never reads file contents.
use super::{
    environment::{Environment, Kind},
    storage,
    topology::KernelTopology,
};
use crate::{
    audit::{Evidence, Outcome, Reason, Status},
    observation::{CoverageItem, EncryptionCoverage, Observation, Protection, Quality},
    platform::command::CommandRunner,
    policy::SensitiveTarget,
};
use serde_json::json;
use std::{
    ffi::CString,
    fs,
    io::{BufRead, BufReader, Read},
    os::{
        fd::{AsRawFd, FromRawFd, OwnedFd},
        unix::{
            ffi::OsStrExt,
            fs::{FileTypeExt, MetadataExt},
        },
    },
    path::{Component, Path},
};

#[derive(Clone, Debug, PartialEq, Eq)]
struct Mount {
    id: u64,
    device: String,
    target: String,
    fstype: String,
    passthrough: bool,
}

fn unescape(value: &str) -> Option<String> {
    let b = value.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\' {
            if i + 3 >= b.len() || !b[i + 1..i + 4].iter().all(|c| (b'0'..=b'7').contains(c)) {
                return None;
            }
            let n = u16::from(b[i + 1] - b'0') * 64
                + u16::from(b[i + 2] - b'0') * 8
                + u16::from(b[i + 3] - b'0');
            if n == 0 || n > 255 {
                return None;
            }
            out.push(n as u8);
            i += 4;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

fn parse_mounts(mut reader: impl BufRead) -> Option<Vec<Mount>> {
    let mut mounts = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut total = 0usize;
    loop {
        let mut line = String::new();
        let bytes = reader.read_line(&mut line).ok()?;
        if bytes == 0 {
            break;
        }
        total = total.checked_add(bytes)?;
        if total > 4 * 1024 * 1024 || bytes > 65536 || !line.ends_with('\n') {
            return None;
        }
        let (left, right) = line.split_once(" - ")?;
        let fields: Vec<_> = left.split_ascii_whitespace().collect();
        let rest: Vec<_> = right.split_ascii_whitespace().collect();
        if fields.len() < 6 || rest.len() < 3 || mounts.len() >= 16384 {
            return None;
        }
        let id = fields[0].parse::<u64>().ok()?;
        let target = unescape(fields[4])?;
        if !ids.insert(id)
            || !Path::new(&target).is_absolute()
            || !super::topology::valid_device(fields[2])
        {
            return None;
        }
        mounts.push(Mount {
            id,
            device: fields[2].into(),
            target,
            fstype: rest[0].to_owned(),
            passthrough: fields[5]
                .split(',')
                .chain(rest[2].split(','))
                .any(|v| v == "ecryptfs_passthrough"),
        });
    }
    Some(mounts)
}
fn read_mounts() -> Option<Vec<Mount>> {
    let file = fs::File::open("/proc/self/mountinfo").ok()?;
    parse_mounts(BufReader::new(file.take(4 * 1024 * 1024 + 1)))
}

fn bounded(path: &str, limit: u64) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes).ok()?;
    if bytes.len() as u64 > limit {
        return None;
    }
    String::from_utf8(bytes).ok()
}

/// Open each policy-authorized path component as an O_PATH handle, rejecting
/// symlinks even in parents. This never opens the target for reading.
fn open_path(path: &str) -> Option<(OwnedFd, bool)> {
    let p = Path::new(path);
    if !p.is_absolute()
        || p.components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return None;
    }
    let root = unsafe {
        libc::open(
            c"/".as_ptr(),
            libc::O_PATH | libc::O_CLOEXEC | libc::O_DIRECTORY,
        )
    };
    if root < 0 {
        return None;
    }
    let mut fd = unsafe { OwnedFd::from_raw_fd(root) };
    for component in p.components() {
        let Component::Normal(name) = component else {
            continue;
        };
        let name = CString::new(name.as_bytes()).ok()?;
        let next = unsafe {
            libc::openat(
                fd.as_raw_fd(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if next < 0 {
            return None;
        }
        let next = unsafe { OwnedFd::from_raw_fd(next) };
        let mut st: libc::stat = unsafe { std::mem::zeroed() };
        if unsafe { libc::fstat(next.as_raw_fd(), &mut st) } != 0
            || st.st_mode & libc::S_IFMT == libc::S_IFLNK
        {
            return None;
        }
        fd = next;
    }
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return None;
    }
    Some((fd, st.st_mode & libc::S_IFMT == libc::S_IFDIR))
}

fn mount_id(fd: &OwnedFd) -> Option<u64> {
    let text = bounded(&format!("/proc/self/fdinfo/{}", fd.as_raw_fd()), 8192)?;
    text.lines().find_map(|l| {
        l.strip_prefix("mnt_id:")
            .and_then(|v| v.trim().parse().ok())
    })
}
fn identity(fd: &OwnedFd) -> Option<(u64, u64)> {
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::fstat(fd.as_raw_fd(), &mut st) } != 0 {
        return None;
    }
    Some((st.st_dev, st.st_ino))
}
fn inode_encrypted(fd: &OwnedFd) -> Option<bool> {
    // statx reports the kernel inode encryption attribute without opening or
    // reading file contents. Unsupported masks are unknown, not plaintext.
    const ENCRYPTED: u64 = 0x800;
    let mut st: libc::statx = unsafe { std::mem::zeroed() };
    let rc = unsafe {
        libc::statx(
            fd.as_raw_fd(),
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            libc::STATX_BASIC_STATS,
            &mut st,
        )
    };
    if rc != 0 || st.stx_attributes_mask & ENCRYPTED == 0 {
        return None;
    }
    Some(st.stx_attributes & ENCRYPTED != 0)
}

fn blank(id: &str) -> CoverageItem {
    CoverageItem {
        id: id.into(),
        protection: Protection::Inconclusive,
        technology: None,
        mounted: None,
        at_rest: None,
        source: None,
    }
}

fn selected_mount<'a>(
    mounts: &'a [Mount],
    mid: u64,
    path: &str,
    directory: bool,
) -> Option<&'a Mount> {
    let mount = mounts.iter().find(|m| m.id == mid)?;
    if !Path::new(path).starts_with(&mount.target) {
        return None;
    }
    if directory
        && mounts.iter().any(|m| {
            m.id != mid
                && Path::new(&m.target).starts_with(path)
                && (!matches!(m.fstype.as_str(), "ecryptfs" | "fuse.cryfs") || m.passthrough)
        })
    {
        return None;
    }
    Some(mount)
}

fn classify_mount(
    id: &str,
    mount: &Mount,
    backing: Option<&crate::observation::RootEncryption>,
    inode_encrypted: Option<bool>,
) -> CoverageItem {
    let mut result = blank(id);
    result.mounted = Some(true);
    result.source = Some("KERNEL_MOUNT_IDENTITY".into());
    match mount.fstype.as_str() {
        "ecryptfs" if !mount.passthrough => {
            result.technology = Some("ECRYPTFS".into());
            result.protection = Protection::Protected;
            result.at_rest = Some(true);
        }
        "fuse.cryfs" => {
            result.technology = Some("CRYFS".into());
            result.protection = Protection::Protected;
            result.at_rest = Some(true);
        }
        "ext2" | "ext3" | "ext4" | "xfs" | "f2fs" => {
            result.source = Some("KERNEL_MOUNT_AND_BLOCK_TOPOLOGY".into());
            if let Some(facts) = backing {
                if facts.topology_complete
                    && facts.root_device == mount.device
                    && facts.root_filesystem == mount.fstype
                    && !facts.paths.is_empty()
                {
                    if facts.paths.iter().all(|p| p.luks_protected) {
                        result.technology = Some("LUKS".into());
                        result.protection = Protection::Protected;
                        result.at_rest = Some(true);
                    } else if facts.paths.iter().any(|p| !p.luks_protected)
                        && inode_encrypted == Some(false)
                    {
                        result.technology = Some("PLAINTEXT_BACKING".into());
                        result.protection = Protection::Unprotected;
                    }
                }
            }
        }
        _ => {}
    }
    result
}

fn mount_item(
    id: &str,
    path: &str,
    runner: &dyn CommandRunner,
    kernel: &dyn KernelTopology,
    env: &Environment,
) -> CoverageItem {
    let result = blank(id);
    let Some(mounts) = read_mounts() else {
        return result;
    };
    let Some((fd, directory)) = open_path(path) else {
        return result;
    };
    let Some(initial_identity) = identity(&fd) else {
        return result;
    };
    let Some(mid) = mount_id(&fd) else {
        return result;
    };
    let Some(mount) = selected_mount(&mounts, mid, path, directory) else {
        return result;
    };
    let backing = match mount.fstype.as_str() {
        "ext2" | "ext3" | "ext4" | "xfs" | "f2fs" => {
            let observed = storage::encryption_at_mount(runner, kernel, env, &mount.target);
            if let Some(Observation::RootEncryption(facts)) = observed.observation {
                Some(facts)
            } else {
                None
            }
        }
        _ => None,
    };
    let result = classify_mount(id, mount, backing.as_ref(), inode_encrypted(&fd));
    let reopened = open_path(path);
    if read_mounts().as_ref() != Some(&mounts)
        || mount_id(&fd) != Some(mid)
        || reopened.as_ref().and_then(|(fd, _)| identity(fd)) != Some(initial_identity)
        || reopened.as_ref().and_then(|(fd, _)| mount_id(fd)) != Some(mid)
    {
        return blank(id);
    }
    result
}

fn outcome(items: Vec<CoverageItem>, scope: &str) -> Outcome {
    let inconclusive = items
        .iter()
        .any(|i| i.protection == Protection::Inconclusive);
    let negative = items
        .iter()
        .any(|i| i.protection == Protection::Unprotected);
    let na = !items.is_empty()
        && items
            .iter()
            .all(|i| i.protection == Protection::NotApplicable);
    let (status, reason, quality) = if negative {
        (
            Status::Fail,
            Reason::SecurityStateObserved,
            if inconclusive {
                Quality::Inconclusive
            } else {
                Quality::Verified
            },
        )
    } else if items.is_empty() || inconclusive {
        (
            Status::Warn,
            Reason::EvidenceInconclusive,
            Quality::Inconclusive,
        )
    } else if na {
        (
            Status::NotApplicable,
            Reason::EvidenceUnavailable,
            Quality::NotApplicable,
        )
    } else {
        (
            Status::Pass,
            Reason::SecurityStateObserved,
            Quality::Verified,
        )
    };
    let source = "bounded scope-specific kernel observations";
    Outcome::new(status, reason, format!("{scope}: mounted coverage and at-rest evidence are distinct; no file contents inspected"))
        .with_evidence(Evidence::new(source, "policy scope only; kernel observations, not encryption strength or atomic attestation", &[]))
        .with_observation(Observation::EncryptionCoverage(EncryptionCoverage { quality, items }))
}

/// Traverse kernel backing devices; swap can use plain dm-crypt without LUKS.
fn swap_block(device: &str, kernel: &dyn KernelTopology) -> (Protection, Option<String>) {
    fn walk(
        id: &str,
        kernel: &dyn KernelTopology,
        stack: &mut Vec<String>,
        crypt: bool,
        luks: bool,
        paths: &mut Vec<(bool, bool)>,
    ) -> bool {
        if stack.len() >= 64 || paths.len() >= 256 || stack.iter().any(|v| v == id) {
            return false;
        }
        let Ok(Some(node)) = kernel.inspect(id) else {
            return false;
        };
        if !matches!(node.kind.as_str(), "disk" | "part" | "lvm" | "crypt") {
            return false;
        }
        let encrypted = crypt || node.kind == "crypt";
        let with_luks = luks || node.luks_mapping;
        if node.kind == "disk" {
            if !node.parents.is_empty() {
                return false;
            }
            paths.push((encrypted, with_luks));
            return true;
        }
        if node.parents.is_empty() {
            return false;
        }
        stack.push(id.to_owned());
        let mut complete = true;
        for parent in &node.parents {
            complete &= walk(parent, kernel, stack, encrypted, with_luks, paths);
        }
        stack.pop();
        complete
    }
    let mut paths = Vec::new();
    if !walk(device, kernel, &mut Vec::new(), false, false, &mut paths) || paths.is_empty() {
        return (Protection::Inconclusive, None);
    }
    if paths.iter().all(|p| p.0) {
        let technology = if paths.iter().all(|p| p.1) {
            "LUKS"
        } else {
            "DM_CRYPT"
        };
        (Protection::Protected, Some(technology.into()))
    } else {
        (Protection::Unprotected, Some("PLAINTEXT_BACKING".into()))
    }
}

fn discovery_counts(
    mounts: &[Mount],
    kernel: &dyn KernelTopology,
) -> Option<(std::collections::BTreeMap<String, usize>, usize)> {
    let mut counts = std::collections::BTreeMap::<String, usize>::new();
    let mut unknown_backings = 0usize;
    let mut candidates = 0usize;
    for m in mounts {
        let technology = match m.fstype.as_str() {
            "ecryptfs" if !m.passthrough => Some("ECRYPTFS".to_owned()),
            "ecryptfs" => Some("ECRYPTFS_PASSTHROUGH".to_owned()),
            "fuse.cryfs" => Some("CRYFS".to_owned()),
            "ext2" | "ext3" | "ext4" | "xfs" | "f2fs" => {
                candidates += 1;
                if candidates > 256 {
                    return None;
                }
                let (state, technology) = swap_block(&m.device, kernel);
                if state == Protection::Inconclusive {
                    unknown_backings += 1;
                }
                if state == Protection::Protected {
                    technology
                } else {
                    None
                }
            }
            _ => None,
        };
        if let Some(technology) = technology {
            *counts.entry(technology).or_default() += 1;
        }
    }
    Some((counts, unknown_backings))
}

/// Inventory mount technology only. This never opens mount points or inspects
/// personal content, and the counts cannot satisfy any coverage policy.
pub fn discover(kernel: &dyn KernelTopology, env: &Environment) -> Outcome {
    if env.kind != Kind::NativeHost {
        return Outcome::new(
            Status::Warn,
            Reason::EvidenceInconclusive,
            "Mount discovery unavailable in non-native/unknown environment",
        );
    }
    let Some(mounts) = read_mounts() else {
        return Outcome::new(
            Status::Warn,
            Reason::EvidenceInconclusive,
            "Mount inventory unavailable",
        );
    };
    let Some((counts, unknown_backings)) = discovery_counts(&mounts, kernel) else {
        return Outcome::new(
            Status::Warn,
            Reason::EvidenceInconclusive,
            "Mount inventory exceeds inspection bound",
        );
    };
    if read_mounts().as_ref() != Some(&mounts) {
        return Outcome::new(
            Status::Warn,
            Reason::EvidenceInconclusive,
            "Mount inventory changed during observation",
        );
    }
    let (status, reason) = if unknown_backings == 0 {
        (Status::Pass, Reason::SecurityStateObserved)
    } else {
        (Status::Warn, Reason::EvidenceInconclusive)
    };
    Outcome::new(
        status,
        reason,
        "Discovery only: mount counts do not establish coverage or compliance",
    )
    .with_evidence(Evidence::new(
        "kernel mountinfo and sysfs metadata",
        "aggregate mount counts only; no paths, options, signatures or contents",
        &[
            ("technologyCounts", json!(counts)),
            ("unknownBlockBackings", json!(unknown_backings)),
            ("complianceAssessment", json!(false)),
        ],
    ))
}

fn current_home() -> Option<String> {
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let mut buffer = vec![0_u8; 16384];
    let rc = unsafe {
        libc::getpwuid_r(
            libc::geteuid(),
            &mut pwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() || pwd.pw_dir.is_null() {
        return None;
    }
    let value = unsafe { std::ffi::CStr::from_ptr(pwd.pw_dir) }
        .to_str()
        .ok()?
        .to_owned();
    if !Path::new(&value).is_absolute() {
        return None;
    }
    Some(value)
}

pub fn home(runner: &dyn CommandRunner, kernel: &dyn KernelTopology, env: &Environment) -> Outcome {
    let item = if env.kind == Kind::NativeHost {
        current_home()
            .map(|p| mount_item("home", &p, runner, kernel, env))
            .unwrap_or_else(|| blank("home"))
    } else {
        blank("home")
    };
    outcome(vec![item], "Current-user home")
}

fn sensitive_item(mut item: CoverageItem) -> CoverageItem {
    // Plaintext backing cannot establish whether a separate vault is locked.
    if item.protection == Protection::Unprotected {
        item.protection = Protection::Inconclusive;
    }
    item
}

pub fn sensitive(
    targets: &[SensitiveTarget],
    runner: &dyn CommandRunner,
    kernel: &dyn KernelTopology,
    env: &Environment,
) -> Outcome {
    let items = targets
        .iter()
        .map(|t| {
            if env.kind != Kind::NativeHost {
                return blank(&t.id);
            }
            let item = t
                .path
                .as_deref()
                .map(|p| mount_item(&t.id, p, runner, kernel, env))
                .unwrap_or_else(|| blank(&t.id));
            sensitive_item(item)
        })
        .collect();
    outcome(items, "Policy-authorized sensitive paths")
}

pub fn swap(runner: &dyn CommandRunner, kernel: &dyn KernelTopology, env: &Environment) -> Outcome {
    if env.kind != Kind::NativeHost {
        return outcome(vec![blank("swap")], "Active swap");
    }
    let Some(before) = bounded("/proc/swaps", 1024 * 1024) else {
        return outcome(vec![blank("swap")], "Active swap");
    };
    let mut lines = before.lines();
    if !lines.next().is_some_and(|h| {
        h.split_ascii_whitespace()
            .eq(["Filename", "Type", "Size", "Used", "Priority"])
    }) {
        return outcome(vec![blank("swap")], "Active swap");
    }
    let mut items = Vec::new();
    for (index, line) in lines.enumerate() {
        if index >= 256 {
            return outcome(vec![blank("swap")], "Active swap");
        }
        let parts: Vec<_> = line.split_ascii_whitespace().collect();
        let id = format!("swap-{index}");
        let mut item = blank(&id);
        if parts.len() != 5
            || parts[2].parse::<u64>().is_err()
            || parts[3].parse::<u64>().is_err()
            || parts[4].parse::<i32>().is_err()
        {
            return outcome(vec![blank("swap")], "Active swap");
        }
        if let Some(path) = unescape(parts[0]) {
            if let Ok(meta) = fs::metadata(&path) {
                if meta.file_type().is_block_device() && parts[1] == "partition" {
                    let rdev = meta.rdev();
                    let device = format!("{}:{}", libc::major(rdev), libc::minor(rdev));
                    let sys = format!("/sys/dev/block/{device}");
                    let zram = fs::canonicalize(&sys)
                        .ok()
                        .and_then(|p| p.file_name().map(|s| s.to_string_lossy().into_owned()))
                        .is_some_and(|s| {
                            s.strip_prefix("zram").is_some_and(|n| {
                                !n.is_empty() && n.bytes().all(|c| c.is_ascii_digit())
                            })
                        });
                    if zram {
                        item.source = Some("PROC_SWAPS_AND_ZRAM_SYSFS".into());
                        let backing = bounded(&format!("{sys}/backing_dev"), 4096);
                        match backing.as_deref().map(str::trim) {
                            Some("none")
                                if bounded(&format!("{sys}/backing_dev"), 4096) == backing =>
                            {
                                item.protection = Protection::Protected;
                                item.technology = Some("ZRAM_VOLATILE".into());
                                item.at_rest = Some(false);
                            }
                            _ => {
                                item.technology = Some("ZRAM_BACKING_UNKNOWN".into());
                            }
                        }
                    } else {
                        item.source = Some("PROC_SWAPS_AND_KERNEL_TOPOLOGY".into());
                        let first = swap_block(&device, kernel);
                        let (protection, technology) = if swap_block(&device, kernel) == first {
                            first
                        } else {
                            (Protection::Inconclusive, None)
                        };
                        item.protection = protection;
                        item.technology = technology;
                        item.at_rest = match protection {
                            Protection::Protected => Some(true),
                            Protection::Unprotected => Some(false),
                            _ => None,
                        };
                    }
                } else if meta.file_type().is_file() && parts[1] == "file" {
                    item = mount_item(&id, &path, runner, kernel, env);
                    if item.protection == Protection::Unprotected {
                        item.at_rest = Some(false);
                    }
                }
            }
        }
        items.push(item);
    }
    if bounded("/proc/swaps", 1024 * 1024).as_deref() != Some(before.as_str()) {
        return outcome(vec![blank("swap")], "Active swap");
    }
    if items.is_empty() {
        let mut i = blank("swap");
        i.protection = Protection::NotApplicable;
        i.technology = Some("NO_ACTIVE_SWAP".into());
        i.source = Some("PROC_SWAPS".into());
        items.push(i);
    }
    outcome(items, "Active swap")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        observation::{BackingPath, RootEncryption},
        platform::{command::ProbeError, linux::topology::KernelDevice},
    };
    use std::collections::BTreeMap;

    fn mount(id: u64, target: &str, fstype: &str, device: &str) -> Mount {
        Mount {
            id,
            target: target.into(),
            fstype: fstype.into(),
            device: device.into(),
            passthrough: false,
        }
    }
    fn backing(device: &str, protected: bool) -> RootEncryption {
        RootEncryption {
            root_filesystem: "ext4".into(),
            root_device: device.into(),
            topology_complete: true,
            paths: vec![BackingPath {
                devices: vec!["8:0".into(), device.into()],
                luks_protected: protected,
            }],
        }
    }
    struct Kernel(BTreeMap<String, KernelDevice>);
    impl KernelTopology for Kernel {
        fn inspect(&self, id: &str) -> Result<Option<KernelDevice>, ProbeError> {
            Ok(self.0.get(id).cloned())
        }
    }
    fn kernel(crypt: bool, luks: bool) -> Kernel {
        let mut map = BTreeMap::new();
        map.insert(
            "8:0".into(),
            KernelDevice {
                kind: "disk".into(),
                parents: vec![],
                luks_mapping: false,
            },
        );
        map.insert(
            "8:1".into(),
            KernelDevice {
                kind: "part".into(),
                parents: vec!["8:0".into()],
                luks_mapping: false,
            },
        );
        if crypt {
            map.insert(
                "253:0".into(),
                KernelDevice {
                    kind: "crypt".into(),
                    parents: vec!["8:1".into()],
                    luks_mapping: luks,
                },
            );
        }
        Kernel(map)
    }
    #[test]
    fn root_plain_and_home_ecryptfs_are_independent() {
        let root = classify_mount(
            "root",
            &mount(1, "/", "ext4", "8:1"),
            Some(&backing("8:1", false)),
            Some(false),
        );
        let home = classify_mount(
            "home",
            &mount(2, "/home/user", "ecryptfs", "0:42"),
            None,
            None,
        );
        assert_eq!(root.protection, Protection::Unprotected);
        assert_eq!(home.protection, Protection::Protected);
        assert_eq!(home.technology.as_deref(), Some("ECRYPTFS"));
    }
    #[test]
    fn discovery_counts_types_without_exporting_mount_paths_or_claiming_compliance() {
        let mounts = vec![
            mount(1, "/private/home", "ecryptfs", "0:42"),
            mount(2, "/private/vault", "fuse.cryfs", "0:43"),
            mount(3, "/private/luks", "ext4", "253:0"),
            mount(4, "/private/plain", "ext4", "8:1"),
        ];
        let (counts, unknown) = discovery_counts(&mounts, &kernel(true, true)).unwrap();
        assert_eq!(counts.get("ECRYPTFS"), Some(&1));
        assert_eq!(counts.get("CRYFS"), Some(&1));
        assert_eq!(counts.get("LUKS"), Some(&1));
        assert_eq!(unknown, 0);
        assert!(!format!("{counts:?}").contains("private"));
    }
    #[test]
    fn luks_backed_home_and_plain_home_are_distinct() {
        let home = mount(2, "/home", "ext4", "253:0");
        let luks = classify_mount("home", &home, Some(&backing("253:0", true)), Some(false));
        let plain = classify_mount("home", &home, Some(&backing("253:0", false)), Some(false));
        assert_eq!(luks.protection, Protection::Protected);
        assert_eq!(plain.protection, Protection::Unprotected);
        assert_eq!(plain.at_rest, None);
        assert_eq!(
            classify_mount("home", &home, Some(&backing("8:1", true)), Some(false)).protection,
            Protection::Inconclusive
        );
        assert_eq!(
            classify_mount("home", &home, Some(&backing("253:0", false)), None).protection,
            Protection::Inconclusive
        );
    }
    #[test]
    fn cryfs_must_cover_the_selected_path_and_nested_mounts() {
        let mounts = vec![
            mount(1, "/", "ext4", "8:1"),
            mount(2, "/vault", "fuse.cryfs", "0:50"),
        ];
        let selected = selected_mount(&mounts, 2, "/vault/data", true).unwrap();
        assert_eq!(
            classify_mount("vault", selected, None, None).protection,
            Protection::Protected
        );
        assert!(selected_mount(&mounts, 2, "/vault-other/data", true).is_none());
        assert!(selected_mount(&mounts, 1, "/", true).is_some());
        let mut with_plain_child = mounts.clone();
        with_plain_child.push(mount(3, "/vault/data/plain", "ext4", "8:2"));
        assert!(selected_mount(&with_plain_child, 2, "/vault/data", true).is_none());
        assert_eq!(
            classify_mount("vault", &mount(1, "/", "fuse", "0:50"), None, None).protection,
            Protection::Inconclusive
        );
    }
    #[test]
    fn installed_or_unmounted_cryfs_does_not_protect_an_unrelated_path() {
        // Package installation is not consulted; the selected mount is the only evidence.
        let mounts = vec![
            mount(1, "/", "ext4", "8:1"),
            mount(2, "/other-vault", "fuse.cryfs", "0:50"),
        ];
        let active = selected_mount(&mounts, 1, "/requested-vault", true).unwrap();
        let item = classify_mount("vault", active, Some(&backing("8:1", false)), Some(false));
        assert_eq!(item.protection, Protection::Unprotected);
        assert_eq!(item.technology.as_deref(), Some("PLAINTEXT_BACKING"));
        assert_eq!(item.at_rest, None); // a separate locked vault remains unknown
        assert_eq!(sensitive_item(item).protection, Protection::Inconclusive);
    }
    #[test]
    fn mountinfo_redacts_options_and_rejects_partial_or_unsafe_input() {
        let text = "10 1 0:42 / /home/user rw - ecryptfs ecryptfs rw,ecryptfs_sig=secret\n";
        let mounts = parse_mounts(text.as_bytes()).unwrap();
        assert!(!format!("{mounts:?}").contains("secret"));
        assert_eq!(mounts[0].target, "/home/user");
        assert!(parse_mounts(text.trim_end().as_bytes()).is_none());
        assert!(parse_mounts("1 1 0:1 / /bad\\000 rw - ext4 x rw\n".as_bytes()).is_none());
        let passthrough = "10 1 0:42 / /home/user rw - ecryptfs ecryptfs rw,ecryptfs_passthrough\n";
        let m = parse_mounts(passthrough.as_bytes()).unwrap();
        assert_eq!(
            classify_mount("home", &m[0], None, None).protection,
            Protection::Inconclusive
        );
    }
    #[test]
    fn swap_luks_plain_dmcrypt_plaintext_and_unknown() {
        assert_eq!(
            swap_block("253:0", &kernel(true, true)).0,
            Protection::Protected
        );
        let plain_dm = swap_block("253:0", &kernel(true, false));
        assert_eq!(plain_dm, (Protection::Protected, Some("DM_CRYPT".into())));
        assert_eq!(
            swap_block("8:1", &kernel(false, false)).0,
            Protection::Unprotected
        );
        assert_eq!(
            swap_block("missing", &kernel(false, false)).0,
            Protection::Inconclusive
        );
        let mut partial = kernel(true, true);
        partial
            .0
            .get_mut("253:0")
            .unwrap()
            .parents
            .push("missing".into());
        assert_eq!(swap_block("253:0", &partial).0, Protection::Inconclusive);
    }
    #[test]
    fn mixed_swap_does_not_let_zram_hide_plaintext() {
        let volatile = CoverageItem {
            id: "swap-0".into(),
            protection: Protection::Protected,
            technology: Some("ZRAM_VOLATILE".into()),
            mounted: None,
            at_rest: Some(false),
            source: Some("FIXTURE".into()),
        };
        let plain = CoverageItem {
            id: "swap-1".into(),
            protection: Protection::Unprotected,
            technology: Some("PLAINTEXT_BACKING".into()),
            mounted: None,
            at_rest: Some(false),
            source: Some("FIXTURE".into()),
        };
        assert_eq!(
            outcome(vec![volatile.clone()], "Active swap").status,
            Status::Pass
        );
        assert_eq!(
            outcome(vec![volatile, plain], "Active swap").status,
            Status::Fail
        );
        let mut no_swap = blank("swap");
        no_swap.protection = Protection::NotApplicable;
        no_swap.technology = Some("NO_ACTIVE_SWAP".into());
        assert_eq!(
            outcome(vec![no_swap], "Active swap").status,
            Status::NotApplicable
        );
    }
    #[test]
    fn path_opener_rejects_missing_and_symlink_components() {
        let dir = std::env::temp_dir().join(format!("baradwatchu-coverage-{}", std::process::id()));
        fs::create_dir(&dir).unwrap();
        std::os::unix::fs::symlink("/", dir.join("link")).unwrap();
        assert!(open_path(dir.join("missing").to_str().unwrap()).is_none());
        assert!(open_path(dir.join("link/etc").to_str().unwrap()).is_none());
        fs::remove_file(dir.join("link")).unwrap();
        fs::remove_dir(dir).unwrap();
    }
}
