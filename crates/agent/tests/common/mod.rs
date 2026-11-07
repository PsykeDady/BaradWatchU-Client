#![allow(dead_code)]
use baradwatchu_agent::{
    audit::{Clock, OperatingSystem, Outcome},
    observation::*,
    platform::{
        command::{CommandOutput, CommandRunner, CommandSpec, ProbeError},
        AuditPlatform,
    },
};
use std::{
    cell::RefCell,
    collections::{BTreeMap, VecDeque},
};

pub const NOW: u64 = 1_800_000_000;
pub struct FixedClock;
impl Clock for FixedClock {
    fn now_unix_ms(&self) -> Result<u64, String> {
        Ok(NOW * 1000)
    }
}
pub struct FakePlatform {
    pub os: OperatingSystem,
    pub updates: Outcome,
    pub root: Outcome,
    pub calls: RefCell<Vec<&'static str>>,
}
impl AuditPlatform for FakePlatform {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        self.calls.borrow_mut().push("os");
        Ok(self.os.clone())
    }
    fn pending_updates(&self) -> Outcome {
        self.calls.borrow_mut().push("updates");
        self.updates.clone()
    }
    fn root_encryption(&self) -> Outcome {
        self.calls.borrow_mut().push("root");
        self.root.clone()
    }
}
pub fn fresh_updates() -> Updates {
    Updates {
        classification: UpdateClass::NoPending,
        pending_packages: Some(0),
        security_advisories: Some(0),
        ordinary_pending: Some(false),
        classification_complete: true,
        metadata_state: MetadataState::Available,
        coverage_complete: true,
        repositories: vec![RepositoryMetadata {
            id: "updates".into(),
            timestamp_unix_seconds: Some(NOW - 100),
            expires_after_seconds: Some(86400),
        }],
    }
}
pub fn root() -> RootEncryption {
    RootEncryption {
        root_filesystem: "ext4".into(),
        root_device: "253:0".into(),
        topology_complete: true,
        paths: vec![BackingPath {
            devices: vec!["8:0".into(), "8:2".into(), "253:0".into()],
            luks_protected: true,
        }],
    }
}
pub fn platform() -> FakePlatform {
    use baradwatchu_agent::audit::{Reason, Status};
    let mut os = OperatingSystem::unidentified("linux");
    os.supported = true;
    os.distribution_id = Some("fedora".into());
    os.version_id = Some("43".into());
    FakePlatform {
        os,
        updates: Outcome::new(Status::Warn, Reason::NoCachedUpdates, "fixture")
            .with_observation(Observation::Updates(fresh_updates())),
        root: Outcome::new(Status::Pass, Reason::RootEncrypted, "fixture")
            .with_observation(Observation::RootEncryption(root())),
        calls: RefCell::new(vec![]),
    }
}
pub struct Runner {
    pub outputs: RefCell<VecDeque<CommandOutput>>,
    pub commands: RefCell<Vec<CommandSpec>>,
}
impl Runner {
    pub fn new(outputs: Vec<CommandOutput>) -> Self {
        Self {
            outputs: RefCell::new(outputs.into()),
            commands: RefCell::new(vec![]),
        }
    }
}
impl CommandRunner for Runner {
    fn run(&self, spec: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        self.commands.borrow_mut().push(spec.clone());
        Ok(self
            .outputs
            .borrow_mut()
            .pop_front()
            .expect("unexpected command"))
    }
}
pub fn out(code: i32, stdout: &str, stderr: &str) -> CommandOutput {
    CommandOutput {
        code: Some(code),
        stdout: stdout.into(),
        stderr: stderr.into(),
    }
}

#[cfg(target_os = "linux")]
#[derive(Default)]
pub struct Kernel(pub BTreeMap<String, baradwatchu_agent::platform::linux::topology::KernelDevice>);
#[cfg(target_os = "linux")]
impl Kernel {
    // Synthetic kernel oracle for legacy fixtures. Hardening tests independently alter
    // expected slave sets, mapping identity and visibility to test missing lsblk branches.
    pub fn fixture(json: &str) -> Self {
        fn walk(
            nodes: &serde_json::Value,
            parent: Option<&str>,
            map: &mut BTreeMap<String, baradwatchu_agent::platform::linux::topology::KernelDevice>,
        ) {
            if let Some(nodes) = nodes.as_array() {
                for node in nodes {
                    if let (Some(id), Some(kind)) =
                        (node["maj:min"].as_str(), node["type"].as_str())
                    {
                        let entry = map.entry(id.into()).or_insert_with(|| {
                            baradwatchu_agent::platform::linux::topology::KernelDevice {
                                parents: vec![],
                                kind: kind.into(),
                                luks_mapping: kind == "crypt",
                            }
                        });
                        if let Some(parent) = parent {
                            if !entry.parents.iter().any(|p| p == parent) {
                                entry.parents.push(parent.into());
                            }
                        }
                        walk(&node["children"], Some(id), map);
                    }
                }
            }
        }
        let mut map = BTreeMap::new();
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(json) {
            walk(&value["blockdevices"], None, &mut map);
        }
        Self(map)
    }
}
#[cfg(target_os = "linux")]
impl baradwatchu_agent::platform::linux::topology::KernelTopology for Kernel {
    fn inspect(
        &self,
        id: &str,
    ) -> Result<Option<baradwatchu_agent::platform::linux::topology::KernelDevice>, ProbeError>
    {
        Ok(self.0.get(id).cloned())
    }
}
