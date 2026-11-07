//! Installation-owned registry and bridges to existing adapters. No remote registration.
pub mod external;
pub mod legacy;
use crate::{
    audit::{OperatingSystem, Outcome, Reason, Status},
    check_port::{Availability, CheckEvidence, CheckExecutor, ExecutionState},
    platform::{
        command::{ProbeError, SystemRunner},
        AuditPlatform,
    },
    policy::SensitiveTarget,
};
use std::{
    cell::{OnceCell, RefCell},
    io::Read,
    path::PathBuf,
    time::Duration,
};

pub enum Implementation {
    Native,
    EmbeddedCompatibility,
    External(external::ExternalSpec),
}
pub struct Registration {
    pub id: &'static str,
    pub platform: &'static str,
    pub implementation: Implementation,
    pub timeout: Duration,
}
pub fn registry() -> Vec<Registration> {
    crate::workstation::IDS
        .iter()
        .map(|&id| Registration {
            id,
            platform: "linux",
            timeout: Duration::from_secs(10),
            implementation: match id {
                "SEC-003" | "SEC-004" => Implementation::EmbeddedCompatibility,
                "SEC-011" => Implementation::External(external::ExternalSpec {
                    program: "/usr/bin/bash".into(),
                    args: vec![
                        "--noprofile".into(),
                        "--norc".into(),
                        external_file().to_string_lossy().into_owned(),
                    ],
                    timeout: Duration::from_secs(10),
                    output_limit: 8192,
                }),
                _ => Implementation::Native,
            },
        })
        .collect()
}
fn external_file() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| resource_path(&p))
        .unwrap_or_else(|| PathBuf::from("/unavailable/baradwatchu/SEC-011.sh"))
}
fn resource_path(executable: &std::path::Path) -> Option<PathBuf> {
    if !executable.is_absolute() {
        return None;
    }
    Some(
        executable
            .parent()?
            .parent()?
            .join("share/baradwatchu-client/checks/SEC-011.sh"),
    )
}

/// Validate the deployment trust boundary, not just the final file's bytes.
/// A user-owned copy trusts that user; it is not a system-wide installation.
#[cfg(unix)]
fn trusted_path(path: &std::path::Path, owner: u32, system_owner: u32) -> std::io::Result<()> {
    use std::os::unix::fs::MetadataExt;
    let denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    if !path.is_absolute() {
        return Err(denied());
    }
    let mut current = PathBuf::new();
    for component in path.components() {
        if matches!(
            component,
            std::path::Component::ParentDir | std::path::Component::CurDir
        ) {
            return Err(denied());
        }
        current.push(component);
        let m = std::fs::symlink_metadata(&current)?;
        if m.file_type().is_symlink() || (m.uid() != owner && m.uid() != system_owner) {
            return Err(denied());
        }
        // Trusted sticky directories (e.g. /tmp) protect the following owned
        // entry from other users. Ordinary writable directories do not.
        let sticky_directory = m.is_dir() && m.mode() & 0o1000 != 0;
        if m.mode() & 0o022 != 0 && !sticky_directory {
            return Err(denied());
        }
        if current != path && !m.is_dir() {
            return Err(denied());
        }
    }
    Ok(())
}
fn verify_artifact(executable: &std::path::Path, path: &std::path::Path) -> Result<(), ProbeError> {
    let expected = include_bytes!("../../../../scripts/adapters/SEC-011.sh");
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let owner = std::fs::metadata(executable).map_err(ProbeError::io)?.uid();
        // Use the namespace's root-directory owner (may be mapped in tests).
        let system_owner = std::fs::metadata("/").map_err(ProbeError::io)?.uid();
        trusted_path(executable, owner, system_owner).map_err(ProbeError::io)?;
        trusted_path(path, owner, system_owner).map_err(ProbeError::io)?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path).map_err(ProbeError::io)?;
    let m = file.metadata().map_err(ProbeError::io)?;
    if !m.is_file() || m.len() != expected.len() as u64 {
        return Err(ProbeError::new(
            Reason::InvalidOutput,
            "Adapter artifact differs from approved installation",
        ));
    }
    let mut bytes = Vec::new();
    file.take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(ProbeError::io)?;
    if bytes != expected {
        return Err(ProbeError::new(
            Reason::InvalidOutput,
            "Adapter artifact differs from approved installation",
        ));
    }
    Ok(())
}
pub fn descriptors() -> Vec<serde_json::Value> {
    registry().into_iter().map(|r|serde_json::json!({"id":r.id,"platform":r.platform,"type":match r.implementation {Implementation::Native=>"NATIVE",_=>"EXTERNAL"},"timeoutSeconds":if matches!(r.implementation,Implementation::Native) {None} else {Some(r.timeout.as_secs())}})).collect()
}
pub struct LocalExecutor<'a> {
    pub platform: &'a dyn AuditPlatform,
    pub targets: &'a [SensitiveTarget],
    aging: OnceCell<Outcome>,
}
impl<'a> LocalExecutor<'a> {
    pub fn new(platform: &'a dyn AuditPlatform, targets: &'a [SensitiveTarget]) -> Self {
        Self {
            platform,
            targets,
            aging: OnceCell::new(),
        }
    }
    pub fn native(&self, id: &str) -> CheckEvidence {
        let outcome = match id {
            "SEC-001" => self.platform.pending_updates(),
            "SEC-006" => self.platform.root_encryption(),
            "SEC-007" => self.platform.screen_lock(),
            "SEC-008" | "SEC-009" => self
                .aging
                .get_or_init(|| self.platform.password_aging())
                .clone(),
            "SEC-010" => self.platform.password_complexity(),
            "SEC-012" => self.platform.tpm(),
            "SEC-013" => self.platform.secure_boot(),
            "SEC-014" => self.platform.firewall(),
            "SEC-015" => self.platform.home_encryption(),
            "SEC-016" => self.platform.sensitive_encryption(self.targets),
            "SEC-017" => self.platform.swap_protection(),
            _ => {
                return external::unavailable(
                    ExecutionState::NotStarted,
                    Reason::UnsupportedPlatform,
                )
            }
        };
        from_legacy(outcome)
    }
}
pub fn from_legacy(outcome: Outcome) -> CheckEvidence {
    let availability = match outcome.status {
        Status::Error => Availability::Error,
        Status::NotApplicable => Availability::NotApplicable,
        Status::Warn => Availability::Unknown,
        _ => Availability::Available,
    };
    CheckEvidence {
        execution: ExecutionState::Completed,
        availability,
        outcome,
    }
}
impl CheckExecutor for LocalExecutor<'_> {
    fn execute(&self, id: &str) -> CheckEvidence {
        let Some(reg) = registry().into_iter().find(|r| r.id == id) else {
            return external::unavailable(ExecutionState::NotStarted, Reason::UnsupportedPlatform);
        };
        if reg.platform != std::env::consts::OS
            || !self.platform.operating_system().is_ok_and(|o| o.supported)
        {
            return external::unavailable(ExecutionState::NotStarted, Reason::UnsupportedPlatform);
        }
        match reg.implementation {
            Implementation::Native => self.native(id),
            Implementation::EmbeddedCompatibility => {
                from_legacy(legacy::native_script(self.platform, id))
            }
            Implementation::External(mut spec) => {
                spec.timeout = reg.timeout;
                #[cfg(target_os = "linux")]
                {
                    use crate::platform::linux::environment::{detect, Kind, SystemSignals};
                    if detect(&SystemRunner, &SystemSignals).kind != Kind::NativeHost {
                        return external::unavailable(
                            ExecutionState::NotStarted,
                            Reason::EvidenceUnavailable,
                        );
                    }
                }
                let path = std::path::Path::new(&spec.args[2]);
                let verification = std::env::current_exe()
                    .map_err(ProbeError::io)
                    .and_then(|exe| verify_artifact(&exe, path));
                if let Err(error) = verification {
                    return external::unavailable(
                        if error.reason == Reason::MissingTool {
                            ExecutionState::MissingExecutable
                        } else {
                            ExecutionState::NotStarted
                        },
                        error.reason,
                    );
                }
                external::execute(id, &spec, &SystemRunner)
            }
        }
    }
    fn implementation(&self, id: &str) -> &'static str {
        match id {
            "SEC-011" => "EXTERNAL",
            "SEC-003" | "SEC-004" => "EMBEDDED_BASH",
            _ => "NATIVE_RUST",
        }
    }
}
/// Compatibility adapter for existing callers/tests of workstation::audit.
pub struct LegacyExecutor<'a, F> {
    pub native: LocalExecutor<'a>,
    pub collect: RefCell<F>,
}
impl<F: FnMut(&str) -> Outcome> CheckExecutor for LegacyExecutor<'_, F> {
    fn execute(&self, id: &str) -> CheckEvidence {
        if matches!(id, "SEC-003" | "SEC-004" | "SEC-011") {
            from_legacy((self.collect.borrow_mut())(id))
        } else {
            self.native.native(id)
        }
    }
}

/// Compatibility bridge: old builtin collection invokes the universal port.
/// It has no knowledge of which implementations are native or subprocesses.
pub struct PortPlatform<'a> {
    pub context: &'a dyn AuditPlatform,
    pub executor: &'a dyn CheckExecutor,
    pub aging_id: &'a str,
}
macro_rules! forward {($($method:ident=>$id:literal),*)=>{$(fn $method(&self)->Outcome {self.executor.execute($id).outcome})*};}
impl AuditPlatform for PortPlatform<'_> {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        self.context.operating_system()
    }
    forward!(pending_updates=>"SEC-001",root_encryption=>"SEC-006",screen_lock=>"SEC-007",password_complexity=>"SEC-010",tpm=>"SEC-012",secure_boot=>"SEC-013",firewall=>"SEC-014",home_encryption=>"SEC-015",swap_protection=>"SEC-017");
    fn password_aging(&self) -> Outcome {
        self.executor.execute(self.aging_id).outcome
    }
    fn sensitive_encryption(&self, _targets: &[SensitiveTarget]) -> Outcome {
        self.executor.execute("SEC-016").outcome
    }
    fn encryption_discovery(&self) -> Outcome {
        self.context.encryption_discovery()
    }
}

#[cfg(all(test, unix))]
mod installation_tests {
    use super::*;
    use std::{
        fs,
        os::unix::fs::{symlink, PermissionsExt},
        sync::atomic::{AtomicUsize, Ordering},
    };
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    struct Fixture {
        root: PathBuf,
        exe: PathBuf,
        script: PathBuf,
    }
    impl Fixture {
        fn new() -> Self {
            let root = std::env::temp_dir().join(format!(
                "baradwatchu-install-unit-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            fs::create_dir(&root).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
            let exe = root.join("bin/agent");
            let script = resource_path(&exe).unwrap();
            fs::create_dir_all(exe.parent().unwrap()).unwrap();
            fs::create_dir_all(script.parent().unwrap()).unwrap();
            fs::write(&exe, b"fixture executable identity").unwrap();
            fs::set_permissions(&exe, fs::Permissions::from_mode(0o755)).unwrap();
            fs::write(
                &script,
                include_bytes!("../../../../scripts/adapters/SEC-011.sh"),
            )
            .unwrap();
            fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();
            Self { root, exe, script }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.root);
        }
    }
    #[test]
    fn executable_relative_layout_has_no_source_or_profile_heuristic() {
        for directory in ["bin", "debug", "release", "deps"] {
            assert_eq!(
                resource_path(&PathBuf::from(format!("/prefix/{directory}/agent"))),
                Some(PathBuf::from(
                    "/prefix/share/baradwatchu-client/checks/SEC-011.sh"
                ))
            );
        }
        assert_eq!(resource_path(std::path::Path::new("relative/agent")), None);
    }
    #[test]
    fn approved_readable_non_executable_script_is_valid() {
        let f = Fixture::new();
        assert!(verify_artifact(&f.exe, &f.script).is_ok());
    }
    #[test]
    fn missing_modified_and_directory_artifacts_are_distinct() {
        let f = Fixture::new();
        fs::remove_file(&f.script).unwrap();
        assert_eq!(
            verify_artifact(&f.exe, &f.script).unwrap_err().reason,
            Reason::MissingTool
        );
        fs::write(&f.script, b"unapproved").unwrap();
        assert_eq!(
            verify_artifact(&f.exe, &f.script).unwrap_err().reason,
            Reason::InvalidOutput
        );
        fs::remove_file(&f.script).unwrap();
        fs::create_dir(&f.script).unwrap();
        assert_eq!(
            verify_artifact(&f.exe, &f.script).unwrap_err().reason,
            Reason::InvalidOutput
        );
    }
    #[test]
    fn insufficient_read_permissions_are_not_missing_tool() {
        let f = Fixture::new();
        fs::set_permissions(&f.script, fs::Permissions::from_mode(0o000)).unwrap();
        // Root can read mode000 by design; unprivileged CI exercises EACCES.
        if unsafe { libc::geteuid() } != 0 {
            assert_eq!(
                verify_artifact(&f.exe, &f.script).unwrap_err().reason,
                Reason::PermissionDenied
            );
        }
    }
    #[test]
    fn writable_parent_or_artifact_is_rejected_before_execution() {
        let f = Fixture::new();
        fs::set_permissions(&f.script, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            verify_artifact(&f.exe, &f.script).unwrap_err().reason,
            Reason::PermissionDenied
        );
        fs::set_permissions(&f.script, fs::Permissions::from_mode(0o644)).unwrap();
        fs::set_permissions(
            f.script.parent().unwrap(),
            fs::Permissions::from_mode(0o777),
        )
        .unwrap();
        assert_eq!(
            verify_artifact(&f.exe, &f.script).unwrap_err().reason,
            Reason::PermissionDenied
        );
    }
    #[test]
    fn symlink_file_and_symlink_ancestor_are_rejected() {
        let f = Fixture::new();
        let original = f.root.join("approved");
        fs::rename(&f.script, &original).unwrap();
        symlink(&original, &f.script).unwrap();
        assert_eq!(
            verify_artifact(&f.exe, &f.script).unwrap_err().reason,
            Reason::PermissionDenied
        );
        fs::remove_file(&f.script).unwrap();
        fs::rename(&original, &f.script).unwrap();
        let checks = f.script.parent().unwrap();
        let moved = f.root.join("moved-checks");
        fs::rename(checks, &moved).unwrap();
        symlink(&moved, checks).unwrap();
        assert_eq!(
            verify_artifact(&f.exe, &f.script).unwrap_err().reason,
            Reason::PermissionDenied
        );
    }
    #[test]
    fn untrusted_parent_owner_is_rejected() {
        use std::os::unix::fs::MetadataExt;
        let f = Fixture::new();
        let owner = fs::metadata(&f.root).unwrap().uid();
        let system_owner = fs::metadata("/").unwrap().uid();
        if owner != system_owner {
            assert!(trusted_path(&f.script, owner + 1, system_owner).is_err());
        }
    }
}
