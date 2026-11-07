//! Native inspection adapters; the audit domain does not import these implementations.
use crate::audit::{OperatingSystem, Outcome};
use command::ProbeError;

#[cfg(target_os = "linux")]
pub mod arch;
pub mod command;
#[cfg(target_os = "linux")]
pub mod fedora;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
mod macos;
mod probe;
#[cfg(target_os = "linux")]
mod read_only;
#[cfg(target_os = "windows")]
mod windows;

pub fn current_platform() -> &'static str {
    std::env::consts::OS
}

pub trait AuditPlatform {
    fn password_aging(&self) -> Outcome {
        baseline_unavailable()
    }
    fn password_complexity(&self) -> Outcome {
        baseline_unavailable()
    }
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError>;
    fn pending_updates(&self) -> Outcome;
    fn root_encryption(&self) -> Outcome;
    fn secure_boot(&self) -> Outcome {
        baseline_unavailable()
    }
    fn tpm(&self) -> Outcome {
        baseline_unavailable()
    }
    fn firewall(&self) -> Outcome {
        baseline_unavailable()
    }
    fn screen_lock(&self) -> Outcome {
        baseline_unavailable()
    }
    fn home_encryption(&self) -> Outcome {
        baseline_unavailable()
    }
    fn sensitive_encryption(&self, _targets: &[crate::policy::SensitiveTarget]) -> Outcome {
        baseline_unavailable()
    }
    fn swap_protection(&self) -> Outcome {
        baseline_unavailable()
    }
    fn encryption_discovery(&self) -> Outcome {
        baseline_unavailable()
    }
}

pub struct NativePlatform;
impl AuditPlatform for NativePlatform {
    fn password_aging(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::baseline::password_aging::observe(
                &linux::baseline::credential_sources::CredentialFiles,
                &command::SystemRunner,
                &env,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
    fn password_complexity(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::baseline::password_pam::observe(
                &linux::baseline::credential_sources::CredentialFiles,
                &env,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
    fn encryption_discovery(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::coverage::discover(&linux::topology::SysfsTopology, &env)
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
    fn home_encryption(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::coverage::home(
                &command::SystemRunner,
                &linux::topology::SysfsTopology,
                &env,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
    fn sensitive_encryption(&self, targets: &[crate::policy::SensitiveTarget]) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::coverage::sensitive(
                targets,
                &command::SystemRunner,
                &linux::topology::SysfsTopology,
                &env,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = targets;
            baseline_unavailable()
        }
    }
    fn swap_protection(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::coverage::swap(
                &command::SystemRunner,
                &linux::topology::SysfsTopology,
                &env,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError> {
        #[cfg(target_os = "linux")]
        {
            linux::detect()
        }
        #[cfg(not(target_os = "linux"))]
        {
            Ok(OperatingSystem::unidentified(current_platform()))
        }
    }
    fn pending_updates(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            linux::pending_updates(&command::SystemRunner)
        }
        #[cfg(not(target_os = "linux"))]
        {
            unsupported()
        }
    }
    fn root_encryption(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            linux::root_encryption(&command::SystemRunner)
        }
        #[cfg(not(target_os = "linux"))]
        {
            unsupported()
        }
    }
    fn secure_boot(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::baseline::firmware::secure_boot(&linux::baseline::files::SystemFiles, &env)
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
    fn tpm(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::baseline::firmware::tpm(&linux::baseline::files::SystemFiles, &env)
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
    fn firewall(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::baseline::firewall::firewall(&command::SystemRunner, &env)
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
    fn screen_lock(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            let env = linux::environment::detect(
                &command::SystemRunner,
                &linux::environment::SystemSignals,
            );
            linux::baseline::screen_lock::screen_lock(
                &linux::baseline::files::SystemFiles,
                &command::SystemRunner,
                &env,
                &linux::baseline::screen_lock::SessionContext::current(),
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            baseline_unavailable()
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn unsupported() -> Outcome {
    Outcome::new(
        crate::audit::Status::NotApplicable,
        crate::audit::Reason::UnsupportedPlatform,
        "Only native Arch Linux and Fedora RPM/DNF5 are implemented",
    )
}

fn baseline_unavailable() -> Outcome {
    Outcome::new(
        crate::audit::Status::NotApplicable,
        crate::audit::Reason::UnsupportedPlatform,
        "Linux baseline observation not implemented by this adapter",
    )
}
