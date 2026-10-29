//! Native inspection adapters; the audit domain does not import these implementations.
use crate::audit::{OperatingSystem, Outcome};
use command::ProbeError;

pub mod command;
#[cfg(target_os = "linux")]
pub mod fedora;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "linux")]
mod read_only;
#[cfg(target_os = "windows")]
mod windows;

pub fn current_platform() -> &'static str {
    std::env::consts::OS
}

pub trait AuditPlatform {
    fn operating_system(&self) -> Result<OperatingSystem, ProbeError>;
    fn pending_updates(&self) -> Outcome;
    fn root_encryption(&self) -> Outcome;
}

pub struct NativePlatform;
impl AuditPlatform for NativePlatform {
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
            fedora::updates(&command::SystemRunner)
        }
        #[cfg(not(target_os = "linux"))]
        {
            unsupported()
        }
    }
    fn root_encryption(&self) -> Outcome {
        #[cfg(target_os = "linux")]
        {
            fedora::encryption(&command::SystemRunner)
        }
        #[cfg(not(target_os = "linux"))]
        {
            unsupported()
        }
    }
}
#[cfg(not(target_os = "linux"))]
fn unsupported() -> Outcome {
    Outcome::new(
        crate::audit::Status::NotApplicable,
        crate::audit::Reason::UnsupportedPlatform,
        "Only the Fedora RPM/DNF5 baseline is implemented",
    )
}
