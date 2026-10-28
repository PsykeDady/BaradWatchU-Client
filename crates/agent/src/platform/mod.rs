//! Platform-specific adapters selected at compile time.

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(target_os = "windows")]
mod windows;

#[cfg(target_os = "linux")]
pub fn current_platform() -> &'static str {
    linux::NAME
}

#[cfg(target_os = "windows")]
pub fn current_platform() -> &'static str {
    windows::NAME
}

#[cfg(target_os = "macos")]
pub fn current_platform() -> &'static str {
    macos::NAME
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub fn current_platform() -> &'static str {
    "unsupported"
}
