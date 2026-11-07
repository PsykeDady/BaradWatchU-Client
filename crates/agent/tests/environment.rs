#![cfg(target_os = "linux")]
mod common;
use baradwatchu_agent::{
    audit::Reason,
    platform::{
        command::{CommandOutput, CommandRunner, CommandSpec, ProbeError},
        linux::environment::{self, Kind, SignalReader, Signals},
    },
};
use common::*;
struct SignalFixture {
    marker: bool,
    init: bool,
    user: bool,
    root: bool,
}
impl SignalReader for SignalFixture {
    fn read(&self) -> Result<Signals, ProbeError> {
        Ok(Signals {
            container_marker: self.marker,
            native_init: self.init,
            initial_user_namespace: self.user,
            same_root_context: self.root,
        })
    }
}
fn native() -> SignalFixture {
    SignalFixture {
        marker: false,
        init: true,
        user: true,
        root: true,
    }
}
#[test]
fn explicit_marker_is_container_without_command_execution() {
    let signals = SignalFixture {
        marker: true,
        ..native()
    };
    let runner = Runner::new(vec![]);
    let env = environment::detect(&runner, &signals);
    assert_eq!(env.kind, Kind::Container);
    assert!(runner.commands.borrow().is_empty());
}
#[test]
fn detector_positive_identifies_container_even_with_native_looking_signals() {
    for name in ["docker\n", "systemd-nspawn\n", "podman\n"] {
        assert_eq!(
            environment::detect(&Runner::new(vec![out(0, name, "")]), &native()).kind,
            Kind::Container
        );
    }
}
#[test]
fn native_requires_detector_none_and_affirmative_context() {
    assert_eq!(
        environment::detect(&Runner::new(vec![out(1, "none\n", "")]), &native()).kind,
        Kind::NativeHost
    );
    for signals in [
        SignalFixture {
            init: false,
            ..native()
        },
        SignalFixture {
            user: false,
            ..native()
        },
        SignalFixture {
            root: false,
            ..native()
        },
        SignalFixture {
            init: false,
            user: false,
            root: false,
            ..native()
        },
    ] {
        assert_eq!(
            environment::detect(&Runner::new(vec![out(1, "none", "")]), &signals).kind,
            Kind::Unknown
        );
    }
}
#[test]
fn empty_unrecognized_or_failed_detector_never_establishes_native_host() {
    for output in [
        out(1, "", ""),
        out(2, "none", ""),
        out(0, "none", ""),
        out(1, "none", "Permission denied"),
    ] {
        assert_eq!(
            environment::detect(&Runner::new(vec![output]), &native()).kind,
            Kind::Unknown
        );
    }
}
struct Denied(Reason);
impl CommandRunner for Denied {
    fn run(&self, _: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        Err(ProbeError::new(self.0, "fixture"))
    }
}
#[test]
fn missing_tool_permissions_and_guard_failure_are_explicit_unknown_not_native() {
    for reason in [
        Reason::MissingTool,
        Reason::PermissionDenied,
        Reason::ReadOnlyGuardUnavailable,
        Reason::Timeout,
    ] {
        let env = environment::detect(&Denied(reason), &native());
        assert_eq!(env.kind, Kind::Unknown);
        assert_eq!(env.probe_error, Some(reason));
    }
}
struct SignalDenied;
impl SignalReader for SignalDenied {
    fn read(&self) -> Result<Signals, ProbeError> {
        Err(ProbeError::new(Reason::PermissionDenied, "fixture"))
    }
}
#[test]
fn unreadable_proc_signals_prevent_native_claim_even_if_detector_says_none() {
    let env = environment::detect(&Runner::new(vec![out(1, "none", "")]), &SignalDenied);
    assert_eq!(env.kind, Kind::Unknown);
    assert_eq!(env.probe_error, Some(Reason::PermissionDenied));
}
#[test]
fn detector_command_is_fixed_bounded_and_filesystem_guarded() {
    let runner = Runner::new(vec![out(1, "none", "")]);
    environment::detect(&runner, &native());
    let commands = runner.commands.borrow();
    assert_eq!(commands.len(), 1);
    assert_eq!(
        commands[0].program.to_str().unwrap(),
        "/usr/bin/systemd-detect-virt"
    );
    assert_eq!(commands[0].args, ["--container"]);
    assert!(commands[0].read_only_filesystem);
    assert_eq!(commands[0].timeout.as_secs(), 30);
}
