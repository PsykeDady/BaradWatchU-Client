#![cfg(target_os = "linux")]
mod baseline_common;
use baradwatchu_agent::{
    audit::{Outcome, Reason, Status},
    observation::{Observation, Quality},
    platform::{
        command::{CommandOutput, CommandRunner, CommandSpec, ProbeError},
        linux::baseline::{
            files::{Files, Node},
            screen_lock,
        },
    },
};
use baseline_common::*;
use std::cell::{Cell, RefCell};

fn provenance(o: &Outcome) -> serde_json::Value {
    serde_json::to_value(o).unwrap()["evidence"]
        .as_array()
        .unwrap()
        .iter()
        .find_map(|e| e["values"].get("configurationProvenance").cloned())
        .unwrap()
}
#[test]
fn all_candidate_global_sources_are_read_and_tracked_without_exposing_paths() {
    let mut fs = screen_files();
    for p in [
        "/home/fixture/.config/system.kdeglobals",
        "/etc/xdg/system.kdeglobals",
        "/etc/kde5rc",
    ] {
        fs.text(p, "[Daemon]\nLockGrace=0\n");
    }
    let o = screen_lock::screen_lock(&fs, &Runner::new(screen_commands()), &host(), &user());
    assert_eq!(o.status, Status::Pass);
    let e = provenance(&o);
    assert_eq!(e["sourceSetEstablished"], true);
    assert_eq!(e["consistency"], "UNCHANGED_BOUNDED_SNAPSHOTS");
    assert_eq!(e["atomicSnapshot"], false);
    assert_eq!(e["perKeyOriginVerified"], false);
    assert_eq!(e["precedenceAndImmutability"], "DELEGATED_TO_KCONFIG");
    for p in [
        "/home/fixture/.config/system.kdeglobals",
        "/etc/xdg/system.kdeglobals",
        "/etc/kde5rc",
    ] {
        assert_eq!(
            fs.calls.borrow().iter().filter(|s| s.as_str() == p).count(),
            6
        );
    }
    assert!(!e.to_string().contains("/home/fixture"));
    assert!(!e.to_string().contains("LockGrace=0"));
}
#[test]
fn inaccessible_or_foreign_globals_cannot_silently_fall_back_to_defaults() {
    for p in ["/etc/xdg/system.kdeglobals", "/etc/kde5rc"] {
        for foreign in [false, true] {
            let mut fs = screen_files();
            fs.text(p, "[Daemon]\n");
            let n = fs
                .nodes
                .get_mut(p)
                .unwrap()
                .as_mut()
                .unwrap()
                .as_mut()
                .unwrap();
            if foreign {
                n.owner = 2000
            } else {
                n.readable = false
            }
            let mut commands = screen_commands();
            commands.truncate(9);
            let runner = Runner::new(commands);
            let o = screen_lock::screen_lock(&fs, &runner, &host(), &user());
            assert_eq!(o.status, Status::Error);
            assert_eq!(o.reason_code, Reason::PermissionDenied);
            assert_eq!(provenance(&o)["sourceSetEstablished"], false);
            assert_eq!(runner.calls.borrow().len(), 9);
        }
    }
}
#[derive(Clone, Copy)]
enum Change {
    Bytes,
    Create,
    Remove,
    Deny,
}
struct Mutable(RefCell<Fs>);
impl Files for Mutable {
    fn read(&self, p: &str, l: usize) -> Result<Option<Vec<u8>>, ProbeError> {
        self.0.borrow().read(p, l)
    }
    fn info(&self, p: &str) -> Result<Option<Node>, ProbeError> {
        self.0.borrow().info(p)
    }
    fn entries(&self, p: &str) -> Result<Option<Vec<String>>, ProbeError> {
        self.0.borrow().entries(p)
    }
}
struct Changed<'a> {
    fs: &'a Mutable,
    runner: Runner,
    path: &'a str,
    change: Change,
    done: Cell<bool>,
}
impl CommandRunner for Changed<'_> {
    fn run(&self, s: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        let o = self.runner.run(s)?;
        if s.program.to_str() == Some("/usr/bin/kreadconfig6") && !self.done.replace(true) {
            let mut fs = self.fs.0.borrow_mut();
            match self.change {
                Change::Bytes => {
                    fs.reads.insert(
                        self.path.into(),
                        Ok(Some(b"[Daemon]\nLockGrace=5\n".to_vec())),
                    );
                }
                Change::Create => fs.text(self.path, "[Daemon]\nLockGrace=5\n"),
                Change::Remove => {
                    fs.reads.remove(self.path);
                    fs.nodes.remove(self.path);
                }
                Change::Deny => {
                    fs.nodes.insert(
                        self.path.into(),
                        Err(ProbeError::new(Reason::PermissionDenied, "fixture")),
                    );
                }
            }
        }
        Ok(o)
    }
}
#[test]
fn every_global_source_change_creation_or_removal_is_inconclusive() {
    for path in [
        "/home/fixture/.config/system.kdeglobals",
        "/etc/xdg/system.kdeglobals",
        "/etc/kde5rc",
    ] {
        for change in [Change::Bytes, Change::Create, Change::Remove] {
            let mut fs = screen_files();
            if !matches!(change, Change::Create) {
                fs.text(path, "[Daemon]\nLockGrace=0\n")
            }
            let fs = Mutable(RefCell::new(fs));
            let runner = Changed {
                fs: &fs,
                runner: Runner::new(screen_commands()),
                path,
                change,
                done: Cell::new(false),
            };
            let o = screen_lock::screen_lock(&fs, &runner, &host(), &user());
            assert_eq!(o.status, Status::Warn);
            assert!(
                matches!(&o.observation,Some(Observation::ScreenLock(f)) if f.quality==Quality::Inconclusive)
            );
            assert_eq!(provenance(&o)["consistency"], "CHANGED");
        }
    }
}
#[test]
fn read_failures_prevent_lookup_and_lost_access_prevents_consistency_claim() {
    for path in ["/etc/xdg/system.kdeglobals", "/etc/kde5rc"] {
        let mut fs = screen_files();
        fs.text(path, "[Daemon]\nLockGrace=0\n");
        fs.reads.insert(
            path.into(),
            Err(ProbeError::new(Reason::PermissionDenied, "fixture")),
        );
        let mut commands = screen_commands();
        commands.truncate(9);
        let runner = Runner::new(commands);
        let o = screen_lock::screen_lock(&fs, &runner, &host(), &user());
        assert_eq!(o.status, Status::Error);
        assert_eq!(o.reason_code, Reason::PermissionDenied);
        assert_eq!(provenance(&o)["sourceSetEstablished"], false);
        assert_eq!(runner.calls.borrow().len(), 9);

        fs.text(path, "[Daemon]\nLockGrace=0\n");
        let fs = Mutable(RefCell::new(fs));
        let runner = Changed {
            fs: &fs,
            runner: Runner::new(screen_commands()),
            path,
            change: Change::Deny,
            done: Cell::new(false),
        };
        let o = screen_lock::screen_lock(&fs, &runner, &host(), &user());
        assert_eq!(o.status, Status::Error);
        assert_eq!(o.reason_code, Reason::PermissionDenied);
        assert_eq!(provenance(&o)["sourceSetEstablished"], true);
        assert_eq!(provenance(&o)["consistency"], "NOT_ESTABLISHED");
    }
}

#[test]
fn metadata_change_within_initial_snapshot_prevents_configuration_lookup() {
    struct DuringSnapshot(Fs, Cell<u32>);
    impl Files for DuringSnapshot {
        fn read(&self, p: &str, l: usize) -> Result<Option<Vec<u8>>, ProbeError> {
            self.0.read(p, l)
        }
        fn info(&self, p: &str) -> Result<Option<Node>, ProbeError> {
            let mut node = self.0.info(p)?;
            if p == "/etc/xdg/system.kdeglobals" {
                let call = self.1.get();
                self.1.set(call + 1);
                if call > 0 {
                    node.as_mut().unwrap().inode += 1;
                }
            }
            Ok(node)
        }
        fn entries(&self, p: &str) -> Result<Option<Vec<String>>, ProbeError> {
            self.0.entries(p)
        }
    }
    let mut fs = screen_files();
    fs.text("/etc/xdg/system.kdeglobals", "[Daemon]\n");
    let mut commands = screen_commands();
    commands.truncate(9);
    let runner = Runner::new(commands);
    let o = screen_lock::screen_lock(&DuringSnapshot(fs, Cell::new(0)), &runner, &host(), &user());
    assert_eq!(o.status, Status::Error);
    assert_eq!(o.reason_code, Reason::InvalidOutput);
    assert_eq!(provenance(&o)["sourceSetEstablished"], false);
    assert_eq!(runner.calls.borrow().len(), 9);
}
struct Defaults(Runner);
impl CommandRunner for Defaults {
    fn run(&self, s: &CommandSpec) -> Result<CommandOutput, ProbeError> {
        if s.program.to_str() != Some("/usr/bin/kreadconfig6") {
            return self.0.run(s);
        }
        self.0.calls.borrow_mut().push(s.clone());
        let i = s.args.iter().position(|s| s == "--default").unwrap();
        out(&s.args[i + 1])
    }
}
#[test]
fn missing_keys_use_installed_schema_defaults_including_five_second_grace() {
    let mut c = screen_commands();
    c.truncate(9);
    let r = Defaults(Runner::new(c));
    let o = screen_lock::screen_lock(&screen_files(), &r, &host(), &user());
    let Some(Observation::ScreenLock(f)) = o.observation else {
        panic!()
    };
    assert_eq!(f.idle_timeout_seconds, Some(300));
    assert_eq!(f.grace_seconds, Some(5));
    assert_eq!(f.password_required, Some(true));
}
#[test]
fn normalized_xdg_paths_preserve_order_spaces_and_candidate_scope() {
    let fs = screen_files();
    let r = Runner::new(screen_commands());
    let mut u = user();
    u.config_dirs = Some("/etc/xdg/:/etc/./xdg:/srv/with spaces".into());
    let o = screen_lock::screen_lock(&fs, &r, &host(), &u);
    assert_eq!(o.status, Status::Pass);
    assert_eq!(
        r.calls.borrow()[9].config_environment["XDG_CONFIG_DIRS"],
        "/etc/xdg:/srv/with spaces"
    );
    assert!(fs
        .calls
        .borrow()
        .contains(&"/srv/with spaces/system.kdeglobals".into()));
}
#[test]
fn invalid_or_excessive_search_paths_prevent_config_commands() {
    for dirs in [
        "/etc/xdg:relative".to_owned(),
        "/etc/xdg:".into(),
        (0..9)
            .map(|i| format!("/tmp/{i}"))
            .collect::<Vec<_>>()
            .join(":"),
    ] {
        let mut u = user();
        u.config_dirs = Some(dirs);
        let mut c = screen_commands();
        c.truncate(9);
        let r = Runner::new(c);
        let o = screen_lock::screen_lock(&screen_files(), &r, &host(), &u);
        assert_eq!(o.status, Status::Error);
        assert_eq!(r.calls.borrow().len(), 9);
    }
}
#[test]
fn resolver_immutable_global_result_is_not_replaced_by_user_file_guessing() {
    let mut fs = screen_files();
    fs.text("/etc/xdg/system.kdeglobals", "[Daemon]\nTimeout[$i]=4\n");
    fs.text(
        "/home/fixture/.config/kscreenlockerrc",
        "[Daemon]\nTimeout=5\n",
    );
    let r = Runner::new(screen_commands()); // Scripted KConfig winner: 4 minutes.
    let o = screen_lock::screen_lock(&fs, &r, &host(), &user());
    assert!(
        matches!(o.observation,Some(Observation::ScreenLock(f)) if f.idle_timeout_seconds==Some(240))
    );
    assert!(r.calls.borrow()[9]
        .args
        .contains(&"--include-globals".into()));
}
#[test]
fn oversized_candidate_source_is_not_read_by_kconfig() {
    let mut fs = screen_files();
    fs.text("/etc/xdg/system.kdeglobals", &"x".repeat(65537));
    let mut c = screen_commands();
    c.truncate(9);
    let r = Runner::new(c);
    let o = screen_lock::screen_lock(&fs, &r, &host(), &user());
    assert_eq!(o.status, Status::Error);
    assert_eq!(o.reason_code, Reason::OutputLimit);
    assert_eq!(r.calls.borrow().len(), 9);
}
