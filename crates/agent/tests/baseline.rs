#![cfg(target_os = "linux")]
mod baseline_common;
use baradwatchu_agent::{
    audit::{Outcome, Reason, Status},
    observation::{BootState, Filtering, Observation, Quality},
    platform::{
        command::ProbeError,
        linux::{
            baseline::{
                files::{Files, NodeKind, SystemFiles},
                firewall, firmware, screen_lock,
            },
            environment::Kind,
        },
    },
};
use baseline_common::*;
const SB: &str = "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const SETUP: &str = "/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c";
fn efi(enabled: u8, setup: u8) -> Fs {
    let mut fs = Fs::default();
    fs.directory("/sys/firmware");
    fs.directory("/sys/firmware/efi");
    fs.reads
        .insert(SB.into(), Ok(Some(vec![6, 0, 0, 0, enabled])));
    fs.reads
        .insert(SETUP.into(), Ok(Some(vec![6, 0, 0, 0, setup])));
    fs
}
fn tpm(version: &str) -> Fs {
    let mut fs = Fs::default();
    fs.directories
        .insert("/sys/class/tpm".into(), Ok(Some(vec!["tpm0".into()])));
    fs.text("/sys/class/tpm/tpm0/tpm_version_major", version);
    fs.text("/sys/class/tpm/tpm0/dev", "10:224\n");
    fs.nodes
        .insert("/dev/tpm0".into(), Ok(Some(node(NodeKind::Character))));
    fs
}
fn fw(active: &[&str], nft: &str, v4: &str, v6: &str) -> (Outcome, Runner) {
    let r = Runner::new(vec![out(&services(active)), out(nft), out(v4), out(v6)]);
    (firewall::firewall(&r, &host()), r)
}
#[test]
fn secure_boot_enabled_requires_secureboot_and_setupmode() {
    let o = firmware::secure_boot(&efi(1, 0), &host());
    assert_eq!(o.status, Status::Pass);
    match o.observation.unwrap() {
        Observation::SecureBoot(f) => assert_eq!(f.state, BootState::Enabled),
        _ => panic!(),
    }
}
#[test]
fn secure_boot_disabled_verified_in_user_and_setup_modes() {
    for setup in [0, 1] {
        assert_eq!(
            firmware::secure_boot(&efi(0, setup), &host()).status,
            Status::Fail
        )
    }
}
#[test]
fn secure_boot_legacy_kernel_view_differs_from_missing_firmware_mount() {
    let mut fs = Fs::default();
    assert_eq!(firmware::secure_boot(&fs, &host()).status, Status::Warn);
    fs.directory("/sys/firmware");
    let o = firmware::secure_boot(&fs, &host());
    assert_eq!(o.status, Status::Fail);
    match o.observation.unwrap() {
        Observation::SecureBoot(f) => assert_eq!(f.state, BootState::NonUefiBoot),
        _ => panic!(),
    }
}
#[test]
fn efi_directory_presence_is_not_enablement() {
    let mut fs = efi(1, 0);
    fs.reads.remove(SETUP);
    assert_eq!(firmware::secure_boot(&fs, &host()).status, Status::Warn);
    fs.reads.clear();
    assert_eq!(firmware::secure_boot(&fs, &host()).status, Status::Warn)
}
#[test]
fn contradictory_firmware_evidence_is_inconclusive() {
    let o = firmware::secure_boot(&efi(1, 1), &host());
    assert_eq!(o.status, Status::Warn);
    match o.observation.unwrap() {
        Observation::SecureBoot(f) => assert_eq!(f.state, BootState::Inconsistent),
        _ => panic!(),
    }
}
#[test]
fn efi_permission_denied_is_error_not_disabled_or_pass() {
    let mut fs = efi(1, 0);
    fs.reads.insert(
        SB.into(),
        Err(ProbeError::new(Reason::PermissionDenied, "fixture")),
    );
    let o = firmware::secure_boot(&fs, &host());
    assert_eq!(o.status, Status::Error);
    assert_eq!(o.reason_code, Reason::PermissionDenied)
}
#[test]
fn malformed_efi_attributes_payload_or_boolean_are_errors() {
    for data in [
        vec![],
        vec![1],
        vec![0, 0, 0, 0, 1],
        vec![6, 0, 0, 0, 2],
        vec![6, 0, 0, 0, 1, 0],
    ] {
        let mut fs = efi(1, 0);
        fs.reads.insert(SB.into(), Ok(Some(data)));
        assert_eq!(firmware::secure_boot(&fs, &host()).status, Status::Error)
    }
}
#[test]
fn tpm2_presence_and_read_permission_are_separate_from_tpm_commands() {
    let fs = tpm("2\n");
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Pass);
    assert!(!fs
        .calls
        .borrow()
        .iter()
        .any(|p| fs.reads.contains_key(p) && p.starts_with("/dev/")))
}
#[test]
fn tpm12_is_not_tpm2() {
    let o = firmware::tpm(&tpm("1\n"), &host());
    assert_eq!(o.status, Status::Fail)
}
#[test]
fn no_kernel_tpm_and_unavailable_class_are_distinct() {
    let mut fs = Fs::default();
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Warn);
    fs.directories
        .insert("/sys/class/tpm".into(), Ok(Some(vec![])));
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Fail)
}
#[test]
fn tpm_unknown_version_or_missing_metadata_never_pass() {
    for version in ["3", "99"] {
        assert_eq!(firmware::tpm(&tpm(version), &host()).status, Status::Warn)
    }
    let mut fs = tpm("2");
    fs.reads.remove("/sys/class/tpm/tpm0/tpm_version_major");
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Warn)
}
#[test]
fn malformed_tpm_version_and_device_identifiers_are_errors() {
    let mut fs = tpm("bad");
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Error);
    fs.text("/sys/class/tpm/tpm0/tpm_version_major", "2");
    fs.text("/sys/class/tpm/tpm0/dev", "bad");
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Error)
}
#[test]
fn tpm_device_missing_wrong_type_or_mismatched_identity_never_pass() {
    for kind in [NodeKind::Regular, NodeKind::Other] {
        let mut fs = tpm("2");
        let mut n = node(kind);
        n.minor = 999;
        fs.nodes.insert("/dev/tpm0".into(), Ok(Some(n)));
        assert_eq!(firmware::tpm(&fs, &host()).status, Status::Warn)
    }
    let mut fs = tpm("2");
    fs.nodes.clear();
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Warn)
}
#[test]
fn tpm_device_permission_denied_does_not_become_presence_pass() {
    let mut fs = tpm("2");
    let mut n = node(NodeKind::Character);
    n.readable = false;
    fs.nodes.insert("/dev/tpm0".into(), Ok(Some(n)));
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Warn)
}
#[test]
fn accessible_resource_manager_can_substantiate_read_permission() {
    let mut fs = tpm("2");
    let mut raw = node(NodeKind::Character);
    raw.readable = false;
    fs.nodes.insert("/dev/tpm0".into(), Ok(Some(raw)));
    fs.text("/sys/class/tpmrm/tpmrm0/dev", "253:65536");
    let mut rm = node(NodeKind::Character);
    rm.major = 253;
    rm.minor = 65536;
    fs.nodes.insert("/dev/tpmrm0".into(), Ok(Some(rm)));
    assert_eq!(firmware::tpm(&fs, &host()).status, Status::Pass)
}
#[test]
fn tpm_sysfs_permission_errors_remain_explicit() {
    let mut fs = tpm("2");
    fs.reads.insert(
        "/sys/class/tpm/tpm0/tpm_version_major".into(),
        Err(ProbeError::new(Reason::PermissionDenied, "fixture")),
    );
    let o = firmware::tpm(&fs, &host());
    assert_eq!(o.status, Status::Error);
    assert_eq!(o.reason_code, Reason::PermissionDenied)
}
#[test]
fn firewall_nft_proven_input_drop_is_separate_from_service_running() {
    let (o, _) = fw(&["firewalld"], NFT_DROP, IPT_ACCEPT, IPT_ACCEPT);
    assert_eq!(o.status, Status::Pass);
    match o.observation.unwrap() {
        Observation::Firewall(f) => assert_eq!(f.filtering, Filtering::VerifiedInputFiltering),
        _ => panic!(),
    }
}
#[test]
fn running_firewalld_or_ufw_with_no_filtering_is_not_a_pass() {
    for manager in ["firewalld", "ufw", "nftables"] {
        assert_eq!(
            fw(&[manager], NFT_EMPTY, IPT_ACCEPT, IPT_ACCEPT).0.status,
            Status::Fail
        )
    }
}
#[test]
fn legacy_iptables_requires_both_address_families() {
    assert_eq!(
        fw(&["iptables", "ip6tables"], NFT_EMPTY, IPT_DROP, IPT_DROP)
            .0
            .status,
        Status::Pass
    );
    assert_eq!(
        fw(&["iptables"], NFT_EMPTY, IPT_DROP, IPT_ACCEPT).0.status,
        Status::Warn
    )
}
#[test]
fn multiple_active_managers_are_explicitly_ambiguous() {
    let (o, _) = fw(&["firewalld", "ufw"], NFT_DROP, IPT_DROP, IPT_DROP);
    assert_eq!(o.status, Status::Warn);
    match o.observation.unwrap() {
        Observation::Firewall(f) => assert!(f.multiple_managers),
        _ => panic!(),
    }
}
#[test]
fn missing_one_backend_does_not_prove_firewall_disabled() {
    let r = Runner::new(vec![
        out(&services(&[])),
        Err(ProbeError::new(Reason::MissingTool, "fixture")),
        out(IPT_ACCEPT),
        out(IPT_ACCEPT),
    ]);
    assert_eq!(firewall::firewall(&r, &host()).status, Status::Warn)
}
#[test]
fn inaccessible_rules_are_inconclusive_even_if_service_running() {
    let r = Runner::new(vec![
        out(&services(&["firewalld"])),
        Err(ProbeError::new(Reason::PermissionDenied, "fixture")),
        Err(ProbeError::new(Reason::PermissionDenied, "fixture")),
        Err(ProbeError::new(Reason::PermissionDenied, "fixture")),
    ]);
    let o = firewall::firewall(&r, &host());
    assert_eq!(o.status, Status::Warn);
    assert!(serde_json::to_string(&o)
        .unwrap()
        .contains("PERMISSION_DENIED"))
}
#[test]
fn firewall_tool_timeouts_and_malformed_rules_are_errors() {
    for reason in [
        Reason::Timeout,
        Reason::OutputLimit,
        Reason::ReadOnlyGuardUnavailable,
    ] {
        let r = Runner::new(vec![
            out(&services(&[])),
            Err(ProbeError::new(reason, "fixture")),
            out(IPT_ACCEPT),
            out(IPT_ACCEPT),
        ]);
        let o = firewall::firewall(&r, &host());
        assert_eq!(o.status, Status::Error);
        assert_eq!(o.reason_code, reason)
    }
    assert_eq!(
        fw(&[], "{}", IPT_ACCEPT, IPT_ACCEPT).0.status,
        Status::Error
    )
}
#[test]
fn complex_dormant_or_unreachable_nft_drops_do_not_prove_filtering() {
    let mut v: serde_json::Value = serde_json::from_str(NFT_DROP).unwrap();
    v["nftables"].as_array_mut().unwrap().push(serde_json::json!({"rule":{"family":"inet","table":"fixture","chain":"input","expr":[{"accept":null}]}}));
    assert_eq!(
        firewall::nft(&v.to_string()).unwrap(),
        (firewall::Input::Unknown, firewall::Input::Unknown)
    );
    v["nftables"][1]["table"]["flags"] = serde_json::json!(["dormant"]);
    assert_ne!(
        firewall::nft(&v.to_string()).unwrap().0,
        firewall::Input::AllDropped
    )
}
#[test]
fn nft_drop_in_unhooked_chain_is_not_active_host_filtering() {
    let v = r#"{"nftables":[{"chain":{"family":"inet","table":"f","name":"unused"}},{"rule":{"family":"inet","table":"f","chain":"unused","expr":[{"drop":null}]}}]}"#;
    assert_eq!(
        firewall::nft(v).unwrap(),
        (firewall::Input::Unknown, firewall::Input::Unknown)
    )
}
#[test]
fn firewall_inspection_has_no_mutating_or_dns_options() {
    let (_, r) = fw(&[], NFT_DROP, IPT_ACCEPT, IPT_ACCEPT);
    for c in r.calls.borrow().iter() {
        assert!(c.read_only_filesystem);
        assert_eq!(c.timeout.as_secs(), 5);
        assert!(!c.args.iter().any(|a| matches!(
            a.as_str(),
            "flush" | "reload" | "add" | "delete" | "--reversedns" | "-t" | "--file"
        )))
    }
    assert!(r.calls.borrow()[1].args.iter().any(|a| a == "--numeric"))
}
#[test]
fn firewall_rules_are_not_exposed_in_reports() {
    let (o, _) = fw(&[], NFT_DROP, IPT_ACCEPT, IPT_ACCEPT);
    let text = serde_json::to_string(&o).unwrap();
    assert!(!text.contains("\"table\""));
    assert!(!text.contains("\"expr\""));
    assert!(!text.contains("[0:0]"))
}
#[test]
fn plasma6_wayland_configuration_and_capability_are_observed_separately() {
    let r = Runner::new(screen_commands());
    let o = screen_lock::screen_lock(&screen_files(), &r, &host(), &user());
    assert_eq!(o.status, Status::Pass);
    match o.observation.unwrap() {
        Observation::ScreenLock(f) => {
            assert_eq!(f.automatic_lock, Some(true));
            assert_eq!(f.idle_timeout_seconds, Some(240));
            assert_eq!(f.grace_seconds, Some(5));
            assert_eq!(f.current_screen_saver_active, Some(false));
        }
        _ => panic!(),
    }
    assert!(r.outputs.borrow().is_empty())
}
#[test]
fn plasma_disabled_automatic_lock_or_password_is_not_secure() {
    for index in [9, 11, 13] {
        let mut commands = screen_commands();
        commands[index] = out("false");
        let o = screen_lock::screen_lock(&screen_files(), &Runner::new(commands), &host(), &user());
        assert_eq!(o.status, Status::Fail)
    }
}
#[test]
fn timeout_fraction_zero_and_grace_conversions_are_deterministic() {
    let mut values = std::collections::BTreeMap::new();
    for (k, v) in [
        ("Autolock", "true"),
        ("Timeout", "0.5"),
        ("Lock", "true"),
        ("LockGrace", "5"),
        ("RequirePassword", "true"),
        ("LockOnResume", "false"),
    ] {
        values.insert(k.into(), v.into());
    }
    let f = screen_lock::configuration(&values, false).unwrap();
    assert_eq!(f.idle_timeout_seconds, Some(30));
    assert_eq!(f.lock_on_resume, Some(false));
    values.insert("Timeout".into(), "0".into());
    assert_eq!(
        screen_lock::configuration(&values, false)
            .unwrap()
            .automatic_lock,
        Some(false)
    );
    for bad in ["NaN", "inf", "-1", "999999999999"] {
        values.insert("Timeout".into(), bad.into());
        assert!(screen_lock::configuration(&values, false).is_err())
    }
}
#[test]
fn complete_empty_logind_enumeration_is_na_not_missing_session() {
    let r = Runner::new(vec![
        json(serde_json::json!([true])),
        json(serde_json::json!([[]])),
    ]);
    let o = screen_lock::screen_lock(&Fs::default(), &r, &host(), &user());
    assert_eq!(o.status, Status::NotApplicable)
}

#[test]
fn malformed_bus_signature_is_error_without_reading_desktop_configuration() {
    let fs = screen_files();
    let r = Runner::new(vec![out(r#"{"type":"s","data":[true]}"#)]);
    let o = screen_lock::screen_lock(&fs, &r, &host(), &user());
    assert_eq!(o.status, Status::Error);
    assert_eq!(o.reason_code, Reason::InvalidOutput);
    assert!(fs.calls.borrow().is_empty());
}

#[test]
fn changing_selected_configuration_is_inconclusive() {
    struct Changing {
        fs: Fs,
        reads: std::cell::Cell<usize>,
    }
    impl Files for Changing {
        fn read(&self, p: &str, limit: usize) -> Result<Option<Vec<u8>>, ProbeError> {
            self.fs.read(p, limit)
        }
        fn entries(&self, p: &str) -> Result<Option<Vec<String>>, ProbeError> {
            self.fs.entries(p)
        }
        fn info(
            &self,
            p: &str,
        ) -> Result<Option<baradwatchu_agent::platform::linux::baseline::files::Node>, ProbeError>
        {
            let mut n = self.fs.info(p)?;
            if p.ends_with("kscreenlockersettings.kcfg") {
                let count = self.reads.get();
                self.reads.set(count + 1);
                // Two stat calls bracket the initial bounded source read.
                if count >= 2 {
                    n.as_mut().unwrap().modified_ns = Some(2);
                }
            }
            Ok(n)
        }
    }
    let fs = Changing {
        fs: screen_files(),
        reads: std::cell::Cell::new(0),
    };
    let runner = Runner::new(screen_commands());
    let o = screen_lock::screen_lock(&fs, &runner, &host(), &user());
    assert_eq!(o.status, Status::Warn);
    assert!(
        matches!(o.observation,Some(Observation::ScreenLock(f)) if f.quality==Quality::Inconclusive)
    );
}
#[test]
fn missing_logind_or_current_user_session_is_not_headless_na() {
    let r = Runner::new(vec![json(serde_json::json!([false]))]);
    assert_eq!(
        screen_lock::screen_lock(&Fs::default(), &r, &host(), &user()).status,
        Status::Warn
    );
    let r = Runner::new(vec![
        json(serde_json::json!([true])),
        json(sessions(2000)),
        json(serde_json::json!([{"type":"s","data":"wayland"}])),
    ]);
    assert_eq!(
        screen_lock::screen_lock(&Fs::default(), &r, &host(), &user()).status,
        Status::Warn
    )
}
#[test]
fn unknown_session_type_does_not_silently_become_headless() {
    let r = Runner::new(vec![
        json(serde_json::json!([true])),
        json(sessions(1000)),
        json(serde_json::json!([{"type":"s","data":"unspecified"}])),
        json(serde_json::json!([{"type":"s","data":"user"}])),
    ]);
    assert_eq!(
        screen_lock::screen_lock(&Fs::default(), &r, &host(), &user()).status,
        Status::Warn
    )
}
#[test]
fn systemd_user_manager_does_not_hide_plasma_session() {
    let mut commands = screen_commands();
    commands[1] = json(serde_json::json!([[
        [
            "1",
            1000,
            "private",
            "seat0",
            "/org/freedesktop/login1/session/_31"
        ],
        [
            "2",
            1000,
            "private",
            "",
            "/org/freedesktop/login1/session/_32"
        ]
    ]]));
    commands.splice(
        3..3,
        [
            json(serde_json::json!([{"type":"s","data":"unspecified"}])),
            json(serde_json::json!([{"type":"s","data":"manager"}])),
            json(serde_json::json!([{"type":"s","data":"systemd-user"}])),
            json(serde_json::json!([{"type":"b","data":false}])),
        ],
    );
    let runner = Runner::new(commands);
    let result = screen_lock::screen_lock(&screen_files(), &runner, &host(), &user());
    assert_eq!(result.status, Status::Pass);
    assert!(runner.outputs.borrow().is_empty());
}

#[test]
fn unidentified_or_remote_manager_session_remains_inconclusive() {
    for (service, remote) in [("other", false), ("systemd-user", true)] {
        let mut commands = vec![
            json(serde_json::json!([true])),
            json(sessions(1000)),
            json(serde_json::json!([{"type":"s","data":"unspecified"}])),
            json(serde_json::json!([{"type":"s","data":"manager"}])),
            json(serde_json::json!([{"type":"s","data":service}])),
        ];
        if service == "systemd-user" {
            commands.push(json(serde_json::json!([{"type":"b","data":remote}])));
        }
        let fs = Fs::default();
        let outcome = screen_lock::screen_lock(&fs, &Runner::new(commands), &host(), &user());
        assert_eq!(outcome.status, Status::Warn);
        assert!(fs.calls.borrow().is_empty());
    }
}
#[test]
fn unsupported_desktop_x11_or_plasma5_is_not_assumed_compatible() {
    for (index, value) in [(2, "x11"), (3, "GNOME"), (4, "greeter"), (5, "true")] {
        let mut c = screen_commands();
        c[index] = if index == 5 {
            json(serde_json::json!([{"type":"b","data":true}]))
        } else {
            json(serde_json::json!([{"type":"s","data":value}]))
        };
        c.truncate(6);
        let o = screen_lock::screen_lock(&Fs::default(), &Runner::new(c), &host(), &user());
        assert_eq!(o.status, Status::Warn);
        match o.observation.unwrap() {
            Observation::ScreenLock(f) => assert_eq!(f.quality, Quality::Unsupported),
            _ => panic!(),
        }
    }
    let mut u = user();
    u.kde_version = Some("5".into());
    let mut c = screen_commands();
    c.truncate(6);
    assert_eq!(
        screen_lock::screen_lock(&Fs::default(), &Runner::new(c), &host(), &u).status,
        Status::Warn
    )
}
#[test]
fn multiple_graphical_sessions_are_inconclusive_without_config_access() {
    let rows = serde_json::json!([[
        [
            "1",
            1000,
            "private",
            "seat0",
            "/org/freedesktop/login1/session/_31"
        ],
        [
            "2",
            1000,
            "private",
            "seat0",
            "/org/freedesktop/login1/session/_32"
        ]
    ]]);
    let r = Runner::new(vec![
        json(serde_json::json!([true])),
        json(rows),
        json(serde_json::json!([{"type":"s","data":"wayland"}])),
        json(serde_json::json!([{"type":"s","data":"wayland"}])),
    ]);
    let fs = Fs::default();
    assert_eq!(
        screen_lock::screen_lock(&fs, &r, &host(), &user()).status,
        Status::Warn
    );
    assert!(fs.calls.borrow().is_empty())
}
#[test]
fn inaccessible_or_foreign_configuration_is_error_not_default_pass() {
    for foreign in [true, false] {
        let mut fs = screen_files();
        let mut n = node(NodeKind::Regular);
        if foreign {
            n.owner = 2000
        } else {
            n.readable = false
        }
        fs.nodes
            .insert("/home/fixture/.config/kscreenlockerrc".into(), Ok(Some(n)));
        let mut c = screen_commands();
        c.truncate(9);
        let o = screen_lock::screen_lock(&fs, &Runner::new(c), &host(), &user());
        assert_eq!(o.status, Status::Error);
        assert_eq!(o.reason_code, Reason::PermissionDenied)
    }
}
#[test]
fn missing_schema_does_not_invent_compiled_defaults() {
    let mut fs = screen_files();
    fs.reads.clear();
    fs.nodes
        .remove("/usr/share/config.kcfg/kscreenlockersettings.kcfg");
    let mut c = screen_commands();
    c.truncate(9);
    assert_eq!(
        screen_lock::screen_lock(&fs, &Runner::new(c), &host(), &user()).status,
        Status::Warn
    )
}
#[test]
fn missing_kreadconfig_guard_and_permission_failures_remain_explicit() {
    for reason in [
        Reason::MissingTool,
        Reason::PermissionDenied,
        Reason::ReadOnlyGuardUnavailable,
    ] {
        let mut c = screen_commands();
        c.truncate(9);
        c.push(Err(ProbeError::new(reason, "fixture")));
        let o = screen_lock::screen_lock(&screen_files(), &Runner::new(c), &host(), &user());
        assert_eq!(o.status, Status::Error);
        assert_eq!(o.reason_code, reason)
    }
}
#[test]
fn screen_commands_are_local_nonactivating_guarded_and_never_lock_operator() {
    let r = Runner::new(screen_commands());
    screen_lock::screen_lock(&screen_files(), &r, &host(), &user());
    for c in r.calls.borrow().iter() {
        assert!(c.read_only_filesystem);
        if c.program.to_str() == Some("/usr/bin/busctl") {
            assert!(!c.args.iter().any(|a| matches!(
                a.as_str(),
                "Lock"
                    | "SetActive"
                    | "configure"
                    | "Inhibit"
                    | "UnInhibit"
                    | "SimulateUserActivity"
            )));
            assert!(c.args.contains(&"--auto-start=no".into()));
            assert!(c
                .args
                .contains(&"--allow-interactive-authorization=no".into()));
            assert!(!c.args.iter().any(|a| a.contains("tcp:")))
        } else {
            assert_eq!(c.program.to_str(), Some("/usr/bin/kreadconfig6"));
            assert_eq!(c.config_environment.len(), 3);
            assert!(!c.args.iter().any(|a| a == "--dump"))
        }
    }
}
#[test]
fn screen_report_omits_user_names_paths_and_unrelated_config() {
    let o = screen_lock::screen_lock(
        &screen_files(),
        &Runner::new(screen_commands()),
        &host(),
        &user(),
    );
    let s = serde_json::to_string(&o).unwrap();
    for private in ["private-user", "/home/fixture", "seat0", "/run/user/1000"] {
        assert!(!s.contains(private))
    }
}
#[test]
fn all_four_checks_refuse_host_verdicts_in_container_or_unknown_context() {
    for kind in [Kind::Container, Kind::Unknown] {
        let mut env = host();
        env.kind = kind;
        let fs = Fs::default();
        let r = Runner::new(vec![]);
        for o in [
            firmware::secure_boot(&fs, &env),
            firmware::tpm(&fs, &env),
            firewall::firewall(&r, &env),
            screen_lock::screen_lock(&fs, &r, &env, &user()),
        ] {
            assert_eq!(o.status, Status::Warn);
            assert!(serde_json::to_string(&o).unwrap().contains("RESTRICTED"));
            assert_eq!(o.evidence.len(), 1);
            let evidence = serde_json::to_value(&o.evidence[0]).unwrap();
            assert_eq!(evidence["values"]["hostProbesSkipped"], true);
            assert_eq!(
                evidence["source"],
                "Existing Linux execution-environment assessment"
            );
        }
        assert!(fs.calls.borrow().is_empty());
        assert!(r.calls.borrow().is_empty())
    }
}
#[test]
fn bounded_native_file_reader_rejects_oversize_without_modifying_owned_file() {
    let p = std::env::temp_dir().join(format!("baradwatchu-baseline-read-{}", std::process::id()));
    std::fs::write(&p, b"fixture bytes").unwrap();
    assert_eq!(
        SystemFiles.read(p.to_str().unwrap(), 32).unwrap().unwrap(),
        b"fixture bytes"
    );
    assert_eq!(
        SystemFiles.read(p.to_str().unwrap(), 1).unwrap_err().reason,
        Reason::OutputLimit
    );
    assert_eq!(std::fs::read(&p).unwrap(), b"fixture bytes");
    std::fs::remove_file(p).unwrap();
}
