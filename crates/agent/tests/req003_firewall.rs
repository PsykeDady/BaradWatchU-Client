#![cfg(unix)]

use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const CHECK: &str = include_str!("../../../tools/linux/firewall/check.sh");
const UFW: &str = include_str!("../../../tools/linux/firewall/ufw.sh");
const FIREWALLD: &str = include_str!("../../../tools/linux/firewall/firewalld.sh");
const NFTABLES: &str = include_str!("../../../tools/linux/firewall/nftables.sh");

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("baradwatchu-req003-{}-{nonce}", std::process::id()));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("firewall")).unwrap();
        Self { root }
    }

    fn write(&self, path: impl AsRef<Path>, value: &str, executable: bool) {
        let path = path.as_ref();
        fs::write(path, value).unwrap();
        if executable {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn install(&self) {
        let bin = self.root.join("bin");
        let config = self.root.join("ufw.conf");
        let replacements = [
            ("/usr/bin/systemctl", bin.join("systemctl")),
            ("/usr/bin/ufw", bin.join("ufw")),
            ("/usr/bin/firewall-cmd", bin.join("firewall-cmd")),
            ("/usr/bin/nft", bin.join("nft")),
            ("/etc/ufw/ufw.conf", config.clone()),
        ];
        for (name, source) in [
            ("check.sh", CHECK),
            ("ufw.sh", UFW),
            ("firewalld.sh", FIREWALLD),
            ("nftables.sh", NFTABLES),
        ] {
            let mut text = source.to_owned();
            for (from, to) in &replacements {
                text = text.replace(from, &to.to_string_lossy());
            }
            self.write(self.root.join("firewall").join(name), &text, true);
        }
        self.write(
            bin.join("systemctl"),
            r##"#!/usr/bin/bash
if [[ $1 == show ]]; then
  printf 'LoadState=%s\nActiveState=%s\nSubState=%s\nResult=%s\n' "${FW_LOAD:-loaded}" "${FW_ACTIVE:-inactive}" "${FW_SUB:-dead}" "${FW_RESULT:-success}"
elif [[ $1 == is-active ]]; then printf '%s\n' "${FW_ACTIVE:-inactive}"; exit "${FW_ACTIVE_RC:-3}"
elif [[ $1 == is-enabled ]]; then printf '%s\n' "${FW_ENABLED:-not-found}"; exit "${FW_ENABLED_RC:-1}"
else exit 1; fi
"##,
            true,
        );
        self.write(
            bin.join("ufw"),
            r##"#!/usr/bin/bash
printf '%s\n' "${FW_UFW_STATUS:-Status: inactive}"
exit "${FW_UFW_RC:-1}"
"##,
            true,
        );
        self.write(
            bin.join("firewall-cmd"),
            r##"#!/usr/bin/bash
printf '%s\n' "${FW_FIREWALLD_STATE:-not running}"
exit "${FW_FIREWALLD_RC:-1}"
"##,
            true,
        );
        self.write(
            bin.join("nft"),
            r##"#!/usr/bin/bash
if [[ ${FW_NFT_RC:-1} != 0 ]]; then echo 'Operation not permitted' >&2; exit "${FW_NFT_RC:-1}"; fi
cat "${FW_NFT_RULES:-/dev/null}"
"##,
            true,
        );
        self.write(config, "ENABLED=no\n", false);
    }

    fn set_config(&self, value: &str) {
        fs::write(self.root.join("ufw.conf"), value).unwrap();
    }

    fn run(&self, env: &[(&str, &str)]) -> Value {
        let mut command = Command::new(self.root.join("firewall/check.sh"));
        command.env_clear().env("PATH", "/usr/bin:/bin");
        for (key, value) in env {
            command.env(key, value);
        }
        let output = command.output().unwrap();
        assert_success(&output);
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn set_helpers(&self, ufw: &str, firewalld: &str, nftables: &str) {
        for (name, output) in [
            ("ufw.sh", ufw),
            ("firewalld.sh", firewalld),
            ("nftables.sh", nftables),
        ] {
            self.write(
                self.root.join("firewall").join(name),
                &format!("#!/usr/bin/bash\nprintf '%s' '{output}'\n"),
                true,
            );
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "exit={:?}; stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn req003_requires_runtime_evidence_and_aggregates_conservatively() {
    let fixture = Fixture::new();
    fixture.install();

    // Explicit ENABLED=no is a UFW failure even when systemd's last Result is success.
    let output = fixture.run(&[
        ("FW_LOAD", "loaded"),
        ("FW_ACTIVE", "inactive"),
        ("FW_SUB", "dead"),
        ("FW_RESULT", "success"),
        ("FW_ENABLED", "disabled"),
        ("FW_NFT_RC", "1"),
    ]);
    assert_eq!(output["status"], "FAIL");
    assert!(output["details"][0].as_str().unwrap().contains("FAIL"));
    assert!(output["details"][0].as_str().unwrap().contains("config=no"));
    assert!(output["details"][2]
        .as_str()
        .unwrap()
        .contains("ruleset non leggibile"));

    // An enabled oneshot UFW unit with a successful result and ENABLED=yes is operational.
    fixture.set_config("ENABLED=yes\n");
    let output = fixture.run(&[
        ("FW_LOAD", "loaded"),
        ("FW_ACTIVE", "active"),
        ("FW_SUB", "exited"),
        ("FW_RESULT", "success"),
        ("FW_ENABLED", "enabled"),
        ("FW_UFW_RC", "1"),
        ("FW_NFT_RC", "1"),
    ]);
    assert_eq!(output["status"], "PASS");
    assert!(output["details"][0].as_str().unwrap().contains("PASS"));

    // firewalld requires firewall-cmd --state to confirm a running daemon.
    fixture.set_config("ENABLED=no\n");
    let output = fixture.run(&[
        ("FW_ACTIVE", "active"),
        ("FW_ENABLED", "enabled"),
        ("FW_FIREWALLD_STATE", "running"),
        ("FW_FIREWALLD_RC", "0"),
        ("FW_NFT_RC", "1"),
    ]);
    assert_eq!(output["status"], "PASS");
    assert!(output["details"][1].as_str().unwrap().contains("PASS"));

    // A readable, effective nftables input ruleset can independently pass.
    let rules = fixture.root.join("ruleset.nft");
    fixture.write(
        &rules,
        "table inet filter {\n chain input {\n  type filter hook input priority filter; policy drop;\n }\n}\n",
        false,
    );
    let output = fixture.run(&[
        ("FW_ACTIVE", "inactive"),
        ("FW_ENABLED", "disabled"),
        ("FW_FIREWALLD_STATE", "not running"),
        ("FW_FIREWALLD_RC", "1"),
        ("FW_NFT_RC", "0"),
        ("FW_NFT_RULES", rules.to_str().unwrap()),
    ]);
    assert_eq!(output["status"], "PASS");
    assert!(output["details"][2]
        .as_str()
        .unwrap()
        .contains("policy drop"));

    // Aggregation: any verified PASS wins; otherwise WARN wins over all-FAIL.
    for (statuses, expected) in [
        (("PASS|ok", "FAIL|off", "WARN|unknown"), "PASS"),
        (("FAIL|off", "WARN|unknown", "FAIL|off"), "WARN"),
        (("FAIL|off", "FAIL|off", "FAIL|off"), "FAIL"),
    ] {
        fixture.set_helpers(statuses.0, statuses.1, statuses.2);
        assert_eq!(fixture.run(&[])["status"], expected);
    }
}
