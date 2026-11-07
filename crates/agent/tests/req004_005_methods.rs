#![cfg(unix)]

use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

const DNS_CHECK: &str = include_str!("../../../catalog/checks/REQ-004/check.sh");
const DNSMASQ: &str = include_str!("../../../catalog/checks/REQ-004/dnsmasq.sh");
const HOSTS: &str = include_str!("../../../catalog/checks/REQ-004/hosts.sh");
const VPN_CHECK: &str = include_str!("../../../catalog/checks/REQ-005/check.sh");
const CATO: &str = include_str!("../../../catalog/checks/REQ-005/cato.sh");
const WIREGUARD: &str = include_str!("../../../catalog/checks/REQ-005/wireguard.sh");

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "baradwatchu-req004-005-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("dns-filter")).unwrap();
        fs::create_dir_all(root.join("vpn")).unwrap();
        Self { root }
    }

    fn write(&self, path: impl AsRef<Path>, value: &str, executable: bool) {
        let path = path.as_ref();
        fs::write(path, value).unwrap();
        if executable {
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn executable(&self, name: &str, body: &str) {
        self.write(self.root.join("bin").join(name), body, true);
    }

    fn setup_scripts(&self) {
        let bin = self.root.join("bin");
        let hosts = self.root.join("hosts");
        let replacements = [
            ("/usr/bin/dnsmasq", bin.join("dnsmasq")),
            ("/usr/bin/systemctl", bin.join("systemctl")),
            ("/usr/bin/cato-sdp", bin.join("cato-sdp")),
            ("/usr/bin/wg", bin.join("wg")),
            ("/etc/hosts", hosts.clone()),
        ];
        for (name, source, directory) in [
            ("check.sh", DNS_CHECK, "dns-filter"),
            ("dnsmasq.sh", DNSMASQ, "dns-filter"),
            ("hosts.sh", HOSTS, "dns-filter"),
            ("check.sh", VPN_CHECK, "vpn"),
            ("cato.sh", CATO, "vpn"),
            ("wireguard.sh", WIREGUARD, "vpn"),
        ] {
            let mut script = source.to_owned();
            for (from, to) in &replacements {
                script = script.replace(from, &to.to_string_lossy());
            }
            self.write(self.root.join(directory).join(name), &script, true);
        }
        self.write(hosts, "127.0.0.1 localhost\n", false);
        self.executable(
            "systemctl",
            "#!/usr/bin/bash\nif [[ ${DNS_STATE:-active} == unknown ]]; then echo 'Failed to connect to bus'; exit 1; fi\necho \"${DNS_STATE:-active}\"\n[[ ${DNS_STATE:-active} == active ]]\n",
        );
        self.executable(
            "cato-sdp",
            "#!/usr/bin/bash\nprintf '%s\\n' \"${CATO_OUTPUT:-Cato client is disconnected}\"\nexit \"${CATO_RC:-0}\"\n",
        );
        self.executable(
            "wg",
            "#!/usr/bin/bash\n[[ ${WG_RC:-0} == 0 ]] || exit \"$WG_RC\"\nprintf '%s\\n' \"${WG_INTERFACES:-}\"\n",
        );
        self.executable("dnsmasq", "#!/usr/bin/bash\nexit 0\n");
    }

    fn run(&self, directory: &str, env: &[(&str, &str)]) -> Value {
        let mut command = Command::new(self.root.join(directory).join("check.sh"));
        command.env_clear().env("PATH", "/usr/bin:/bin");
        for (key, value) in env {
            command.env(key, value);
        }
        let output = command.output().unwrap();
        assert_success(&output);
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn remove_tool(&self, name: &str) {
        fs::remove_file(self.root.join("bin").join(name)).unwrap();
    }

    fn set_hosts_block(&self) {
        fs::write(
            self.root.join("hosts"),
            "127.0.0.1 localhost\n0.0.0.0 ads.example tracker.example\n",
        )
        .unwrap();
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
fn dns_requires_active_dnsmasq_or_hosts_fallback_when_dnsmasq_is_absent() {
    let fixture = Fixture::new();
    fixture.setup_scripts();

    assert_eq!(fixture.run("dns-filter", &[])["status"], "PASS");

    fixture.remove_tool("dnsmasq");
    fixture.set_hosts_block();
    assert_eq!(fixture.run("dns-filter", &[])["status"], "PASS");

    fixture.executable("dnsmasq", "#!/usr/bin/bash\nexit 0\n");
    let inactive = fixture.run("dns-filter", &[("DNS_STATE", "inactive")]);
    assert_eq!(inactive["status"], "FAIL");
    assert!(inactive["summary"]
        .as_str()
        .unwrap()
        .contains("fallback solo in assenza"));

    assert_eq!(
        fixture.run("dns-filter", &[("DNS_STATE", "unknown")])["status"],
        "WARN"
    );
}

#[test]
fn vpn_requires_connection_and_warns_when_supported_client_is_disconnected() {
    let fixture = Fixture::new();
    fixture.setup_scripts();

    assert_eq!(fixture.run("vpn", &[])["status"], "WARN");
    assert_eq!(
        fixture.run("vpn", &[("CATO_OUTPUT", "Cato client is connected")])["status"],
        "PASS"
    );

    fixture.remove_tool("cato-sdp");
    assert_eq!(
        fixture.run("vpn", &[("WG_INTERFACES", "wg0")])["status"],
        "PASS"
    );
    assert_eq!(fixture.run("vpn", &[])["status"], "WARN");

    fixture.remove_tool("wg");
    assert_eq!(fixture.run("vpn", &[])["status"], "FAIL");
}
