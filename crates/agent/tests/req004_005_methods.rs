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
            ("/etc/resolv.conf", self.root.join("resolv.conf")),
            ("/etc/dnsmasq.conf", self.root.join("dnsmasq.conf")),
            ("/etc/dnsmasq.d", self.root.join("dnsmasq.d")),
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
        self.write(
            self.root.join("resolv.conf"),
            "nameserver 127.0.0.1\n",
            false,
        );
        fs::create_dir_all(self.root.join("dnsmasq.d")).unwrap();
        self.write(
            self.root.join("dnsmasq.conf"),
            &format!("servers-file={}\n", self.root.join("servers").display()),
            false,
        );
        self.set_dnsmasq_rules(1500);
        self.executable(
            "systemctl",
            "#!/usr/bin/bash\ncase $1 in\n  is-active)\n    if [[ ${DNS_STATE:-active} == unknown ]]; then echo 'Failed to connect to bus'; exit 1; fi\n    echo \"${DNS_STATE:-active}\"; [[ ${DNS_STATE:-active} == active ]] ;;\n  is-enabled) echo \"${DNS_ENABLED:-enabled}\"; [[ ${DNS_ENABLED:-enabled} == enabled ]] ;;\nesac\n",
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
        self.run_with_parameters(directory, env, None)
    }

    /// Run like the agent does: parameters arrive on stdin as {"requirementId","parameters"}.
    fn run_with_parameters(
        &self,
        directory: &str,
        env: &[(&str, &str)],
        parameters: Option<Value>,
    ) -> Value {
        use std::io::Write;
        let mut command = Command::new(self.root.join(directory).join("check.sh"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if let Some(parameters) = parameters {
            let input = serde_json::json!({"requirementId": "REQ-004", "parameters": parameters});
            stdin.write_all(input.to_string().as_bytes()).unwrap();
        }
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        assert_success(&output);
        serde_json::from_slice(&output.stdout).unwrap()
    }

    fn set_dnsmasq_rules(&self, count: usize) {
        let rules: String = (0..count)
            .map(|n| format!("server=/ad{n}.example/\n"))
            .collect();
        fs::write(self.root.join("servers"), rules).unwrap();
    }

    fn remove_tool(&self, name: &str) {
        fs::remove_file(self.root.join("bin").join(name)).unwrap();
    }

    fn set_hosts_block(&self) {
        fs::write(
            self.root.join("hosts"),
            "127.0.0.1 localhost\n0.0.0.0 ads.example\n0.0.0.0 tracker.example\n",
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
fn dns_passes_when_at_least_one_complete_method_is_active() {
    let fixture = Fixture::new();
    fixture.setup_scripts();
    let summary = |value: &Value| value["summary"].as_str().unwrap().to_owned();

    // Method B: dnsmasq active, enabled, with a loaded blocklist.
    let active = fixture.run("dns-filter", &[]);
    assert_eq!(active["status"], "PASS", "{active}");
    assert!(active["details"][0]
        .as_str()
        .unwrap()
        .contains("1500 regole"));

    // Not enabled at boot, or no blocklist, is not a DNS filter (skill R7).
    let not_enabled = fixture.run("dns-filter", &[("DNS_ENABLED", "disabled")]);
    assert_eq!(not_enabled["status"], "FAIL");
    assert!(summary(&not_enabled).contains("non abilitato"));
    fixture.set_dnsmasq_rules(10);
    let few_rules = fixture.run("dns-filter", &[]);
    assert_eq!(few_rules["status"], "FAIL");
    assert!(summary(&few_rules).contains("senza regole"));
    let lowered = fixture.run_with_parameters(
        "dns-filter",
        &[],
        Some(serde_json::json!({"minimumDnsmasqRules": 5, "minimumHostsEntries": 10000})),
    );
    assert_eq!(lowered["status"], "PASS");
    fixture.set_dnsmasq_rules(1500);

    // A VPN rewriting resolv.conf is an observation, not a failure of the filter.
    fs::write(fixture.root.join("resolv.conf"), "nameserver 10.0.0.1\n").unwrap();
    let vpn = fixture.run("dns-filter", &[]);
    assert_eq!(vpn["status"], "PASS");
    assert!(vpn["details"][0].as_str().unwrap().contains("osservazione"));

    // Method A: a small hosts list is not a blocklist; a large enough one is.
    fixture.set_hosts_block();
    let inactive = fixture.run("dns-filter", &[("DNS_STATE", "inactive")]);
    assert_eq!(inactive["status"], "FAIL");
    assert!(inactive["details"][1]
        .as_str()
        .unwrap()
        .contains("solo 2 voci"));
    let hosts_ok = fixture.run_with_parameters(
        "dns-filter",
        &[("DNS_STATE", "inactive")],
        Some(serde_json::json!({"minimumHostsEntries": 2, "minimumDnsmasqRules": 1000})),
    );
    assert_eq!(hosts_ok["status"], "PASS", "{hosts_ok}");
    assert!(
        summary(&hosts_ok).contains("blocklist completa"),
        "{hosts_ok}"
    );

    fixture.remove_tool("dnsmasq");
    assert_eq!(fixture.run("dns-filter", &[])["status"], "FAIL");
    fs::write(fixture.root.join("hosts"), "127.0.0.1 localhost\n").unwrap();
    let nothing = fixture.run("dns-filter", &[]);
    assert_eq!(nothing["status"], "FAIL");
    assert!(summary(&nothing).contains("Nessun metodo"));

    fixture.executable("dnsmasq", "#!/usr/bin/bash\nexit 0\n");
    assert_eq!(
        fixture.run("dns-filter", &[("DNS_STATE", "unknown")])["status"],
        "WARN"
    );
    let invalid = fixture.run_with_parameters(
        "dns-filter",
        &[],
        Some(serde_json::json!({"minimumHostsEntries": "many"})),
    );
    assert_eq!(invalid["status"], "ERROR");
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
