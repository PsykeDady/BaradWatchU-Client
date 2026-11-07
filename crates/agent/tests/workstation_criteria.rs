#![cfg(unix)]
//! Fixture tests for the built-in Arch checks whose PASS criteria follow the workstation
//! audit baseline (REQUIREMENTS §5 SEC-003/006/007/008-010, skill audit-postazione R1-R5).
//! Absolute system paths in each script are rewritten to fixture files and stub commands.

use serde_json::Value;
use std::{
    fs,
    io::Write,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    process::{Command, Stdio},
    time::{SystemTime, UNIX_EPOCH},
};

struct Fixture {
    root: PathBuf,
}

impl Fixture {
    fn new(label: &str) -> Self {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!(
            "baradwatchu-{label}-{}-{nonce}",
            std::process::id()
        ));
        fs::create_dir_all(root.join("bin")).unwrap();
        fs::create_dir_all(root.join("check")).unwrap();
        Self { root }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.root.join(relative)
    }

    fn write(&self, relative: &str, content: &str) {
        let path = self.path(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, content).unwrap();
    }

    fn executable(&self, relative: &str, content: &str) {
        self.write(relative, content);
        fs::set_permissions(self.path(relative), fs::Permissions::from_mode(0o700)).unwrap();
    }

    /// Install `scripts` (name, source) into check/ with every `from` path replaced.
    fn install(&self, scripts: &[(&str, &str)], replacements: &[(&str, PathBuf)]) {
        for (name, source) in scripts {
            let mut script = (*source).to_owned();
            for (from, to) in replacements {
                script = script.replace(from, &to.to_string_lossy());
            }
            self.executable(&format!("check/{name}"), &script);
        }
    }

    fn run(&self, env: &[(&str, &str)], parameters: Option<Value>) -> Value {
        let mut command = Command::new(self.path("check/check.sh"));
        command
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        for (key, value) in env {
            command.env(key, value);
        }
        let mut child = command.spawn().unwrap();
        let mut stdin = child.stdin.take().unwrap();
        if let Some(parameters) = parameters {
            let input = serde_json::json!({"requirementId": "REQ", "parameters": parameters});
            stdin.write_all(input.to_string().as_bytes()).unwrap();
        }
        drop(stdin);
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "exit={:?} stderr={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)))
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn summary(value: &Value) -> &str {
    value["summary"].as_str().unwrap()
}

fn bin(fixture: &Fixture, name: &str) -> (String, PathBuf) {
    (
        format!("/usr/bin/{name}"),
        fixture.path(&format!("bin/{name}")),
    )
}

// ---------------------------------------------------------------- REQ-007 screen lock

fn screen_lock_fixture() -> Fixture {
    let fixture = Fixture::new("req007");
    let replacements = [bin(&fixture, "kreadconfig6"), bin(&fixture, "pgrep")];
    let replacements: Vec<(&str, PathBuf)> = replacements
        .iter()
        .map(|(a, b)| (a.as_str(), b.clone()))
        .collect();
    fixture.install(
        &[(
            "check.sh",
            include_str!("../../../catalog/checks/REQ-007/check.sh"),
        )],
        &replacements,
    );
    // Each key comes from KS_<Key>; unset keys return the --default value like kreadconfig6.
    fixture.executable(
        "bin/kreadconfig6",
        "#!/usr/bin/bash\nwhile (($#)); do case $1 in --key) key=$2; shift;; --default) def=$2; shift;; esac; shift; done\nvar=KS_$key\nprintf '%s\\n' \"${!var:-$def}\"\n",
    );
    fixture.executable("bin/pgrep", "#!/usr/bin/bash\nexit 1\n");
    fixture
}

const PLASMA: [(&str, &str); 3] = [
    ("XDG_CURRENT_DESKTOP", "KDE"),
    ("XDG_SESSION_TYPE", "wayland"),
    ("WAYLAND_DISPLAY", "wayland-0"),
];

fn with_plasma<'a>(extra: &[(&'a str, &'a str)]) -> Vec<(&'a str, &'a str)> {
    PLASMA
        .iter()
        .copied()
        .chain(extra.iter().copied())
        .collect()
}

#[test]
fn screen_lock_requires_five_minutes_and_immediate_password() {
    let fixture = screen_lock_fixture();
    let compliant = fixture.run(&with_plasma(&[("KS_LockGrace", "0")]), None);
    assert_eq!(compliant["status"], "PASS", "{compliant}");

    // Plasma's default grace period (5 s) does not ask for the password immediately.
    let default_grace = fixture.run(&with_plasma(&[]), None);
    assert_eq!(default_grace["status"], "FAIL");
    assert!(summary(&default_grace).contains("grazia"));

    let long_timeout = fixture.run(
        &with_plasma(&[("KS_LockGrace", "0"), ("KS_Timeout", "15")]),
        None,
    );
    assert_eq!(long_timeout["status"], "FAIL");
    assert!(summary(&long_timeout).contains("15 minuti"));

    let disabled = fixture.run(
        &with_plasma(&[
            ("KS_Autolock", "false"),
            ("KS_Timeout", "0"),
            ("KS_LockGrace", "0"),
        ]),
        None,
    );
    assert_eq!(disabled["status"], "FAIL");
    assert!(summary(&disabled).contains("disattivato"));

    let no_resume = fixture.run(
        &with_plasma(&[("KS_LockGrace", "0"), ("KS_LockOnResume", "false")]),
        None,
    );
    assert_eq!(no_resume["status"], "FAIL");

    // Thresholds are parameters, not constants.
    let relaxed = fixture.run(
        &with_plasma(&[("KS_Timeout", "10")]),
        Some(serde_json::json!({"maxTimeoutMinutes": 10, "maxLockGraceSeconds": 5})),
    );
    assert_eq!(relaxed["status"], "PASS", "{relaxed}");
    let invalid = fixture.run(
        &with_plasma(&[]),
        Some(serde_json::json!({"maxTimeoutMinutes": 0})),
    );
    assert_eq!(invalid["status"], "ERROR");

    let x11 = fixture.run(&[("XDG_SESSION_TYPE", "x11")], None);
    assert_eq!(x11["status"], "NOT_APPLICABLE");
}

// ---------------------------------------------------------------- REQ-008 passwords

fn password_fixture() -> Fixture {
    let fixture = Fixture::new("req008");
    let chage = bin(&fixture, "chage");
    let replacements = vec![
        (chage.0.as_str(), chage.1.clone()),
        ("/etc/login.defs", fixture.path("login.defs")),
        (
            "/etc/security/pwquality.conf",
            fixture.path("pwquality.conf"),
        ),
        ("/etc/pam.d", fixture.path("pam.d")),
    ];
    fixture.install(
        &[(
            "check.sh",
            include_str!("../../../catalog/checks/REQ-008/check.sh"),
        )],
        &replacements,
    );
    fixture.executable(
        "bin/chage",
        "#!/usr/bin/bash\ncat <<OUT\nLast password change\t\t\t\t\t: Oct 01, 2026\nPassword expires\t\t\t\t\t: ${EXPIRES:-Nov 30, 2026}\nPassword inactive\t\t\t\t\t: never\nAccount expires\t\t\t\t\t\t: never\nMinimum number of days between password change\t\t: 1\nMaximum number of days between password change\t\t: ${MAX_DAYS:-60}\nNumber of days of warning before password expires\t: ${WARN_DAYS:-10}\nOUT\n",
    );
    fixture.write(
        "login.defs",
        "PASS_MAX_DAYS\t60\nPASS_MIN_DAYS\t1\nPASS_WARN_AGE\t10\n",
    );
    fixture.write(
        "pwquality.conf",
        "# comment\nminlen = 14\nminclass = 4\nucredit = -1\nlcredit = -1\ndcredit = -1\nocredit = -1\n",
    );
    fixture.write(
        "pam.d/system-auth",
        "password required pam_pwquality.so retry=3\npassword required pam_unix.so\n",
    );
    fixture
}

#[test]
fn password_policy_follows_age_warning_length_classes_and_credits() {
    let fixture = password_fixture();
    let user = [("USER", "alice")];
    let compliant = fixture.run(&user, None);
    assert_eq!(compliant["status"], "PASS", "{compliant}");

    let never = fixture.run(
        &[
            ("USER", "alice"),
            ("MAX_DAYS", "99999"),
            ("EXPIRES", "never"),
        ],
        None,
    );
    assert_eq!(never["status"], "FAIL");
    assert!(summary(&never).contains("scadenza"));

    let short_warning = fixture.run(&[("USER", "alice"), ("WARN_DAYS", "7")], None);
    assert_eq!(short_warning["status"], "FAIL");
    assert!(summary(&short_warning).contains("preavviso"));

    fixture.write(
        "pwquality.conf",
        "minlen = 14\nminclass = 4\nucredit = 0\nlcredit = -1\ndcredit = -1\nocredit = -1\n",
    );
    let weak_credit = fixture.run(&user, None);
    assert_eq!(weak_credit["status"], "FAIL");
    assert!(summary(&weak_credit).contains("ucredit=0"));
    let credits_off = fixture.run(
        &user,
        Some(serde_json::json!({"requireCharacterCredits": false})),
    );
    assert_eq!(credits_off["status"], "PASS", "{credits_off}");

    fixture.write("pwquality.conf", "minlen = 8\n");
    let short = fixture.run(&user, None);
    assert_eq!(short["status"], "FAIL");
    assert!(summary(&short).contains("minlen=8"));

    fixture.write(
        "pwquality.conf",
        "minlen = 14\nminclass = 4\nucredit = -1\nlcredit = -1\ndcredit = -1\nocredit = -1\n",
    );
    fixture.write("login.defs", "PASS_MAX_DAYS\t99999\n");
    let defs = fixture.run(&user, None);
    assert_eq!(defs["status"], "FAIL");
    assert!(summary(&defs).contains("PASS_MAX_DAYS=99999"));

    fixture.write("login.defs", "PASS_MAX_DAYS\t60\n");
    fixture.write(
        "pam.d/system-auth",
        "#password required pam_pwquality.so\npassword required pam_unix.so\n",
    );
    let no_pam = fixture.run(&user, None);
    assert_eq!(
        no_pam["status"], "WARN",
        "commented PAM line must not count: {no_pam}"
    );

    let invalid = fixture.run(&user, Some(serde_json::json!({"minimumLength": -3})));
    assert_eq!(invalid["status"], "ERROR");
    let anonymous = fixture.run(&[], None);
    assert_eq!(anonymous["status"], "WARN");
}

// ---------------------------------------------------------------- REQ-002 antivirus

fn antivirus_fixture() -> Fixture {
    let fixture = Fixture::new("req002");
    let pacman = bin(&fixture, "pacman");
    let systemctl = bin(&fixture, "systemctl");
    let replacements = vec![
        (pacman.0.as_str(), pacman.1.clone()),
        (systemctl.0.as_str(), systemctl.1.clone()),
        ("/etc/clamav/clamd.conf", fixture.path("clamd.conf")),
        ("/etc/clamd.d/scan.conf", fixture.path("missing-scan.conf")),
        ("/etc/clamd.conf", fixture.path("missing-clamd.conf")),
        ("/var/lib/clamav", fixture.path("clamav")),
    ];
    fixture.install(
        &[(
            "check.sh",
            include_str!("../../../catalog/checks/REQ-002/check.sh"),
        )],
        &replacements,
    );
    fixture.executable(
        "bin/pacman",
        "#!/usr/bin/bash\n[[ ${CLAMAV_INSTALLED:-yes} == yes ]]\n",
    );
    // INACTIVE lists units reported inactive; "unknown" simulates an unreachable systemd.
    fixture.executable(
        "bin/systemctl",
        "#!/usr/bin/bash\nif [[ ${SYSTEMD:-ok} == unknown ]]; then echo 'Failed to connect to bus'; exit 1; fi\ncase \" ${INACTIVE:-} \" in *\" $2 \"*) echo inactive; exit 3;; esac\ncase $2 in clamav-daemon.service|clamav-freshclam.service|clamav-clamonacc.service) echo active; exit 0;; esac\necho inactive; exit 3\n",
    );
    fixture.write(
        "clamd.conf",
        "OnAccessPrevention yes\nOnAccessIncludePath /home\n",
    );
    fixture.write("clamav/daily.cld", "signatures");
    fixture
}

#[test]
fn antivirus_requires_all_services_prevention_and_fresh_signatures() {
    let fixture = antivirus_fixture();
    let compliant = fixture.run(&[], None);
    assert_eq!(compliant["status"], "PASS", "{compliant}");

    let no_onaccess = fixture.run(
        &[("INACTIVE", "clamav-clamonacc.service clamonacc.service")],
        None,
    );
    assert_eq!(no_onaccess["status"], "FAIL", "{no_onaccess}");
    assert!(summary(&no_onaccess).contains("clamonacc"));

    let no_updater = fixture.run(
        &[("INACTIVE", "clamav-freshclam.service freshclam.service")],
        None,
    );
    assert_eq!(no_updater["status"], "FAIL");

    let unknown = fixture.run(&[("SYSTEMD", "unknown")], None);
    assert_eq!(unknown["status"], "WARN");

    fixture.write(
        "clamd.conf",
        "OnAccessPrevention no\nOnAccessIncludePath /home\n",
    );
    let no_prevention = fixture.run(&[], None);
    assert_eq!(no_prevention["status"], "FAIL");
    assert!(summary(&no_prevention).contains("OnAccessPrevention=no"));

    fixture.write(
        "clamd.conf",
        "OnAccessPrevention yes\nOnAccessIncludePath /home\n",
    );
    let old = SystemTime::now() - std::time::Duration::from_secs(10 * 86400);
    let file = fs::File::options()
        .write(true)
        .open(fixture.path("clamav/daily.cld"))
        .unwrap();
    file.set_modified(old).unwrap();
    let stale = fixture.run(&[], None);
    assert_eq!(stale["status"], "FAIL");
    assert!(summary(&stale).contains("10 giorni"));

    let missing = fixture.run(&[("CLAMAV_INSTALLED", "no")], None);
    assert_eq!(missing["status"], "FAIL");
}

// ---------------------------------------------------------------- REQ-006 encryption

fn encryption_fixture() -> Fixture {
    let fixture = Fixture::new("req006");
    let lsblk = bin(&fixture, "lsblk");
    let findmnt = bin(&fixture, "findmnt");
    let cryfs = bin(&fixture, "cryfs");
    let replacements = vec![
        (lsblk.0.as_str(), lsblk.1.clone()),
        (findmnt.0.as_str(), findmnt.1.clone()),
        (cryfs.0.as_str(), cryfs.1.clone()),
    ];
    fixture.install(
        &[
            (
                "check.sh",
                include_str!("../../../catalog/checks/REQ-006/check.sh"),
            ),
            (
                "luks.sh",
                include_str!("../../../catalog/checks/REQ-006/luks.sh"),
            ),
            (
                "ecryptfs.sh",
                include_str!("../../../catalog/checks/REQ-006/ecryptfs.sh"),
            ),
            (
                "cryfs.sh",
                include_str!("../../../catalog/checks/REQ-006/cryfs.sh"),
            ),
        ],
        &replacements,
    );
    fixture.executable(
        "bin/lsblk",
        "#!/usr/bin/bash\nprintf '%b' \"${LSBLK_TYPES:-disk\\npart\\n}\"\n",
    );
    fixture.executable(
        "bin/findmnt",
        "#!/usr/bin/bash\ncase \"$*\" in *'-t ecryptfs'*) printf '%b' \"${ECRYPTFS:-}\";; *'-t fuse.cryfs'*) printf '%b' \"${CRYFS:-}\";; esac\n",
    );
    fixture
}

#[test]
fn encryption_accepts_luks_ecryptfs_home_or_cryfs_and_fails_without_any() {
    let fixture = encryption_fixture();
    let none = fixture.run(&[("HOME", "/home/alice")], None);
    assert_eq!(none["status"], "FAIL", "{none}");

    let luks = fixture.run(&[("LSBLK_TYPES", "disk\\npart\\ncrypt\\n")], None);
    assert_eq!(luks["status"], "PASS");

    let home = fixture.run(
        &[("HOME", "/home/alice"), ("ECRYPTFS", "/home/alice\\n")],
        None,
    );
    assert_eq!(home["status"], "PASS");
    assert!(home["details"][1]
        .as_str()
        .unwrap()
        .contains("home utente cifrata=yes"));

    let other = fixture.run(
        &[("HOME", "/home/alice"), ("ECRYPTFS", "/srv/data\\n")],
        None,
    );
    assert!(other["details"][1]
        .as_str()
        .unwrap()
        .contains("home utente cifrata=no"));

    let cryfs = fixture.run(&[("CRYFS", "/home/alice/Vault\\n")], None);
    assert_eq!(cryfs["status"], "PASS");
    assert!(cryfs["details"][2]
        .as_str()
        .unwrap()
        .contains("1 container CryFS"));

    fs::remove_file(fixture.path("bin/findmnt")).unwrap();
    fs::remove_file(fixture.path("bin/lsblk")).unwrap();
    let unknown = fixture.run(&[], None);
    assert_eq!(unknown["status"], "WARN");
}
