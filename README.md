# BaradWatchU Client

*Nine were given to the Devs, who await their sorrowful bugs; seven to the SysAdmins, in their halls of servers; three to the Security Officers, keepers of the secret policies.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU Client audits the workstation where it runs. Audits, settings and history are local. The Server is not required. Development targets are Arch Linux and, since 2026-11-08, Windows 11 (in development, see [Windows](#windows-in-development)); macOS is not supported.

## Checks: one folder each

Every control, built-in or custom, is a folder named after its ID that contains `configuration.json` and the tool it runs:

```text
custom-checks/
└── CUSTOM-001/
    ├── configuration.json
    └── CUSTOM-001.sh
```

```json
{
  "schemaVersion": "baradwatchu.custom-checks.v1",
  "id": "CUSTOM-001",
  "name": "Password Reminder",
  "description": "What the check verifies",
  "priority": "OPTIONAL",
  "enabled": true,
  "toolPath": "./CUSTOM-001.sh",
  "arguments": [],
  "expectedSha256": "<sha256 of the tool>",
  "version": 1,
  "timeoutSeconds": 20,
  "parameters": {},
  "overrideBuiltinId": null
}
```

- Built-in checks live in `share/baradwatchu-client/catalog/checks/REQ-*/` of the installation (Windows: `catalog/checks-windows/REQ-*/`); custom checks live in `$XDG_CONFIG_HOME/baradwatchu/custom-checks/CUSTOM-*/` (default `~/.config/baradwatchu/custom-checks/`; Windows `%APPDATA%\baradwatchu\custom-checks\`). A pre-release `custom-tools` folder is renamed to `custom-checks` on first use; its contents are not changed.
- `id` must equal the folder name and start with `CUSTOM-` (uppercase letters, digits, dashes). `toolPath` is relative to the folder. `arguments` are passed directly to the tool, without a shell. `timeoutSeconds` (1–300, default 20) and `version` are optional. `parameters` is a JSON object sent to the tool on stdin as `{"requirementId":…,"parameters":{…}}`. Unknown fields are rejected. Priorities are `HIGHEST`, `HIGH`, `MEDIUM`, `LOW` and `OPTIONAL`; they do not change a result.
- A custom check prints **one** JSON object on stdout and exits with code 0: `{"status":"PASS","summary":"Readable outcome","details":["evidence"]}`. Statuses are `PASS`, `FAIL`, `WARNING` (shown as `WARN`) and `ERROR`; `details` is optional, a string or an array. It does not repeat its ID. Built-in tools additionally return their `id`.
- The tool runs in its own folder as the current user, without a shell or elevation, with a clean environment (`PATH` is `/usr/bin:/bin`, plus `~/.local/bin` for custom checks), its own process group and a bounded output. On timeout the whole process group is killed, including helpers the script started. A non-zero exit, invalid JSON or a timeout is `ERROR`, and the tool's stderr appears in the details. On Windows see [Windows](#windows-in-development) for how tools are started.
- **Integrity:** before every run the tool's SHA-256 is compared with `expectedSha256` (built-ins: the manifest embedded in the agent). On a mismatch the tool **is not executed** and the result is `ERROR`. After an intentional edit, pin the new file with `baradwatchu-agent custom accept CUSTOM-ID` or **Accept current version** in the dashboard; uploading a new file through the dashboard does the same and increments `version`. A check written by hand without `expectedSha256` stays blocked until accepted. Hash scope is the entrypoint file only.
- **Fault isolation:** a custom folder with an invalid configuration does not stop the other controls. It appears as an `ERROR` control with the exact reason (for example an unknown field) and can be deleted from the CLI or the dashboard. Folders whose name is not a valid `CUSTOM-` ID are listed as ignored by `refresh` and the dashboard.

Folders are rescanned on every `list`, audit and dashboard request; `baradwatchu-agent refresh` or **Rescan folders** in the dashboard forces it and reports invalid folders.

## Built-in checks (Arch Linux)

The criteria follow the workstation baseline in `REQUIREMENTS.md` §5. Thresholds are parameters in each `configuration.json` and can be changed with `configure` or the dashboard. When the evidence is missing or unreadable the result is `WARN`, never `PASS`; something observed as switched off is `FAIL`.

| ID | PASS when |
|---|---|
| REQ-001 | `checkupdates` (pacman-contrib) reports no pending updates in the official repositories (AUR excluded). The date of the last full upgrade from `pacman.log` is reported. It contacts Arch mirrors; timeout 90 s. |
| REQ-002 | ClamAV daemon, freshclam and clamonacc are active, `OnAccessPrevention yes` with at least one watched path, daily signatures at most 3 days old. |
| REQ-003 | UFW, firewalld or nftables shows verified operational filtering. All managed firewalls explicitly inactive is `FAIL`; unreadable rules otherwise `WARN`. |
| REQ-004 | At least one DNS-filter method is complete: dnsmasq active **and** enabled with at least `minimumDnsmasqRules` (1000) block rules, or a [HaGeZi](https://github.com/hagezi/dns-blocklists-legacy) blocklist in `/etc/hosts` (see [HaGeZi hosts lists](#hagezi-hosts-lists)). A `resolv.conf` that does not point to loopback (for example while a VPN is connected) is reported as an observation. |
| REQ-005 | Cato or WireGuard is connected. Installed but disconnected is `WARN`; neither installed is `FAIL`. |
| REQ-006 | At least one active encryption method: LUKS/dm-crypt device, mounted eCryptfs (the details say whether the home is covered) or a mounted CryFS container. This does not certify every data area. |
| REQ-007 | KDE Plasma 6 Wayland: `Autolock=true`, `Timeout` ≤ `maxTimeoutMinutes` (5), `LockGrace` ≤ `maxLockGraceSeconds` (0, password required immediately), lock on resume enabled. Other sessions are `NOT_APPLICABLE`. |
| REQ-008 | Current account maximum password age ≤ `maxPasswordAgeDays` (60) and not "never"; warning ≥ `minimumWarningDays` (10); `PASS_MAX_DAYS` in `/etc/login.defs` within the same limit; pwquality `minlen` ≥ 14, `minclass` ≥ 4, `ucredit`/`lcredit`/`dcredit`/`ocredit` = -1 (`requireCharacterCredits`), with `pam_pwquality` or `pam_passwdqc` in PAM. |
| REQ-009 | Firmware reports Secure Boot on and SetupMode off; `systemd-analyze has-tpm2` output is recorded. |

### HaGeZi hosts lists

The hosts-file method of REQ-004 (Linux and Windows) accepts only a HaGeZi list: a header starting with `# Title: HaGeZi's` whose `# Homepage:` is under `github.com/hagezi/`. HaGeZi now publishes the hosts format in the [legacy repository](https://github.com/hagezi/dns-blocklists-legacy) (`hosts/*.txt`, also the `*-compressed.txt` variants with up to 9 names per line). Several lists can be concatenated. The file must contain at least as many blocking lines (`0.0.0.0` or `::`) as the headers declare in `# Number of entries` (otherwise the list is truncated: `FAIL`) and at least `minimumHostsEntries` (10000) blocked names. A list whose `# Last modified` is older than `maxListAgeDays` (30, `0` disables the check) is `WARN`. `requireHagezi: false` accepts any blocklist of sufficient size. Host names are never reported. The check works offline: it does not download the list to compare its contents.

## Windows (in development)

Built-in checks are PowerShell scripts in `catalog/checks-windows/REQ-*/check.ps1`, listed with their hashes in the same `catalog/builtin-tools.sha256` (platform column `windows`). They run as the current user **without administrator rights**, so they use sources readable by a standard user (CIM/COM, registry, documented Win32 APIs) and not localized command output where possible.

| ID | PASS when (Windows) |
|---|---|
| REQ-001 | Windows Update (COM search, no elevation) finds no software update that is not installed and not hidden. Pending updates are `FAIL` with the count of security updates; a search that cannot complete is `WARN`. It may contact Windows Update; timeout 240 s. |
| REQ-002 | An antivirus registered in Windows Security Center is on with up-to-date signatures. For Microsoft Defender, real-time protection must be on (otherwise `FAIL`) and signatures at most `maxSignatureAgeDays` (7) old (otherwise `WARN`). No antivirus registered is `FAIL`. |
| REQ-003 | Windows Defender Firewall is on with inbound `Block` on every profile, read from the effective `ActiveStore` (local and Group Policy), or a third-party firewall registered in Security Center is on. |
| REQ-004 | A complete, recent HaGeZi list in the system hosts file (see above). Configured resolvers and the Chrome/Edge `DnsOverHttpsMode` policy are reported as observations. |
| REQ-005 | Cato Client is installed and signed by Cato Networks, `CatoClientCliAT.exe antitamper status` answers, and a Cato network adapter is `Up`. Present but not connected, or not answering, is `WARN`; not installed is `FAIL`. Which of the two Cato adapters carries the tunnel has not been verified on a connected device yet. |
| REQ-006 | BitLocker protects the system drive, read from the Explorer property `System.Volume.BitLockerProtection` (the BitLocker WMI class and `manage-bde` need administrator rights). Off, decrypting or suspended is `FAIL`; encrypting, or other fixed drives unprotected or unknown, is `WARN`. |
| REQ-007 | At least one method locks the session within `maxTimeoutMinutes` (5): the machine inactivity limit policy, a password-protected screen saver (policy values win), or sleep with sign-in required on wake for every power source of the device. A `ScreenSaverGracePeriod` above `maxLockGraceSeconds` (0) makes the screen-saver method insufficient. |
| REQ-008 | Local password policy read through the SAM API available to standard users (the data `secedit` needs elevation for): maximum age set and ≤ `maxPasswordAgeDays` (60), minimum length ≥ `minimumLength` (14), complexity on (`requireComplexity`; Windows requires 3 of 4 character classes), expiry warning ≥ `minimumWarningDays` (10, Windows default 5), and no enabled local account whose password never expires. Microsoft accounts and domain membership are `WARN` because another authority governs them. Account names are never reported. The Windows Hello PIN is not checked. |
| REQ-009 | UEFI firmware with Secure Boot on (state recorded by Windows at boot) and a TPM 2.0 (TPM Base Services). Legacy BIOS, Secure Boot off or no TPM 2.0 is `FAIL`. |

How tools are started on Windows: `.ps1` scripts through Windows PowerShell 5.1 (`%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File`, by absolute path), `.exe` files directly; other file types are `ERROR`. The execution policy bypass applies only to that process: the SHA-256 gate decides what runs. The environment is cleaned (`PATH` = System32, Windows, WBEM and the PowerShell folder, plus the standard per-user folders), no console window is shown, and the tool and every process it starts belong to a Job Object that is terminated on timeout and after the tool exits. Scripts that print non-ASCII text must be saved as UTF-8 with BOM (Windows PowerShell 5.1 reads files without BOM in the ANSI code page); the built-in scripts are, and `.gitattributes` keeps them CRLF so their hash is the same on every checkout.

Data folders on Windows (when the XDG variables are not set): settings and custom checks `%APPDATA%\baradwatchu\`, events and consent requests `%LOCALAPPDATA%\baradwatchu\state\` (runtime files in `state\run\`), audit history `%LOCALAPPDATA%\baradwatchu\cache\audit\`. The dashboard launcher is opened with Explorer, which uses the default browser.

## CLI

```sh
baradwatchu-agent list [--json]
baradwatchu-agent refresh
baradwatchu-agent enable|disable ID
baradwatchu-agent priority ID HIGHEST|HIGH|MEDIUM|LOW|OPTIONAL
baradwatchu-agent configure REQ-007 '{"maxTimeoutMinutes":5,"maxLockGraceSeconds":0}'
baradwatchu-agent check ID [--log]
baradwatchu-agent audit [--json] [--notify] [--log]
baradwatchu-agent status [--json]
baradwatchu-agent history [--json]
baradwatchu-agent history delete STAMP
baradwatchu-agent history clear --yes
baradwatchu-agent custom accept CUSTOM-ID
baradwatchu-agent custom remove CUSTOM-ID
baradwatchu-agent dashboard [--no-browser] [--open status|custom|history|notifications|settings]
baradwatchu-agent notifications [--json]
baradwatchu-agent notifications set enabled|informative on|off
baradwatchu-agent events --json [--after ID]
baradwatchu-agent consent simulate [--server ID] [--account NAME] [--account-id ID] [--device NAME] [--ttl SECONDS]
baradwatchu-agent consent list [--json]
baradwatchu-agent consent accept|reject REQUEST-ID
baradwatchu-tray [--version | --help | autostart enable|disable|status [--json]]
```

During development use `cargo run -p baradwatchu-agent -- …`. Exit codes of `audit`/`check`: 0 all passed (or disabled/not applicable), 4 at least one `WARN`, 3 at least one `FAIL`, 1 at least one `ERROR`, 2 usage error. Every audit is saved as JSON under `~/.cache/baradwatchu/audit/reports/` for `status` and the dashboard history; `--log` also writes a plain-text `.log` with tools, exit codes and diagnostics in `~/.cache/baradwatchu/audit/`. This folder is disposable: deleting it only clears the history and the last result. History from `~/.local/state/baradwatchu/audits/` is moved there automatically once. `list --json` and the dashboard API use camelCase field names. `custom accept` and `custom remove` work even when the folder's configuration is invalid. The former `workstation`, `policy validate`, `audit --policy`, `audit --format` and `audit --local-config` commands are removed; the CLI rejects them before reading any local data. Every completed audit (CLI, dashboard or tray) also appends one event to `~/.local/state/baradwatchu/events.jsonl` (last 200 kept); `events --json` is the compact state the tray polls and `notifications` shows or changes the notification preferences (`~/.config/baradwatchu/notifications.json`).

## Dashboard and notifications

`baradwatchu-agent dashboard` serves the Angular dashboard on an ephemeral `127.0.0.1` port and opens it in the browser when a desktop session is available. It does not start a service or listen on the network. Loopback is not treated as a security boundary: every `/api/` call needs a random per-session token (otherwise `401`), requests that change data must also come from the dashboard origin with a JSON body, and the `Host` header must match. The browser receives the token through a private launcher file (`$XDG_RUNTIME_DIR/baradwatchu/open-dashboard.html`, mode 0600), so it never appears on a process command line; the tab keeps it in `sessionStorage` and removes it from the address bar. A second `dashboard` call (for example from the tray) reuses the running instance recorded in `$XDG_RUNTIME_DIR/baradwatchu/dashboard.json` instead of starting another one. It uses the same settings, runner and history as the CLI.

- **Workstation status:** last audit summary (the counters filter the list), filters by outcome, search, requirements sorted by severity after an audit, per-requirement details, settings, parameters, and collapsed technical/integrity details. Historical audits can be opened from the side panel without changing the current state. The panel shows how much disk space the history uses; **✕** deletes one audit (report, log and PDF when present) and **Clear history** deletes them all, including the last result, after a confirmation. From the CLI: `history` lists audits with their size, `history delete STAMP` removes one (STAMP = completion time in Unix ms, as listed), `history clear --yes` removes all. Only `<stamp>.json|.log|.pdf` files in the history folder and its `reports/` subfolder are removed; other files are left alone.
- **Custom checks:** a separate section lists your checks with integrity state and last outcome, and offers **Check now**, **Accept current version**, **Upload new file**, **Restore built-in** (for overrides) and **Delete**. Invalid folders appear with their error and can be deleted. **New check** opens the import form: ID (next free `CUSTOM-NNN` suggested), name, description, priority, timeout, file, arguments and, under advanced options, copying metadata or overriding a built-in. The file keeps its name inside the new folder. The section also explains the folder layout and output contract.
- **Notifications:** notification preferences (desktop notifications on/off, informative ones on/off), whether the tray is running, the local event history and the consent requests. **Simulate a request** creates a local 60-second test request; the dashboard never decides a request. `#/history` opens the status page at the audit history.
- **Settings:** start of the tray at login (the same switch as **Start at login** in the tray menu; the agent runs the tray installed next to it with `autostart enable|disable|status --json`, fixed arguments, no shell, 10-second timeout), whether the tray is installed and running (Linux: live PID; Windows: the tray's exclusive lock on `tray.lock`), version, operating system, installation folder and the local data folders (settings, custom checks, events and consent, audit history, session files). Uninstalling never deletes those folders. `dashboard --open settings` or `#/impostazioni` opens it.

Development build:

```sh
cd web && npm ci && npm run build && cd ..
cargo run -p baradwatchu-agent -- dashboard
```

Native notifications are sent by the tray companion (below), also when no browser is open. Without the tray, `baradwatchu-agent audit --notify` still asks `notify-send` to show the audit summary; with the tray running this duplicates the tray notification. Dashboard audits no longer call `notify-send`.

A custom `PASS` is the tool's own claim, not an independent security proof. The Server has no audit catalog or authenticated registration yet, so it does not verify these hashes.

## Tray companion

`baradwatchu-tray` is a small separate process for the user's desktop session. It never audits by itself: it runs the agent installed next to it with a fixed set of subcommands (`events --json`, `audit --json`, `dashboard --open …`, `consent accept|reject ID --via window`), without a shell and with timeouts. The agent keeps working without the tray, and closing the tray does not stop the agent or an open dashboard. One tray runs per user (lock file `$XDG_RUNTIME_DIR/baradwatchu/tray.lock`); a second start prints that it is already active.

- **Menu:** state line and last audit, Open dashboard, Run audit (disabled while running), Show last result, Audit history, Pending requests, Recent notifications, Start at login, About, Close tray.
- **Icon:** green operational, slate blue no audit yet, amber `FAIL`/`WARN`, red `ERROR` or integrity block, blue request awaiting a decision, grey agent unreachable. The tooltip lists counts, integrity blocks and custom checks separately and states that the result of local checks is not a security certification.
- **Notifications:** one per audit, classified by its most serious aspect (integrity issue, execution error, anomalies, completed). Each event is shown once; at most three per poll, the rest summarised; an anomaly set equal to the previous audit counts as informative. Agent unreachable is notified once, after two failed polls (every 5 s), and recovery once. Preferences: all notifications off, or informative ones off; consent requests are never silenced.
- **Consent requests (preparation only):** the agent models a request for the workstation report with `requestId`, server ID, account name and ID, declared device, operation (`AUDIT_REPORT`), expiry and state. In this milestone requests can only be simulated locally (`consent simulate`, dashboard button); there is no remote request, Server authentication or cryptographic contract. The tray opens a dedicated window (zenity, or kdialog as fallback on Linux): **Accept**, **Reject**, **Decide later**. Accept is never the default button. Only an explicit Accept authorizes, and only that one request; reject, closing, "decide later", timeout and a merely shown notification authorize nothing, and an expired request cannot be accepted. Decisions are also possible with `baradwatchu-agent consent accept|reject ID`.
- **Start at login:** `baradwatchu-tray autostart enable|disable|status` or the menu checkbox. Linux writes `~/.config/autostart/baradwatchu-tray.desktop` (XDG, used by KDE Plasma); Windows uses the per-user `HKCU\…\Run` key; macOS a per-user LaunchAgent limited to the Aqua session. No administrator rights and no system service.

Libraries: [`tray-icon`](https://github.com/tauri-apps/tray-icon) 0.26 (on Linux its `ksni` StatusNotifierItem backend over D-Bus, so no GTK/AppIndicator libraries are needed), [`notify-rust`](https://github.com/hoodie/notify-rust) 4.18 (freedesktop D-Bus, Windows toasts, macOS Notification Center), and on Windows/macOS only `tao` 0.37 (event loop) and `rfd` 0.18 (message boxes). The full Tauri framework and WebViews are not used; the dashboard stays in the browser.

**Platform status.** Linux (Arch, KDE Plasma 6 on Wayland) is built and verified end to end. Windows and macOS code is type-checked and passes Clippy (`cargo check`/`cargo clippy --target x86_64-pc-windows-msvc|x86_64-pc-windows-gnu|aarch64-apple-darwin|x86_64-apple-darwin`; for macOS the Objective-C part of `mac-notification-sys` needs the Apple SDK and was not compiled). On Windows 11 the agent, its checks, the dashboard and the tray run (see [Windows](#windows-in-development)); the tray was started, polled the agent, refused a second instance and quit on a close request, but its menu, notifications and consent window have not been exercised there yet. macOS has never been run and is **not supported**. On Windows the tray is a GUI-subsystem program (no console window); `--version`, `--help` and `autostart` print to the terminal that started it or to redirected output (in PowerShell pipe it, for example `baradwatchu-tray --version | Out-String`, so PowerShell waits for it). It quits cleanly when a WM_CLOSE is posted to its invisible window "BaradWatchU Tray", which is how `install.ps1` asks it to close. On Windows/macOS the consent message box cannot close itself on expiry (a late Accept is refused by the agent).

## Build and install

The source installer builds as a normal user and uses `sudo` only to copy files into a protected prefix:

```sh
./install.sh --missing-deps                        # read-only dependency check
./install.sh --dry-run                             # show the plan
./install.sh                                       # build and install into /usr/local
./install.sh --build-only --build-dir=DIR          # build and validate the cache only
./install.sh --no-tray-autostart                   # first install without starting the tray at login
./install.sh --without-tray                        # agent and dashboard only
./install.sh -U                                    # uninstall
```

Every run starts with a summary of the effective options. The dependency check lists:

- **[REQUIRED] build tools** (Rust/Cargo ≥ 1.92 with the tray, ≥ 1.80 with `--without-tray`; C/C++ tools, make, tar, glibc, Node.js 20 ≥ 20.11.1 selected through `web/.nvmrc` and nvm when available, npm) and **[REQUIRED] runtime tools** used by the agent and checks (bash, python3, awk, sed, grep, coreutils). If any is missing the installer stops before building or changing files and prints the package command.
- **[optional] audit tools — Arch Linux only** (`checkupdates`, `systemctl`, `ufw`/`firewalld`/`nftables`, `dnsmasq`, Cato/`wg`, `lsblk`, `findmnt`, `kreadconfig6`, `pgrep`, `chage`, `systemd-analyze`, `notify-send`, `xdg-open`), each with the check that needs it. A missing one never blocks; its check reports `WARN`. Alternatives (one firewall, one VPN client) are satisfied by any one of them. On other distributions this section is skipped with a note, because the built-in checks target Arch.
- **[optional] tray companion:** `zenity` or `kdialog` for the consent window (without them the tray asks you to decide with the CLI). The tray also needs a desktop session with D-Bus and a StatusNotifierItem host (KDE Plasma; GNOME needs the AppIndicator extension).

With the tray (default) the installer adds `bin/baradwatchu-tray` and the menu entry `share/applications/baradwatchu-tray.desktop` to the manifest. **Start at login:** a first installation (no manifest yet) enables the tray's start at login for the invoking user after the files are installed (as that user, never as root); `--no-tray-autostart` skips it. A reinstall or upgrade keeps the user's current choice, which is changed from the tray menu (**Start at login**) or with `baradwatchu-tray autostart enable|disable`; `--tray-autostart` enables it anyway. Uninstall removes that user's autostart entry when it points to this installation.

**Running instances:** before files are replaced or removed, a `baradwatchu-agent` or `baradwatchu-tray` started from the same installation (matched by its executable path, never by name, for example an open dashboard) receives SIGTERM and has up to `BARADWATCHU_STOP_TIMEOUT` seconds (default 10) to exit. It is never killed: if it does not exit, the installer stops without changing anything. Other users' instances are only reported. `--dry-run` shows what would be closed.

The installer keeps its build cache, manifest-based reinstall and uninstall; user settings, custom checks and history are never touched. It does not create a system service or a package-manager package. `./install.sh --help` lists all options.

### Windows: install.ps1 and setup.exe

`install.ps1` is the Windows counterpart of `install.sh`. It installs **per user, without administrator rights** and without services. Windows blocks unsigned scripts by default, so start it through Windows PowerShell with a process-only bypass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -MissingDeps   # read-only dependency check
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -DryRun        # show the plan
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1                # build and install
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -NoTrayAutostart # first install without start at login
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -WithoutTray   # agent and dashboard only
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall     # uninstall
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Package       # build setup.exe instead
```

- **Dependencies:** [REQUIRED] Rust ≥ 1.92 with the MSVC toolchain (≥ 1.80 with `-WithoutTray`), Visual Studio Build Tools with the C++ workload, Node.js 20 ≥ 20.11.1 and npm; Windows PowerShell 5.1 at runtime. [optional] Inno Setup 6 for `-Package`, and the audit sources (PowerShell FullLanguage mode, Defender and NetSecurity cmdlets, Cato Client). The `winget` command for each missing item is printed.
- **Build:** as on Linux, a validated cache outside the source tree (default `%LOCALAPPDATA%\baradwatchu\build\baradwatchu-agent-VERSION`, `-BuildDir`, `-BuildOnly`, `-NoBuild`), with the Angular build in a private copy of `web`, a source fingerprint (changes during the build or since the cached build are refused), version checks of both executables and the same integrity check of the built-in Windows checks against `builtin-tools.sha256`.
- **Install:** default `%LOCALAPPDATA%\Programs\BaradWatchU` (`-Prefix`), layout `bin\*.exe` + `share\baradwatchu-client\{catalog,web}`, manifest `share\baradwatchu-source\baradwatchu-agent.manifest` with the SHA-256 of every file. Unmanaged or locally changed files are never overwritten or removed; symbolic links and junctions in the path are refused. Start menu entries **BaradWatchU Dashboard** and **BaradWatchU Tray** are created in the user's Start menu and recorded in the manifest. Start at login follows the same rule as on Linux: enabled on a first installation (`HKCU\…\Run`, opt-out `-NoTrayAutostart`), kept as the user left it on a reinstall (`-TrayAutostart` enables it anyway). Uninstall also removes the tray's `HKCU\…\Run` entry if it points to this installation and the folders that become empty.
- **Running instances:** programs started from the same installation (matched by executable path) are asked to close before files change: a short-lived helper posts a close request (WM_CLOSE) to the tray's window and sends Ctrl+C on the console of agent and dashboard (never on the installer's console). They get up to `BARADWATCHU_STOP_TIMEOUT` seconds (default 10) and are never killed: if one is still running, the installer stops without changing anything. A dashboard started from your own terminal shares that console, so other programs attached to it receive the same Ctrl+C.
- **Setup (`-Package`):** stages the same validated build and compiles `packaging\windows\baradwatchu-client.iss` with Inno Setup 6 into `BaradWatchU-Client-VERSION-setup.exe` (default `BUILDDIR\dist`, `-OutputDir`), printing its SHA-256. The setup installs per user into `%LOCALAPPDATA%\Programs\BaradWatchU` without administrator rights, in Italian or English, with Start menu entries, a "start the tray at login" task (selected by default and offered only on a first installation, so an upgrade keeps the user's choice; silent opt-out `/MERGETASKS="!trayautostart"`) and an uninstaller in **Settings › Apps**; upgrades replace the same installation. Setup and uninstaller refuse to run while a BaradWatchU program of that folder is running (exit code 7 / 1, nothing changed) and never terminate it: close the dashboard and the tray first. It supports the standard silent switches (`/VERYSILENT /SUPPRESSMSGBOXES`, `/DIR=`). `install.ps1` refuses a folder owned by the setup, so use one method per folder. The setup is **not code-signed**: SmartScreen shows an unknown-publisher warning until the organisation signs it (for example with `signtool`), which is not automated here.

## Development checks

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cd web && npm test && npm run build
```

On Windows the same commands work from a Developer shell with the MSVC toolchain (Visual Studio Build Tools, C++ workload) and Node.js 20; for installation use `install.ps1` (see above). Test tools are shell scripts on Unix and PowerShell scripts on Windows; the shell-only runner tests and the built-in script suites run on Unix only. Tests point every XDG directory at private temporary folders and serialise environment changes, so they run in parallel and never touch the developer's configuration or history. Built-in check scripts are tested with fixture files and stub commands (`tests/workstation_criteria.rs`, `tests/req003_firewall.rs`, `tests/req004_005_methods.rs`). Tray logic (icon state, notification policy, snapshot contract) is unit-tested without a GUI in `crates/tray/src/model.rs`.

## Current limits

The legacy architecture (policy evaluation, native Fedora/Arch collectors, adapters, workstation registry, `policies/`, `scripts/`, `configs/`) was removed on 2026-11-07; the source tree contains only the folder-based catalog, runner, CLI and dashboard. Some checks are intentionally conservative and return `WARN`; real-host validation beyond the developer's Arch workstation is still pending. There is no scheduler/daemon, Server communication, remote policy or remote consent request, dynamic tool download, macOS audit implementation or automatic remediation. On Windows there is a per-user installer and an unsigned per-user setup, but no service, code signing or per-machine installation yet; its checks run without administrator rights, so BitLocker details, full Secure Boot/TPM queries and `secedit` data are out of reach, and the Cato adapter that signals a connection has not been verified on a connected device. Consent decisions are bound to the local user: any process of the same user can call `consent accept`, exactly as it can read that user's files.
