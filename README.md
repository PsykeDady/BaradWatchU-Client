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
- **Integrity:** before every run the tool's SHA-256 is compared with `expectedSha256` (built-ins: the manifest embedded in the agent). On a mismatch the tool **is not executed** and the result is `ERROR`. After an intentional edit, pin the new file with `baradwatchu-agent custom accept CUSTOM-ID` or **Accept current version** in the dashboard; uploading a new file through the dashboard does the same and increments `version`. A check written by hand without `expectedSha256` stays blocked until accepted. For custom checks the hash covers the entrypoint file only; built-in checks are verified file by file (see [Providers and installation integrity](#providers-and-installation-integrity)).
- **Fault isolation:** a custom folder with an invalid configuration does not stop the other controls. It appears as an `ERROR` control with the exact reason (for example an unknown field) and can be deleted from the CLI or the dashboard. Folders whose name is not a valid `CUSTOM-` ID are listed as ignored by `refresh` and the dashboard.
- **Local changes are always custom checks.** Enabling/disabling, priority and parameters of a built-in check are changed only through a CUSTOM folder that overrides it, so every local change is visible ("Configuration changed by CUSTOM-…" in the dashboard, `isOverride`/`configurationOverride` in reports). `enable|disable`, `priority`, `configure` and the dashboard controls write a **configuration-only override** `CUSTOM-<ID>/configuration.json` (`overrideBuiltinId`, no `toolPath`, `expectedSha256` or `arguments`): the official files still run and stay under the manifest check, with the folder's `enabled`, `priority` and `parameters`. Going back to the official values, or **Restore** in the dashboard, deletes that folder. On a custom check the same commands edit its own `configuration.json`. A script override (with `toolPath`) replaces the built-in entirely. The former `settings.json` is no longer read; if present, `refresh` and the dashboard report it as an ignored file that can be deleted.

Folders are rescanned on every `list`, audit and dashboard request; `baradwatchu-agent refresh` or **Rescan folders** in the dashboard forces it and reports invalid folders.

## Providers and installation integrity

**Providers.** A built-in requirement can have several interchangeable implementations (providers), one script per product in `providers/` of its check folder, declared in `configuration.json` under `providers` (`name`, `toolPath`, `parameters`, optional `timeoutSeconds`) instead of `toolPath`. Today only REQ-002 (antivirus) uses them: `clamav` and `bitdefender-gravityzone` on Linux, `defender`, `bitdefender-gravityzone` and `security-center` on Windows. Every provider runs at every audit and is reported on its own (JSON `extensions.providers`, dashboard, PDF). The requirement parameter `acceptedProviders` decides the outcome:

- empty (default for every built-in): one provider with `PASS` is enough; without one the result is `ERROR` if a provider failed to run, otherwise `WARN` if one was inconclusive, otherwise `FAIL`;
- not empty, e.g. `["bitdefender-gravityzone"]`: every listed provider is mandatory and must `PASS`; the worst of them decides (`ERROR` > `FAIL` > `WARN`). Unlisted providers still run and are shown as optional;
- an unknown ID or a value that is not a list is `ERROR` and no provider runs.

`providerParameters` overrides a provider's defaults, e.g. `{"acceptedProviders":["bitdefender-gravityzone"],"providerParameters":{"bitdefender-gravityzone":{"maxSignatureAgeDays":1}}}`. Set them from the dashboard (REQ-002 parameters) or with `baradwatchu-agent configure REQ-002 '…'`: both create the configuration-only override `CUSTOM-REQ-002`. Custom checks cannot declare providers; a custom check that replaces REQ-002 replaces it as a whole.

The Bitdefender GravityZone provider is written from Bitdefender's public documentation and is **not verified on a managed endpoint**. Linux: install folder `/opt/bitdefender-security-tools`, `bdsec*` systemd units (main `bdsec.service` active and enabled), `bduitool get ps` for on-access status and last update (it requires root, so an unprivileged audit reports that status as not verifiable: `WARN` at best, never `PASS`). Windows: Bitdefender Endpoint Security Tools uninstall entry or `product.console.exe`, services whose name contains "Bitdefender", Windows Security Center state, `product.console.exe /c GetUpdateStatus antivirus`. Parameters: `maxSignatureAgeDays` (3), `expectedCompanyId` (empty: not checked; when set it is reported as not verifiable until a reliable source is confirmed).

**Installation integrity.** `catalog/builtin-tools.sha256` lists the SHA-256 of **every file** of every built-in check folder (scripts, providers, helpers, `configuration.json`), one line per file, for Linux and Windows. It is embedded in the agent at build time: editing the installed copy changes nothing. At every audit the agent hashes the installed built-in files, reports each one in the JSON (`installation`: state `VERIFIED`, `MODIFIED`, `MISSING`, `UNEXPECTED` or `UNSAFE`, expected and actual hash, plus the manifest hash) and shows a summary line in the CLI, dashboard and PDF. A built-in control whose folder differs from the manifest is `ERROR` and is **not executed**; a deleted built-in folder appears as an `ERROR` control. Any difference raises an `INTEGRITY_ISSUE` event. Custom checks are not in the manifest and keep their own entrypoint pin. The per-file hashes are meant for the future Server check of the installation (not implemented yet); a modified agent binary can still lie about them. After editing a built-in check run `scripts/update-builtin-hashes.sh`: it refreshes `expectedSha256` of entrypoint checks and rewrites the manifest.

## Built-in checks (Arch Linux)

The criteria follow the workstation baseline in `REQUIREMENTS.md` §5. Thresholds are parameters in each `configuration.json` and can be changed with `configure` or the dashboard, which create a visible `CUSTOM-<ID>` configuration override. When the evidence is missing or unreadable the result is `WARN`, never `PASS`; something observed as switched off is `FAIL`.

| ID | PASS when |
|---|---|
| REQ-001 | `checkupdates` (pacman-contrib) reports no pending updates in the official repositories (AUR excluded). The date of the last full upgrade from `pacman.log` is reported. It contacts Arch mirrors; timeout 90 s. |
| REQ-002 | Provider-based (see [Providers](#providers-and-installation-integrity)). `clamav`: ClamAV daemon, freshclam and clamonacc are active, `OnAccessPrevention yes` with at least one watched path, daily signatures at most 3 days old. `bitdefender-gravityzone`: see above. |
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

Built-in checks are PowerShell scripts in `catalog/checks-windows/REQ-*/check.ps1` (REQ-002: `providers/*.ps1`), listed with their hashes in the same `catalog/builtin-tools.sha256` (platform column `windows`). They run as the current user **without administrator rights**, so they use sources readable by a standard user (CIM/COM, registry, documented Win32 APIs) and not localized command output where possible.

| ID | PASS when (Windows) |
|---|---|
| REQ-001 | Windows Update (COM search, no elevation) finds no software update that is not installed and not hidden. Pending updates are `FAIL` with the count of security updates; a search that cannot complete is `WARN`. It may contact Windows Update; timeout 240 s. |
| REQ-002 | Provider-based. `defender`: Microsoft Defender is the active engine with real-time protection on (otherwise `FAIL`) and signatures at most `maxSignatureAgeDays` (7) old (otherwise `WARN`). `security-center`: any antivirus registered in Windows Security Center is on with up-to-date signatures; none registered or all off is `FAIL`. `bitdefender-gravityzone`: see [Providers](#providers-and-installation-integrity). The provider scripts have not been run on Windows yet. |
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
baradwatchu-agent identity generate [--yes] | identity reset [--yes]
baradwatchu-agent identity show [--json] | identity export [--output FILE]
baradwatchu-agent trust list [--json] | trust show SERVER-ID [--json]
baradwatchu-agent trust import FILE [--fingerprint SHA256:…]
baradwatchu-agent trust revoke SERVER-ID [--yes] | trust clear [--yes]
baradwatchu-agent remote enable | remote disable | remote status [--json]
baradwatchu-agent service run          # system service (systemd, launchd, Windows Service)
baradwatchu-tray [--version | --help | autostart enable|disable|status [--json]]
```

During development use `cargo run -p baradwatchu-agent -- …`. Exit codes of `audit`/`check`: 0 all passed (or disabled/not applicable), 4 at least one `WARN`, 3 at least one `FAIL`, 1 at least one `ERROR`, 2 usage error. On Linux, every audit always saves its JSON report under `~/.cache/baradwatchu/audit/reports/`; Windows uses `%LOCALAPPDATA%\baradwatchu\cache\audit\reports\`. `audit --json` prints only JSON but still creates the PDF. The report includes the agent version and SHA-256, plus the PDF status and path. Cached JSON also retains each requirement’s description, summary and execution details, so the PDF uses the audit snapshot. Every audit automatically creates an A4 PDF in the `baradwatchu/audit/` cache folder; if PDF generation fails, the audit completes and returns the reason. `--log` also writes a plain-text `.log` with the client hash, tools, exit codes, diagnostics and PDF path or error. PDF theme definitions are JSON files in `~/.config/baradwatchu/themes/` on Linux and `%APPDATA%\baradwatchu\themes\` on Windows; `report-theme.json` stores the selected theme ID. The built-in BaradWatchU theme is always available. Settings or `baradwatchu-agent report-theme use ID` selects a theme; `baradwatchu-agent report-theme list` lists them. The cache folder is disposable: deleting it only clears the history and the last result. History from `~/.local/state/baradwatchu/audits/` is moved there automatically once. `list --json` and the dashboard API use camelCase field names. `custom accept` and `custom remove` work even when the folder's configuration is invalid. The former `workstation`, `policy validate`, `audit --policy`, `audit --format` and `audit --local-config` commands are removed; the CLI rejects them before reading any local data. Every completed audit (CLI, dashboard or tray) also appends one event to `~/.local/state/baradwatchu/events.jsonl` (last 200 kept); `events --json` is the compact state the tray polls and `notifications` shows or changes the notification preferences (`~/.config/baradwatchu/notifications.json`).

## Dashboard and notifications

`baradwatchu-agent dashboard` serves the Angular dashboard on an ephemeral `127.0.0.1` port and opens it in the browser when a desktop session is available. It does not start a service or listen on the network. Loopback is not treated as a security boundary: every `/api/` call needs a random per-session token (otherwise `401`), requests that change data must also come from the dashboard origin with a JSON body, and the `Host` header must match. The browser receives the token through a private launcher file (`$XDG_RUNTIME_DIR/baradwatchu/open-dashboard.html`, mode 0600), so it never appears on a process command line; the tab keeps it in `sessionStorage` and removes it from the address bar. A second `dashboard` call (for example from the tray) reuses the running instance recorded in `$XDG_RUNTIME_DIR/baradwatchu/dashboard.json` instead of starting another one. It uses the same settings, runner and history as the CLI.

- **Workstation status:** last audit summary (the counters filter the list), filters by outcome, search, requirements sorted by severity after an audit, per-requirement details, settings, parameters, and collapsed technical/integrity details. The agent version and SHA-256 are shown with the PDF path; **Open PDF** opens the report downloaded from the local cache. Historical audits can be opened from the side panel without changing the current state. The panel shows how much disk space the history uses; **✕** deletes one audit (report, log and PDF when present) and **Clear history** deletes them all, including the last result, after a confirmation. From the CLI: `history` lists audits with their size, `history delete STAMP` removes one (STAMP = completion time in Unix ms, as listed), `history clear --yes` removes all. Only `<stamp>.json|.log|.pdf` files in the history folder and its `reports/` subfolder are removed; other files are left alone.
- **Custom checks:** a separate section lists your checks with integrity state and last outcome, and offers **Check now**, **Accept current version**, **Upload new file**, **Restore built-in** (for overrides) and **Delete**. Invalid folders appear with their error and can be deleted. **New check** opens the import form: ID (next free `CUSTOM-NNN` suggested), name, description, priority, timeout, file, arguments and, under advanced options, copying metadata or overriding a built-in. The file keeps its name inside the new folder. You can also import a JSON package exported by BaradWatchU Server; it pre-fills the form and tool file for review, then the Client calculates and pins the tool hash after explicit confirmation. The section also explains the folder layout and output contract.
- **Notifications:** notification preferences (desktop notifications on/off, informative ones on/off), whether the tray is running, the local event history and the consent requests. **Simulate a request** creates a local 60-second test request; the dashboard never decides a request. `#/history` opens the status page at the audit history.
- **Settings:** start of the tray at login (the same switch as **Start at login** in the tray menu; the agent runs the tray installed next to it with `autostart enable|disable|status --json`, fixed arguments, no shell, 10-second timeout), PDF theme (PNG/JPEG logo path, text, background and accent colors; badge colors stay fixed), whether the tray is installed and running (Linux: live PID; Windows: the tray's exclusive lock on `tray.lock`), version, operating system, installation folder and the local data folders (settings, custom checks, events and consent, audit history, session files), plus the Client identity and the trusted Servers (see [Identity and trusted Servers](#identity-and-trusted-servers)). Uninstalling never deletes those folders. `dashboard --open settings` or `#/impostazioni` opens it.
- **Language:** Settings offers `System default`, `Italiano`, and `English`; the per-user choice is stored in `language.json` and shared by the agent and tray. System default detects Italian from the Windows UI language, macOS preferred interface languages (`AppleLanguages`, with `AppleLocale` as fallback), or POSIX locale variables (including GNU `LANGUAGE` lists); missing or unsupported locales fall back to English (`en_EN`). The shared JSON catalogs are `crates/messages/locales/en_EN.json` and `it_IT.json`; they are embedded in the binaries at build time. A missing translation displays its key as the label. CLI, dashboard, tray and PDF interface messages use this catalog. Audit evidence and custom tool output remain verbatim. Windows/macOS runtime coverage is not verified in the current Linux environment.

Development build:

```sh
cd web && npm ci && npm run build && cd ..
cargo run -p baradwatchu-agent -- dashboard
```

Native notifications are sent by the tray companion (below), also when no browser is open. Without the tray, `baradwatchu-agent audit --notify` still asks `notify-send` to show the audit summary; with the tray running this duplicates the tray notification. Dashboard audits no longer call `notify-send`.

A custom `PASS` is the tool's own claim, not an independent security proof. The Server has no audit catalog or authenticated registration yet, so it does not verify these hashes.

## Tray companion

`baradwatchu-tray` is a small separate process for the user's desktop session. It never audits by itself: it runs the agent installed next to it with a fixed set of subcommands (`events --json`, `audit --json`, `dashboard --open …`, `consent accept|reject ID --via window`, and the long-running `remote link --watch-stdin` for [remote audit requests](#remote-audit-requests)), without a shell and with timeouts. The agent keeps working without the tray, and closing the tray does not stop the agent or an open dashboard. One tray runs per user (lock file `$XDG_RUNTIME_DIR/baradwatchu/tray.lock`); a second start prints that it is already active.

- **Menu:** state line and last audit, Open dashboard, Run audit (disabled while running), Show last result, Audit history, Pending requests, Recent notifications, Start at login, About, Close tray, Quit BaradWatchU.
- **Quit BaradWatchU** (tray menu, the **Quit BaradWatchU** button in the dashboard header, or `baradwatchu-agent quit`) closes this user's dashboard and tray. The dashboard stops through its own authenticated API (`POST /api/shutdown` with body exactly `{"confirm":true}`, same token, `Host`, `Origin` and JSON checks as every other change). The tray is asked to close through a file in the private runtime folder (`tray-quit-request`); it reads it at its next poll (within 5 s), ignores requests older than its own start and removes it. The system service, its Server connections and other users' programs are never touched. Upgrades use the same command to close the running dashboard and tray before the setup.
- **Icon:** green operational, slate blue no audit yet, amber `FAIL`/`WARN`, red `ERROR` or integrity block, blue request awaiting a decision, grey agent unreachable. The tooltip lists counts, integrity blocks and custom checks separately and states that the result of local checks is not a security certification.
- **Notifications:** one per audit, classified by its most serious aspect (integrity issue, execution error, anomalies, completed). Each event is shown once; at most three per poll, the rest summarised; an anomaly set equal to the previous audit counts as informative. Agent unreachable is notified once, after two failed polls (every 5 s), and recovery once. Preferences: all notifications off, or informative ones off; consent requests are never silenced.
- **Consent requests:** the agent models a request for the workstation report with `requestId`, server ID, account name and ID, declared device, operation (`AUDIT_REPORT`), expiry and state. Requests are either simulated locally (`consent simulate`, dashboard button; nothing is sent) or come from a trusted Server authenticated by mutual TLS (source `REMOTE_SERVER`, see [Remote audit requests](#remote-audit-requests)); the remote prompt names the Server, its ID and key fingerprint. On Windows the tray shows the request as a notification with **Accept** and **Reject** buttons ("reminder" toast: it stays on screen until answered or dismissed; no second plain notification is sent); if the notification cannot be shown, it falls back to the message box. On Linux and macOS the tray opens a dedicated window (zenity, or kdialog as fallback on Linux; NSAlert on macOS): **Accept**, **Reject**, **Decide later**. Accept is never the default button. A pending request can also be decided in the dashboard's **Notifications** tab (**Accept** / **Reject** next to it; the list refreshes every 5 seconds; `POST /api/consent/decide` with body exactly `{"requestId": "...", "accept": true|false}`, same token, `Host`, `Origin` and JSON checks as every other change) or with `baradwatchu-agent consent accept|reject ID`. The decision records its channel (`decidedVia`: `CONSENT_WINDOW`, `NOTIFICATION`, `DASHBOARD`, `CLI`). Only an explicit Accept authorizes, and only that one request; reject, closing or dismissing the notification, "decide later", timeout and a merely shown notification authorize nothing, an already decided request cannot be decided again, and an expired request cannot be accepted (a late click on a notification still on screen is refused).
- **Start at login:** `baradwatchu-tray autostart enable|disable|status` or the menu checkbox. Linux writes `~/.config/autostart/baradwatchu-tray.desktop` (XDG, used by KDE Plasma); Windows uses the per-user `HKCU\…\Run` key; macOS a per-user LaunchAgent limited to the Aqua session. No administrator rights; the system service for remote requests is managed by the main installer (see **Build and install**).

Libraries: [`tray-icon`](https://github.com/tauri-apps/tray-icon) 0.26 (on Linux its `ksni` StatusNotifierItem backend over D-Bus, so no GTK/AppIndicator libraries are needed), [`notify-rust`](https://github.com/hoodie/notify-rust) 4.18 (freedesktop D-Bus, Windows toasts, macOS Notification Center), and on Windows/macOS only `tao` 0.37 (event loop) and `rfd` 0.18 (message boxes). The full Tauri framework and WebViews are not used; the dashboard stays in the browser.

**Platform status.** Linux (Arch, KDE Plasma 6 on Wayland) is built and verified end to end. Windows and macOS code is type-checked and passes Clippy (`cargo check`/`cargo clippy --target x86_64-pc-windows-msvc|x86_64-pc-windows-gnu|aarch64-apple-darwin|x86_64-apple-darwin`; for macOS the Objective-C part of `mac-notification-sys` needs the Apple SDK and was not compiled). On Windows 11 the agent, its checks, the dashboard and the tray run (see [Windows](#windows-in-development)); the tray was started, polled the agent, refused a second instance and quit on a close request, but its menu, notifications and consent window have not been exercised there yet. macOS has never been run and is **not supported**. On Windows the tray is a GUI-subsystem program (no console window); `--version`, `--help` and `autostart` print to the terminal that started it or to redirected output (in PowerShell pipe it, for example `baradwatchu-tray --version | Out-String`, so PowerShell waits for it). It quits cleanly when a WM_CLOSE is posted to its invisible window "BaradWatchU Tray" (used by `install.ps1 -Uninstall` for a former per-user installation) or through **Quit BaradWatchU**. On Windows the consent notification, and the macOS message box, cannot close themselves on expiry or when the request was decided elsewhere (a late click is refused by the agent).

## Identity and trusted Servers

Optional and local. These keys authenticate the Client and the Servers in [remote audit requests](#remote-audit-requests) (Milestone 2, off by default). Trust never comes from the network: public keys are exchanged beforehand through verified external channels and imported locally.

- **Why generate keys.** An Ed25519 key pair will let a BaradWatchU Server recognise this workstation and send it an audit request. Even a trusted Server can only *present* a request: every remote audit will have to be accepted by the user through the existing notification/consent window. An unknown or revoked Server cannot request anything. Without keys the Client works normally (local audits, dashboard, history, PDF).
- **Only on request.** Keys are generated only by `identity generate` or **Generate identity** in Settings, after the mandatory confirmation message. Installation, start-up, audits and updates never create them. Missing or damaged files are never regenerated: the status becomes *damaged* and the full reset is the explicit recovery. A second `generate` is refused and points to the reset.
- **Public vs private key.** The public key (standard base64 of 32 bytes), its fingerprint and the Device ID can be shared. The private key stays in `private.key` on this device (owner-only file `0600` in `0700` folders on Linux/macOS, checked at every use; on Windows a protected ACL for the user and SYSTEM only, set at creation) and is never shown, copied, exported, returned by the dashboard API, or written to logs, audits, PDFs or notifications. Signing is refused if the key files are accessible to other users.
- **Formats.** Fingerprint = `SHA256:` + 64 lowercase hex digits of SHA-256 over the 32 raw public key bytes. Device ID = `BWU-XXXX-XXXX-XXXX-XXXX` (first 64 bits of SHA-256 over `baradwatchu.device-id.v1\0` + public key); Server ID = `SRV-…`, derived the same way from `baradwatchu.server-id.v1\0`. Export and import use the versioned JSON `baradwatchu.public-identity.v1`: `{schemaVersion, role: "client"|"server", id?, name?, algorithm: "Ed25519", publicKey, fingerprint?, createdAtUnixMs?}` (unknown fields refused); a declared `id` or `fingerprint` is recomputed from the key and must match.
- **Exchanging the public key.** `identity export [--output FILE]` or **Export public identity (.json)** produce that file; **Copy public key** copies the full key even while it is hidden behind the eye icon (hidden by default). Hand it over in person or through a secure channel and confirm the fingerprint with the Server's administrator over an independent channel (phone, in person).
- **Importing a trusted Server.** Only from a local file received out of band (USB, CD, PGP-signed message…): `trust import FILE` or **Import Server key…** in Settings. The Client shows name, Server ID and fingerprint and imports only after an explicit confirmation (CLI: type "yes", or pass `--fingerprint` with the value you verified, required without a terminal; dashboard: the verification checkbox, and the agent re-checks that the confirmed fingerprint matches the file). Refused: malformed files, Client identities (`role: "client"`), weak keys, the Client's own key, keys already present, a name already used by a trusted Server, revoked keys. The Client never accepts a key presented by a remote device: no trust on first use, no network pairing.
- **Managing Servers.** `trust list|show|revoke` and the **Trusted Servers** panel (details, **Revoke**). A revocation keeps the entry (status `REVOKED`, revocation time) so the key cannot be imported again silently.
- **Remove all trusted Servers** (`trust clear`) forgets every Server, recorded revocations included, and keeps the Client keys, Device ID and fingerprint. It is not a reset.
- **Full reset** (`identity reset`, **Full reset…**): only if you suspect the key is compromised or you are initializing the PC for a new Server. It replaces the key pair (new Device ID and fingerprint), empties the trust store and expires pending consent requests; afterwards the new public key must be exchanged again out of band with every Server. Confirmation: type `RESET` (CLI and dashboard); without a terminal, `--yes` is required.
- **Suspected compromise.** Run the full reset, give the new public key to the Servers you still use and ask their administrators to revoke the old key/Device ID on their side; until they do, a stolen private key can still impersonate this workstation towards them.
- **Consistency and recovery.** Everything lives in `$XDG_STATE_HOME/baradwatchu/identity/` (Windows `%LOCALAPPDATA%\baradwatchu\state\identity\`, not roaming). Under an exclusive lock, each change writes new files (`key-…/`, `trust-….json`), flushes them, then atomically replaces `state.json`, the single commit point; files it no longer references are removed by the same change or by the next one. An interruption leaves either the previous or the new state, never a new key with the old trust store; a missing or corrupted `state.json` is reported as damaged and nothing is deleted or adopted until the full reset. Concurrent generations produce exactly one identity.
- **Limits of local protection.** File permissions stop other users, not processes running as the same user (they can read the private key like any file of that user), administrators/root, backups or a compromised endpoint. Old private keys are overwritten before deletion on a best-effort basis, but SSDs, copy-on-write filesystems, snapshots and backups may keep their bytes. No TPM, Secure Enclave or OS key store is used yet. On Windows the ACL is set at creation and not re-verified (shown as "not verified").
- **Dashboard API** (same token, `Host`, `Origin` and JSON checks as the rest of the bridge): `GET /api/identity`; `POST /api/identity/generate|reset`, `/api/trust/clear`, `/api/trust/revoke/SERVER-ID` with body exactly `{"confirm":true}`; `POST /api/trust/preview` `{content}` and `/api/trust/import` `{content, confirmFingerprint}`. No response contains private key material.
- **For later milestones** (`crates/agent/src/identity.rs`): `public_identity`, `sign`, `verify_signature` (strict Ed25519), `trusted_server_for_key` (matches the full key, never a name, address or declared ID) and `check_remote_request`, whose best outcome is `RequiresLocalConsent`: no outcome authorizes running an audit.
- **Exit codes** of `identity`/`trust`: 0 done, 1 cancelled by the user (nothing changed), 2 usage error or failure.

## Remote audit requests

A trusted BaradWatchU Server may ask for an audit, but the Client runs it only after the user accepts in the tray's local consent window (120 seconds). No remote command execution, automatic acceptance, or network key enrollment is provided. The public identity JSON files are exchanged and imported on both systems beforehand; their Ed25519 keys are the mutual TLS credentials. See [the remote protocol](docs/remote-protocol.md).

- **Components.** The system installation runs `baradwatchu-agent service run` (systemd, LaunchDaemon or Windows service). It opens outbound connections for registered users, keeps request records, and relays requests to the per-user `remote link` started by the tray. Only that linked agent can show consent and run the normal audit engine. The service never audits.
- **Per-user setup.** Generate the Client identity, import the Server public identity in Settings, and enable remote requests with `remote enable` or on the **Active connections** tab. The service registers the user's owner-only identity folder through OS-authenticated local IPC. Several users on one machine can register independently. After `identity reset`, run `remote enable` again. `remote disable` removes that user's registration.
- **Connection.** On **Active connections**, enter the Server DNS name or IP and tunnel port (default `7445`) beside a trusted Server and select **Start**. The Client initiates a persistent TLS 1.3 connection and retries after network loss. **Stop** closes it and persists the stopped state; **Refresh / repair** restarts it and applies a changed address. These controls operate per user and need no administrator prompt. The Client has no inbound listener or LAN discovery. The Server dashboard in LOCAL mode remains loopback-only; its separate tunnel port must be reachable from the Client.
- **Trust and status.** The Client pins the imported Server key; the Server accepts only an imported Client key. The Server fleet shows **Connected** only for an authenticated live channel. The Client tab shows each trusted Server's connection and error state. Names and addresses are informational, never authorization. `remote status [--json]` reports service, identity, registration, linked session and connection counts.
- **Audit flow.** The Server sends create/status/result frames on the tunnel. Duplicate request IDs never execute twice. No linked tray/session returns `UNAVAILABLE`; an audit or consent request already in progress returns `BUSY`. Revocation and identity reset withdraw pending consent, and subsequent tunnel requests are rejected. Results are Client-produced and remain in service memory for one hour; the user's local history persists separately.
- **Installation.** Use the system installation for the service: Linux `./install.sh`, Windows `install.ps1` (always system-wide), or the manual macOS service installer. Linux per-user installations (`--local`) have no service. Installers do not generate keys or turn on connections. The tray remains necessary for consent. The new outbound tunnel has been source-built on Linux; actual service, Windows and macOS runtime behavior remains unverified.

## Build and install

The source installer builds as a normal user and uses `sudo` only to copy files into a protected prefix:

```sh
./install.sh --missing-deps                        # read-only dependency check
./install.sh --dry-run                             # show the plan
./install.sh                                       # build and install into /usr/local
./install.sh --build-only --build-dir=DIR          # build and validate the cache only
./install.sh --no-tray-autostart                   # first install without starting the tray at login
./install.sh --without-tray                        # agent and dashboard only
./install.sh --local                              # per-user installation in ~/.local (no service)
./install.sh -U                                    # uninstall (service included; data kept)
```

Every run starts with a summary of the effective options. The dependency check lists:

- **[REQUIRED] build tools** (Rust/Cargo ≥ 1.92 with the tray, ≥ 1.80 with `--without-tray`; C/C++ tools, make, tar, glibc, Node.js 20 ≥ 20.11.1 selected through `web/.nvmrc` and nvm when available, npm) and **[REQUIRED] runtime tools** used by the agent and checks (bash, python3, awk, sed, grep, coreutils). If any is missing the installer stops before building or changing files and prints the package command.
- **[optional] audit tools — Arch Linux only** (`checkupdates`, `systemctl`, `ufw`/`firewalld`/`nftables`, `dnsmasq`, Cato/`wg`, `lsblk`, `findmnt`, `kreadconfig6`, `pgrep`, `chage`, `systemd-analyze`, `notify-send`, `xdg-open`), each with the check that needs it. A missing one never blocks; its check reports `WARN`. Alternatives (one firewall, one VPN client) are satisfied by any one of them. On other distributions this section is skipped with a note, because the built-in checks target Arch.
- **[optional] tray companion:** `zenity` or `kdialog` for the consent window (without them the tray asks you to decide with the CLI). The tray also needs a desktop session with D-Bus and a StatusNotifierItem host (KDE Plasma; GNOME needs the AppIndicator extension).

With the tray (default) the installer adds `bin/baradwatchu-tray` and the menu entry `share/applications/baradwatchu-tray.desktop` to the manifest. **Start at login:** a first installation (no manifest yet) enables the tray's start at login for the invoking user after the files are installed (as that user, never as root); `--no-tray-autostart` skips it. A reinstall or upgrade keeps the user's current choice, which is changed from the tray menu (**Start at login**) or with `baradwatchu-tray autostart enable|disable`; `--tray-autostart` enables it anyway. Uninstall removes that user's autostart entry when it points to this installation.

**Running instances:** before files are replaced or removed, a `baradwatchu-agent` or `baradwatchu-tray` started from the same installation (matched by its executable path, never by name, for example an open dashboard) receives SIGTERM and has up to `BARADWATCHU_STOP_TIMEOUT` seconds (default 10) to exit. It is never killed: if it does not exit, the installer stops without changing anything. Other users' instances are only reported. `--dry-run` shows what would be closed.

**Installation modes.** The installation mode decides what is installed; install, update and uninstall always respect it.

| Mode | When | Contents |
|---|---|---|
| **System** (standard distribution) | a prefix that needs root (default `/usr/local`); on Windows always (`install.ps1` / setup) | the complete Client: agent, dashboard, tray and the **system service** that opens outbound remote mTLS tunnels |
| **Per user** (local, Linux only) | `--local`, or a `--prefix` writable without root | agent, dashboard, tray, identity, trust store, local audits and reports, without administrator rights; **no system service, no remote communication** |

A per-user installation is not a broken one: it is meant for development, tests and diagnostics, and everything local works. There is no per-user variant of the service, and none on Windows. The plan at the top of every run shows the `mode` and `service` lines; `--dry-run` changes nothing.

**System service** (remote audit requests, Milestone 2). `install.sh` is the single entry point: in the step that already runs with `sudo` it calls `packaging/service/install-service.sh`, its internal component (that script can still be run by hand, and is the way on macOS). Building, the dependency check and the tray autostart stay unprivileged.

- **Always in the system installation.** Installation and every update install or update the systemd unit `baradwatchu-agent.service` (root, enabled at boot, restarted on failure); also an existing installation made before the service gets it at its next update. There are no options to leave it out: whether it is *used* is decided by each user's `remote enable` registration and Server connection controls. One service per machine: if it belongs to another installation, the installer stops before changing anything and says how to remove it. The system installation needs systemd; without it use `--local`.
- **Never an old executable.** Before any file changes, the service of this installation is stopped (then the usual running instances are closed); after the files are in place it is restarted and the installer checks that the running process is exactly the new `bin/baradwatchu-agent` (not a replaced file). If the installation fails before that point (for example a dashboard that does not close), the service is started again on the files in place. If the service itself cannot start, the installer stops it, reports that the files are installed and prints the command to retry; it exits with an error.
- **Uninstall** (`-U`) stops and removes this installation's service before removing files.
- **Kept, always:** every user's identity, trust store, settings, custom checks, events and history, and the service folder `/var/lib/baradwatchu` (registrations with Server addresses and enabled state, request records). Remove that folder by hand only to forget the registrations: `sudo rm -r /var/lib/baradwatchu`. The installer never generates keys or starts a Server connection and never changes the firewall.

The installer keeps its build cache, manifest-based reinstall and uninstall; user settings, custom checks and history are never touched. It does not create a package-manager package. `./install.sh --help` lists all options.

### Windows: install.ps1 and setup.exe

On Windows there is only the **system installation** (Program Files, all users, with the Windows service that keeps the Server tunnels). `install.ps1` is the counterpart of `install.sh`: it builds as the current user, compiles the setup with Inno Setup 6 and runs it **elevated (UAC prompt: administrator credentials are required)**. Windows blocks unsigned scripts by default, so start it through Windows PowerShell with a process-only bypass:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -MissingDeps   # read-only dependency check
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -DryRun        # show the plan
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1                # build, build the setup, install
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -NoTrayAutostart # first install without start at login
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -WithoutTray   # agent and dashboard only
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Uninstall     # uninstall
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1 -Package       # only build setup.exe (other machines)
```

- **Dependencies:** [REQUIRED] Rust ≥ 1.92 with the MSVC toolchain (≥ 1.80 with `-WithoutTray`), Visual Studio Build Tools with the C++ workload, Node.js 20 ≥ 20.11.1, npm and Inno Setup 6; Windows PowerShell 5.1 at runtime. [optional] the audit sources (PowerShell FullLanguage mode, Defender and NetSecurity cmdlets, Cato Client). The `winget` command for each missing item is printed. Unknown options are refused (exit code 2).
- **Build:** as on Linux, a validated cache outside the source tree (default `%LOCALAPPDATA%\baradwatchu\build\baradwatchu-agent-VERSION`, `-BuildDir`, `-BuildOnly`, `-NoBuild`), with the Angular build in a private copy of `web`, a source fingerprint (changes during the build or since the cached build are refused), version checks of both executables and the same integrity check of the built-in Windows checks against `builtin-tools.sha256`.
- **Install:** stages the validated build, compiles `packaging\windows\baradwatchu-client.iss` into `BaradWatchU-Client-VERSION-setup.exe` (default `BUILDDIR\dist`, `-OutputDir`, SHA-256 printed), asks the dashboard and tray of the installed version to close (`baradwatchu-agent quit`, see **Quit BaradWatchU**), then runs the setup with `/SILENT` as administrator (log in `BUILDDIR\setup.log`) and checks that the `BaradWatchU` service is running. `-Uninstall` runs the uninstaller of the system installation the same way.
- **Setup:** Program Files (`{autopf}\BaradWatchU`), Italian or English, Start menu entries for all users, a "start the tray at login" task (selected by default and offered only on a first installation, so an upgrade keeps the user's choice; `-NoTrayAutostart` = silent `/MERGETASKS="!trayautostart"`; not offered while the `HKCU\…\Run` entry belongs to another installation; written for the user who started setup, and removed by the uninstaller only when it starts this installation's tray) and an uninstaller in **Settings › Apps**; upgrades replace the same installation. It always installs or updates the Windows service `BaradWatchU` (LocalSystem, automatic start, restart on failure) through `install-service.ps1`, shipped in `share\baradwatchu-client\service`; if the service belongs to another installation, setup stops before changing files. Setup stops that service before replacing files and restarts it on the new executable, checking the running process; a refused or cancelled setup starts it again; if it cannot start, setup says so and leaves it stopped. Setup and uninstaller refuse to run while a BaradWatchU program of that folder is running (exit code 7 / 1, nothing changed) and never terminate it: use **Quit BaradWatchU** first. The uninstaller removes the service before deleting files and keeps `%ProgramData%\BaradWatchU\service` and every user's data. The setup can also be run by hand (standard silent switches `/VERYSILENT /SUPPRESSMSGBOXES`, `/DIR=`). It is **not code-signed**: SmartScreen shows an unknown-publisher warning until the organisation signs it (for example with `signtool`), which is not automated here.
- **Former per-user installations:** older versions of `install.ps1` installed per user in `%LOCALAPPDATA%\Programs\BaradWatchU` without the service, and older setups offered "only for me". Installing refuses while one exists. `install.ps1 -Uninstall` removes the former `install.ps1` one (manifest-owned, unchanged files only; its Start menu entries and start-at-login entry; its running dashboard and tray are asked to close with WM_CLOSE / Ctrl+C and never killed); a former per-user setup is removed from **Settings › Apps**.

## Development checks

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cd web && npm test && npm run build
```

Cross-checking Windows/macOS (`cargo clippy --target …`) needs a C compiler for the target because of `ring` (TLS): for example `clang-cl` with the Windows SDK headers, or clang with the Apple SDK.

On Windows the same commands work from a Developer shell with the MSVC toolchain (Visual Studio Build Tools, C++ workload) and Node.js 20; for installation use `install.ps1` (see above). Test tools are shell scripts on Unix and PowerShell scripts on Windows; the shell-only runner tests and the built-in script suites run on Unix only. Tests point every XDG directory at private temporary folders and serialise environment changes, so they run in parallel and never touch the developer's configuration or history. Built-in check scripts are tested with fixture files and stub commands (`tests/workstation_criteria.rs`, `tests/req003_firewall.rs`, `tests/req004_005_methods.rs`). Tray logic (icon state, notification policy, snapshot contract) is unit-tested without a GUI in `crates/tray/src/model.rs`.

## Current limits

The legacy architecture (policy evaluation, native Fedora/Arch collectors, adapters, workstation registry, `policies/`, the old `scripts/`, `configs/`) was removed on 2026-11-07; the source tree contains only the folder-based catalog, runner, CLI and dashboard. Some checks are intentionally conservative and return `WARN`; real-host validation beyond the developer's Arch workstation is still pending. There is no audit scheduler, remote policy, dynamic tool download, macOS audit implementation or automatic remediation. On Windows there is only the system installation (an unsigned setup for all users with the service, built and run by `install.ps1`), no code signing yet, and the Windows service has never been run; its checks run without administrator rights, so BitLocker details, full Secure Boot/TPM queries and `secedit` data are out of reach, and the Cato adapter that signals a connection has not been verified on a connected device. Consent decisions are bound to the local user: any process of the same user can call `consent accept`, exactly as it can read that user's files. Providers exist only for built-in requirements (REQ-002 so far): custom providers are not implemented, the Bitdefender GravityZone provider has not been validated on a managed endpoint, and the Windows provider scripts have not been run yet. The installation hashes are reported but no Server verifies them yet. The private key is protected only by operating-system file permissions (no TPM or OS key store), and the Windows ACL and the macOS build have not been exercised at runtime. Remote requests: the system service reads each registered user's private key from their folder, so a home that is encrypted and not unlocked (systemd-homed, FileVault, eCryptfs) or a root-squashed network home makes that user unreachable (the handshake fails, so the Server sees no answer rather than `UNAVAILABLE`); remote requests depend on the tray (consent window); consent prompts appear within the tray's 5-second poll; audit results stay in the service's memory for one hour and are lost on restart; an audit already running is not cancelled if the session goes away (its result stays local); there is no dashboard panel for remote requests yet (CLI `remote …` only).

## Server MVP requester metadata

Remote audit requests from the Server MVP carry the Google operator's display name and
Server display name. The consent prompt still shows the locally trusted Server identity
and fingerprint; the operator name is descriptive and does not authorize execution.
New audit JSON/history, the local dashboard and PDF distinguish `LOCAL` and `REMOTE`,
with the requester name and Server reference for remote audits. Historical reports that
lack attribution remain readable without inventing an origin.

The PDF header labels remote results `CLIENT · REMOTE AUDIT`, local results `CLIENT · LOCAL AUDIT`, and legacy reports without origin `CLIENT · ORIGIN UNKNOWN`.

Upgrade both the Client service and user agent before connecting the Server MVP: old
strict protocol-v1 readers reject the optional `requester` field; upgraded readers still
accept legacy requests without it. Consent remains 120 seconds; completed remote results
remain available in service memory for one hour, independently of local history.
See [the protocol](docs/remote-protocol.md) for the additive fields and compatibility.
