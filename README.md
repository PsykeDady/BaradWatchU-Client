# BaradWatchU Client

*Nine were given to the Devs, who await their sorrowful bugs; seven to the SysAdmins, in their halls of servers; three to the Security Officers, keepers of the secret policies.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU Client audits the workstation where it runs. Audits, settings and history are local. The Server is not required. The current development target is Arch Linux; other operating systems are not supported by this requirement catalog yet.

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

- Built-in checks live in `share/baradwatchu-client/catalog/checks/REQ-*/` of the installation; custom checks live in `$XDG_CONFIG_HOME/baradwatchu/custom-checks/CUSTOM-*/` (default `~/.config/baradwatchu/custom-checks/`). A pre-release `custom-tools` folder is renamed to `custom-checks` on first use; its contents are not changed.
- `id` must equal the folder name and start with `CUSTOM-` (uppercase letters, digits, dashes). `toolPath` is relative to the folder. `arguments` are passed directly to the tool, without a shell. `timeoutSeconds` (1–300, default 20) and `version` are optional. `parameters` is a JSON object sent to the tool on stdin as `{"requirementId":…,"parameters":{…}}`. Unknown fields are rejected. Priorities are `HIGHEST`, `HIGH`, `MEDIUM`, `LOW` and `OPTIONAL`; they do not change a result.
- A custom check prints **one** JSON object on stdout and exits with code 0: `{"status":"PASS","summary":"Readable outcome","details":["evidence"]}`. Statuses are `PASS`, `FAIL`, `WARNING` (shown as `WARN`) and `ERROR`; `details` is optional, a string or an array. It does not repeat its ID. Built-in tools additionally return their `id`.
- The tool runs in its own folder as the current user, without a shell or elevation, with a clean environment (`PATH` is `/usr/bin:/bin`, plus `~/.local/bin` for custom checks), its own process group and a bounded output. On timeout the whole process group is killed, including helpers the script started. A non-zero exit, invalid JSON or a timeout is `ERROR`, and the tool's stderr appears in the details.
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
| REQ-004 | At least one DNS-filter method is complete: dnsmasq active **and** enabled with at least `minimumDnsmasqRules` (1000) block rules, or a blocklist of at least `minimumHostsEntries` (10000) entries in `/etc/hosts`. A `resolv.conf` that does not point to loopback (for example while a VPN is connected) is reported as an observation. |
| REQ-005 | Cato or WireGuard is connected. Installed but disconnected is `WARN`; neither installed is `FAIL`. |
| REQ-006 | At least one active encryption method: LUKS/dm-crypt device, mounted eCryptfs (the details say whether the home is covered) or a mounted CryFS container. This does not certify every data area. |
| REQ-007 | KDE Plasma 6 Wayland: `Autolock=true`, `Timeout` ≤ `maxTimeoutMinutes` (5), `LockGrace` ≤ `maxLockGraceSeconds` (0, password required immediately), lock on resume enabled. Other sessions are `NOT_APPLICABLE`. |
| REQ-008 | Current account maximum password age ≤ `maxPasswordAgeDays` (60) and not "never"; warning ≥ `minimumWarningDays` (10); `PASS_MAX_DAYS` in `/etc/login.defs` within the same limit; pwquality `minlen` ≥ 14, `minclass` ≥ 4, `ucredit`/`lcredit`/`dcredit`/`ocredit` = -1 (`requireCharacterCredits`), with `pam_pwquality` or `pam_passwdqc` in PAM. |
| REQ-009 | Firmware reports Secure Boot on and SetupMode off; `systemd-analyze has-tpm2` output is recorded. |

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
baradwatchu-agent custom accept CUSTOM-ID
baradwatchu-agent custom remove CUSTOM-ID
baradwatchu-agent dashboard
```

During development use `cargo run -p baradwatchu-agent -- …`. Exit codes of `audit`/`check`: 0 all passed (or disabled/not applicable), 4 at least one `WARN`, 3 at least one `FAIL`, 1 at least one `ERROR`, 2 usage error. Every audit is saved as JSON under `~/.local/state/baradwatchu/audits/reports/` for `status` and the dashboard history; `--log` also writes a plain-text `.log` with tools, exit codes and diagnostics. `list --json` and the dashboard API use camelCase field names. `custom accept` and `custom remove` work even when the folder's configuration is invalid. The former `workstation`, `policy validate`, `audit --policy`, `audit --format` and `audit --local-config` commands are removed; the CLI rejects them before reading any local data.

## Dashboard and notifications

`baradwatchu-agent dashboard` serves the Angular dashboard on an ephemeral `127.0.0.1` port and opens it with `xdg-open` when a desktop session is available. It does not start a service or listen on the network; requests that change data must come from the dashboard origin. It uses the same settings, runner and history as the CLI.

- **Workstation status:** last audit summary (the counters filter the list), filters by outcome, search, requirements sorted by severity after an audit, per-requirement details, settings, parameters, and collapsed technical/integrity details. Historical audits can be opened from the side panel without changing the current state.
- **Custom checks:** a separate section lists your checks with integrity state and last outcome, and offers **Check now**, **Accept current version**, **Upload new file**, **Restore built-in** (for overrides) and **Delete**. Invalid folders appear with their error and can be deleted. **New check** opens the import form: ID (next free `CUSTOM-NNN` suggested), name, description, priority, timeout, file, arguments and, under advanced options, copying metadata or overriding a built-in. The file keeps its name inside the new folder. The section also explains the folder layout and output contract.

Development build:

```sh
cd web && npm ci && npm run build && cd ..
cargo run -p baradwatchu-agent -- dashboard
```

`baradwatchu-agent audit --notify` asks `notify-send` to show the audit summary when it is installed and a notification session is available.

A custom `PASS` is the tool's own claim, not an independent security proof. The Server has no audit catalog or authenticated registration yet, so it does not verify these hashes.

## Build and install

The source installer builds as a normal user and uses `sudo` only to copy files into a protected prefix:

```sh
./install.sh --missing-deps                        # read-only dependency check
./install.sh --dry-run                             # show the plan
./install.sh                                       # build and install into /usr/local
./install.sh --build-only --build-dir=DIR          # build and validate the cache only
./install.sh -U                                    # uninstall
```

Every run starts with a summary of the effective options. The dependency check lists:

- **[REQUIRED] build tools** (Rust/Cargo ≥ 1.80, C/C++ tools, make, tar, glibc, Node.js 20 ≥ 20.11.1 selected through `web/.nvmrc` and nvm when available, npm) and **[REQUIRED] runtime tools** used by the agent and checks (bash, python3, awk, sed, grep, coreutils). If any is missing the installer stops before building or changing files and prints the package command.
- **[optional] audit tools — Arch Linux only** (`checkupdates`, `systemctl`, `ufw`/`firewalld`/`nftables`, `dnsmasq`, Cato/`wg`, `lsblk`, `findmnt`, `kreadconfig6`, `pgrep`, `chage`, `systemd-analyze`, `notify-send`, `xdg-open`), each with the check that needs it. A missing one never blocks; its check reports `WARN`. Alternatives (one firewall, one VPN client) are satisfied by any one of them. On other distributions this section is skipped with a note, because the built-in checks target Arch.

**Running instances:** before files are replaced or removed, a `baradwatchu-agent` started from the same installation (matched by its executable path, never by name, for example an open dashboard) receives SIGTERM and has up to `BARADWATCHU_STOP_TIMEOUT` seconds (default 10) to exit. It is never killed: if it does not exit, the installer stops without changing anything. Other users' instances are only reported. `--dry-run` shows what would be closed.

The installer keeps its build cache, manifest-based reinstall and uninstall; user settings, custom checks and history are never touched. It does not create a system service or a package-manager package. `./install.sh --help` lists all options.

## Development checks

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cd web && npm test && npm run build
```

Tests point every XDG directory at private temporary folders and serialise environment changes, so they run in parallel and never touch the developer's configuration or history. Built-in check scripts are tested with fixture files and stub commands (`tests/workstation_criteria.rs`, `tests/req003_firewall.rs`, `tests/req004_005_methods.rs`).

## Current limits

The legacy architecture (policy evaluation, native Fedora/Arch collectors, adapters, workstation registry, `policies/`, `scripts/`, `configs/`) was removed on 2026-11-07; the source tree contains only the folder-based catalog, runner, CLI and dashboard. Some checks are intentionally conservative and return `WARN`; real-host validation beyond the developer's Arch workstation is still pending. There is no scheduler/daemon, Server communication, remote policy, dynamic tool download, Windows/macOS implementation or automatic remediation.
