# BaradWatchU Client

*Nine were given to the Devs, who await their sorrowful bugs; seven to the SysAdmins, in their halls of servers; three to the Security Officers, keepers of the secret policies.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU Client audits the workstation where it runs. Audits, settings and history are local. The Server is not required. The current development target is Arch Linux; other operating systems are not supported by this requirement catalog yet.

## Requirements and results

Controls are discovered from one folder per check. Built-in folders live under `catalog/checks/REQ-*/`; custom folders live under `$XDG_CONFIG_HOME/baradwatchu/custom-tools/CUSTOM-*/` (or `~/.config/baradwatchu/custom-tools/CUSTOM-*/`). Each folder contains `configuration.json` and its tool. The configuration stores identity, description, enabled state, priority, `toolPath`, direct `arguments`, parameters, and expected SHA-256. Runtime inventory and installer validation discover folders instead of relying on a second requirement-ID list. Priorities are `HIGHEST`, `HIGH`, `MEDIUM`, `LOW`, and `OPTIONAL`; they do not change a check result.

Each tool is executed directly, without an implicit shell, with a bounded runtime and output. Built-in tools identify their requirement in the result; a custom tool returns only `status`, `summary`, and optional `details`, since the configured requirement already supplies the ID. Custom statuses are `PASS`, `FAIL`, `WARNING`, or `ERROR`; the Client displays `WARNING` as `WARN`. `details` may be one string or an array of strings. The whole response must be one JSON object on stdout. Missing or unclear evidence should use `WARNING`; launch and protocol failures become `ERROR`. Tools do not elevate privileges or change system configuration.

`REQ-001` checks package updates with `/usr/bin/checkupdates --nocolor` from `pacman-contrib`. `checkupdates` uses a temporary package database and can contact Arch mirrors; this check is not offline. Missing `checkupdates`, mirror errors, or other inconclusive outcomes produce `WARN`. Finding packages to update produces `FAIL`; no updates produces `PASS`. This does not assess vulnerability status. See the [Arch checkupdates manual](https://man.archlinux.org/man/extra/pacman-contrib/checkupdates.8.en).

Several other checks deliberately return `WARN` while their local indicators cannot establish the security property. In particular, antivirus service presence does not prove scan coverage, DNS settings do not prove filtering, VPN status does not prove tunnel reachability, and current encryption/password/boot tools do not claim more than their available evidence supports. Review each result's summary and details before treating it as compliance.

## CLI

Build with Rust and Angular dependencies installed, then run:

```sh
cargo run -p baradwatchu-agent -- list
cargo run -p baradwatchu-agent -- enable REQ-001
cargo run -p baradwatchu-agent -- disable REQ-005
cargo run -p baradwatchu-agent -- priority REQ-001 HIGH
cargo run -p baradwatchu-agent -- configure REQ-006 '{"sensitivePaths":["/srv/archive"]}'
cargo run -p baradwatchu-agent -- check REQ-001
cargo run -p baradwatchu-agent -- check REQ-001 --log
cargo run -p baradwatchu-agent -- audit
cargo run -p baradwatchu-agent -- audit --json
cargo run -p baradwatchu-agent -- audit --log
cargo run -p baradwatchu-agent -- status
```

Use `--json` explicitly for machine-readable output and `--log` on `audit` or `check ID` when you want a plain-text `.log` under `~/.local/state/baradwatchu/audits/`. Text logs are off by default. Structured JSON reports remain saved for `status` and the dashboard under `audits/reports/`; these are application history, not duplicate text logs. A requested text log shows results, invoked tools and diagnostics. The installer also suggests Arch packages for missing optional audit commands. Disabling a requirement preserves it and its settings. Parameters are JSON objects passed through standard input; tools that do not consume them ignore them.

The current Linux checks report method evidence separately: REQ-003 supports operational UFW, firewalld and nftables; REQ-004 passes when dnsmasq is installed and active, or when dnsmasq is absent and custom blocking entries exist in `/etc/hosts`; REQ-005 supports Cato and WireGuard and passes only when one is connected. An installed but inactive dnsmasq fails, while an installed but disconnected VPN warns because company services may be unavailable. Antivirus and similar service-based checks require their relevant services to be active; installation alone does not pass. REQ-003 returns `PASS` only when a method's operation is verified. If all managed firewall services are explicitly inactive/disabled, it returns `FAIL` even when the kernel ruleset cannot be read; that uncertainty remains in the diagnostics. Otherwise inaccessible nftables rules produce `WARN`, not an assumed absence or success.

The former `workstation`, `policy validate`, `audit --policy`, `audit --format` and `audit --local-config` commands are removed; the CLI rejects them. The old implementation files remain temporarily for migration tests and internal code, but are not exposed as commands.

## Dashboard and notifications

`baradwatchu-agent dashboard` starts the Angular dashboard on an ephemeral loopback address and attempts to open it with `xdg-open`. It does not start an agent service or expose a listener to the network. The dashboard uses the same local requirement settings, audit runner and report history as the CLI; audit can also run without a browser. For development, build the Angular app first and then run the Rust dashboard command; Cargo stages the local bundle beside its executable:

```sh
cd web
npm ci
npm run build
cd ..
cargo run -p baradwatchu-agent -- dashboard
```

`baradwatchu-agent audit --notify` asks `notify-send` to display the completed audit summary when that program is installed and a desktop notification session is available. Notification delivery is optional and is not required for an audit.

The dashboard's **Custom checks** panel imports, updates, removes and enables local executables. You can copy metadata from an existing requirement to create a custom check or explicitly override a built-in requirement; restore returns the built-in tool while retaining the imported check as a standalone custom item. Before import, BaradWatchU warns that the file is executable and runs with the current user's privileges. Imported controls are saved as a folder with `configuration.json` and the tool under `$XDG_CONFIG_HOME/baradwatchu/custom-tools/CUSTOM-*/` (or `~/.config/baradwatchu/custom-tools/CUSTOM-*/`). `arguments` is a JSON string array passed directly to the executable, without a shell. A custom tool returns only its result, for example `{"status":"PASS","summary":"Check passed","details":["Method: dnsmasq"]}`; it does not repeat the requirement ID, including for an override. No shell is inserted and there is no elevation.

The inventory is rescanned when the client starts and for each `list`/audit/dashboard data request. To force an immediate rescan, run `baradwatchu-agent refresh` or select **Riscansiona controlli** in the dashboard. A manually added custom folder appears after refresh when its folder name matches its `CUSTOM-*` ID and its `configuration.json` and tool path are valid.

Each audit result keeps compliance status separate from integrity evidence. Custom files get an expected SHA-256 at import; edits report `MISMATCH`, and replacing a file through the dashboard is an explicit version update. Built-in expected hashes come from the static distribution manifest embedded in the agent and validated by the installer. Hash scope is the entrypoint file only: scripts or system executables they call are outside that digest. For custom tools, execution uses a private snapshot of the imported file bytes. A custom `PASS` is the tool's own claim, not an independent security proof. Reports contain tool identity, origin, paths, expected/actual hashes and override details. The Server currently has no compatible audit catalog or authenticated registration, so it does not independently verify these hashes.

## Build and install on Arch Linux

The source installer retains its build-cache, staging, reinstall and manifest-based uninstall flow. Run it as a normal user; it requests `sudo` only when copying into a protected prefix:

```sh
./install.sh --missing-deps
./install.sh --build-only
./install.sh
```

The installer needs Rust/Cargo, C/C++ build tools, Python, tar, Node.js 20 (at least 20.11.1) and npm. It selects the version in `web/.nvmrc` through an existing nvm installation when available; it does not download Node automatically. Install `pacman-contrib` to run `REQ-001`. `./install.sh --help` lists build-only, cache, prefix and uninstall options. The installer does not create a system service or package-manager package.

## Development checks

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cd web && npm test && npm run build
```

The npm commands use the Node version selected by `web/.nvmrc`.

## Current migration limits

This is the first implementation checkpoint for the simplified Client, not the completed migration. Legacy policy evaluation, native collectors and workstation registry remain in the source tree, but their old CLI commands have been removed. Some of the nine Arch tools are intentionally conservative and return `WARN`; encryption path coverage and broader real-host validation remain unfinished. There is no schedule/daemon, Server communication, remote policy, dynamic tool download, Windows/macOS implementation, or automatic remediation.
