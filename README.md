# BaradWatchU Client

*Nine were given to the Devs, who await their sorrowful bugs; seven to the SysAdmins, in their halls of servers; three to the Security Officers, keepers of the secret policies.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU is an endpoint security compliance auditing platform. This repository contains the independent Rust agent and its local Angular status viewer. The agent performs a standalone Fedora audit slice offline and will later communicate evidence to the separate server repository.

## Status

**Implemented in L0.1:** a Rust bootstrap executable that prints its detected compile-time platform and exits; Linux, Windows and macOS adapter boundaries; an Angular local status viewer scaffold that reports that no service or audit data is connected.

**Validated in L0.1.1:** version `0.0.1`, Rust CLI, debug/release builds and Angular production build. Regression tests cover startup and version metadata. The installer was checked with isolated caches and prefixes for install/update/uninstall; its complete build reaches the Rust stage, while npm installation in a fresh cache is blocked in the offline environment. System services and native packages remain planned.

**Implemented in L1.1 / Checkpoint 1:** standalone Rust audit, five outcome states, versioned JSON and human reports, OS identity, cached Fedora DNF5 updates, and root-filesystem block encryption inspection. No Server or Angular process is required.

**Operator-confirmed L0.1.1 smoke:** Server `/health` returned HTTP 200 with expected JSON; both Angular dev servers worked; launcher Ctrl+C stopped the services. Fresh-cache installer builds, native packages, distribution-wide dependency audits and vulnerability audits remain technical debt.

**Planned:** persistent services, scheduling, signed policies, authorized custom checks, other platform checks, storage, enrollment, authenticated synchronization and remediation. These are not part of this checkpoint.

## Architecture

- `crates/agent/src/main.rs`: CLI parsing, bootstrap compatibility, audit rendering and exit codes.
- `service.rs`: background service lifecycle boundary.
- `audit.rs`: reusable `Check`/`Clock`, report/result/evidence types, deterministic summary and rendering.
- `checks/builtin.rs`: three stable identifiers and applicability; `checks/custom.rs` remains deferred.
- `policy.rs`, `communication.rs`: policy and server transport boundaries; no policy or network behavior exists.
- `platform/mod.rs`: injectable `AuditPlatform`; `linux.rs`: safe os-release parser; `fedora/`: native update/encryption probes; `command.rs`: bounded subprocesses; `read_only.rs`: child-only Linux filesystem restriction. Windows/macOS adapters remain boundaries.
- `web`: Angular local status viewer, independent of the background agent. No local IPC is implemented.

## Version and CLI

Server and Client have independent release lifecycles. The Client's authoritative product version is `[workspace.package].version` in this repository's root `Cargo.toml`; Rust packages inherit it. Angular `package.json` and the displayed version are generated/synchronized from that source by `node web/sync-version.mjs` (also run automatically by `npm run build`). Change the workspace version using SemVer, then run the sync command. Product version is independent of the Client report schema `baradwatchu.audit-report.v1`; Server ingestion and shared fleet protocols remain undefined.

```sh
cargo run -p baradwatchu-agent -- --version
cargo run -p baradwatchu-agent -- --help
cargo run -p baradwatchu-agent -- audit
cargo run -p baradwatchu-agent -- audit --format json
```

The release executable supports these flags without starting a background service. The current bootstrap prints the platform and exits when run without options.

## Standalone audit (L1.1 / Checkpoint 1)

Run the built binary with `target/debug/baradwatchu-agent audit` or `target/release/baradwatchu-agent audit --format json`. No arguments retains bootstrap mode. No audit starts a service or requires root, Node, a browser or the Server.

Fedora prerequisites: a conventional RPM/DNF5 installation with `/usr/bin/dnf5` supporting `--skip-file-locks`, `findmnt` and `lsblk` (util-linux), readable system metadata, and existing repository metadata. DNF4-only, ostree/Atomic/image installations and other distributions are unsupported. A derivative with `ID_LIKE=fedora` does not qualify. Only actual `ID=fedora` plus a numeric `VERSION_ID` qualifies; this is not a certification of Fedora release support or end-of-life status.

The update probe requires enabled/permitted Linux **Landlock ABI 3+**. Its child denies file-content writes, creation, removal, renaming and truncation, and sets `no_new_privs`; inability to enforce that guard yields `ERROR/READ_ONLY_GUARD_UNAVAILABLE`, with no unprotected retry. DNF5 uses cache-only mode, disables plugins, persistent log output and libsolv cache creation, and skips creation/acquisition of the system repository lock; existing DNF state remains readable and the guard blocks writes. The update observation is not a transaction-locked snapshot and remains subject to concurrent package changes; no refresh or package transaction is invoked. The auditor never populates or refreshes missing metadata. It reads `/etc/os-release`, falling back to `/usr/lib/os-release` only if absent; no shell evaluation occurs. Probes use fixed executable paths, a minimal C locale environment, null stdin, a 30-second deadline and a 256 KiB limit per output stream. Raw package lists, stderr, repository URLs, disk serials and UUIDs are not included in the report.

| Check | Interpretation and outcome policy |
|---|---|
| `SYS-OS-001` — OS identity | `PASS`: distribution identified, with version if present (rolling distributions may omit it). Unsupported OS still has explicit coverage limits; inability to read/parse identity is `ERROR`. This observation does not certify security compliance. |
| `SEC-001` — pending updates | DNF5 `check-upgrade`: exit 100 is `FAIL` (cached updates available). Exit 0 is `WARN/NO_CACHED_UPDATES`, since freshness/coverage is unverified. Missing cache or no repositories is `WARN`; missing DNF5, permissions, timeout, invalid options and other execution failures are `ERROR`. There is deliberately no update `PASS` until trustworthy freshness/coverage can be established. The future quarterly policy is not evaluated. |
| `SEC-006` — root block encryption | `findmnt` identifies `/` by major:minor; `lsblk` traces **every observed backing path**. `PASS` requires a simple disk/partition/LVM path with an active dm-crypt layer directly backed by LUKS metadata on every path. A proven plain path is `FAIL`. An unrelated LUKS volume never qualifies. Missing/incomplete/unknown ancestry, conflicting metadata, plain dm-crypt without proven LUKS, Btrfs (including Fedora's common default), RAID/multipath, loop, overlay or network root are `WARN`; missing tools, permissions, command errors and malformed output are `ERROR`. |

Encryption scope is **the root filesystem only**, not all system/user data: separate `/home`, boot/EFI, swap, external disks, hardware encryption, key strength and authenticated boot are not certified. Complex storage requires later work; it is never assumed compliant. Unsupported platforms produce `NOT_APPLICABLE` Fedora checks, no probe commands and an overall `WARN`. Unknown OS identity produces `ERROR`, not a successful skip.

Exit codes: **0** all applicable checks PASS (also bootstrap/help/version); **1** any execution ERROR; **2** invalid CLI; **3** FAIL without ERROR; **4** WARN, unsupported or incomplete coverage without ERROR/FAIL. Precedence is ERROR > FAIL > WARN > PASS. Counts for all five states remain separate and deterministic.

JSON contract: `schemaVersion`, `agentVersion`, `startedAtUnixMs`, `completedAtUnixMs`, `operatingSystem`, `overall`, `summary`, `results`. Each result has `check` metadata (`id`, `name`, `description`, implementation `version`), `observedAtUnixMs`, `status`, `reasonCode`, `message`, `evidence` (`source`, `scope`, structured `values`). Timestamps are integer Unix milliseconds in UTC; result timestamps record check start. No device identity, applied policy, signature or Server compatibility is invented. Completed audits emit a complete report even with nonzero outcome codes; fatal clock/output errors can prevent a report. For completed audits, capture the exit code when saving JSON:

```sh
./target/release/baradwatchu-agent audit --format json > report.json
result=$?
printf 'Audit exit: %s\n' "$result"
```

Validation: 38 Rust tests, formatting, Clippy with warnings denied and locked debug/release builds pass on Arch. Both binaries produce valid human/JSON unsupported-platform reports (overall WARN, exit 4); the Linux write-denial test executed successfully. Parser/contract/platform fixtures and subprocess tests require neither Fedora configuration nor root. Actual Fedora DNF5/root-storage execution remains an operator smoke test; fixtures are not endpoint compliance evidence. Technical references: [DNF5 cache/configuration](https://dnf5.readthedocs.io/en/stable/dnf5.conf.5.html), [check-upgrade exit codes](https://dnf5.readthedocs.io/en/stable/commands/check-upgrade.8.html), [Landlock](https://docs.kernel.org/userspace-api/landlock.html), [lsblk](https://man7.org/linux/man-pages/man8/lsblk.8.html).

## Prerequisites

- Rust stable toolchain with Cargo and rustfmt (workspace baseline: Rust 1.80+).
- Node.js 20.11.1 or later within Node 20 and npm 8+; `web/.nvmrc` selects Node 20. Commands reject incompatible Node versions with an actionable message.
- Network access on first dependency resolution unless dependencies are already cached.
- GNU/Linux with glibc 2.17+ to build; a cache records the actual build host glibc and conservatively requires the same or a newer version.
- For the full source build: C/C++ compilers, make, Python 3 and tar (including native npm dependency fallbacks).

## Commands

From the repository root:

```sh
cargo fmt --all -- --check
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo build --workspace --locked
cargo build --release --workspace --locked
cargo run -p baradwatchu-agent
cargo run -p baradwatchu-agent -- --version
cargo run -p baradwatchu-agent -- --help
```

Build the status viewer separately:

```sh
cd web
npm ci
npm start       # local development
npm test        # version tooling tests
npm run build   # production
```

If using nvm, run `nvm use` in `web/` before npm commands. The development UI listens at `http://127.0.0.1:4201` and remains independent of the Rust process. `npm start` stays in the foreground; stop it with Ctrl-C before running other commands in that terminal.

## Linux source installation

Supported installer detection: Arch Linux, Fedora, Debian and Ubuntu, including `ID_LIKE`. `--missing-deps` only inspects dependencies, reports missing local Angular packages and prints package-manager/project commands; it never installs system packages. Required source-build tools are Rust/Cargo 1.80+, Node.js 20 >=20.11.1, npm 8+, C/C++, make, Python 3 and tar; glibc 2.17+ is the minimum checked on the build host. A validated prebuilt cache does not require Node/Angular tooling, but this source installer builds those assets when building from source.

```sh
./install.sh --help
./install.sh --missing-deps
./install.sh --dry-run --prefix=/tmp/baradwatchu-preview
./install.sh --local                         # limited development copy for this user
./install.sh --build-only --build-dir="$HOME/.cache/baradwatchu/baradwatchu-agent-0.0.1"
sudo ./install.sh --no-build --build-dir="$HOME/.cache/baradwatchu/baradwatchu-agent-0.0.1" --prefix=/usr/local
./install.sh --uninstall --prefix=/usr/local
```

`--no-build` requires a complete cache created from this exact source tree, version and host platform. For a system prefix, build as an unprivileged user first, then install with `sudo` and `--no-build`; never build as root. `--local` installs under `~/.local` for manual development use only. It does not provide a system service, privileged checks or compliance monitoring. System-wide source installation currently installs files only; it does not create or restart a service. Uninstall removes only unchanged payload files listed in the source manifest; it refuses package-manager-owned or modified files and preserves configuration, enrollment material, audit data and custom checks. Updates use the same ownership manifest.

`--build-only` uses Cargo `--locked` and a temporary Angular workspace inside the cache: `npm ci` does not replace checkout `node_modules`. Dependencies, npm logs and node-gyp headers stay in the cache. Sources must remain unchanged during the build. `-h` aliases `--help`, `-U` aliases `--uninstall`, and `--build-dir=DIR` selects the marked build cache. Exit codes are 0 for success, 1 for execution/validation failures, and 2 for invalid or conflicting options.

Source installation builds from this checkout. Arch `pacman`, Debian/Ubuntu `.deb`, and Fedora `.rpm` are planned in [`packaging/README.md`](packaging/README.md). Windows `setup.exe` and macOS `.dmg` are also planned there; none of these package artifacts has been built or tested. The source installer refuses to mix with package-manager ownership.

Rust audit tests cover serialization, summary/exit codes, applicability, fixtures and bounded subprocess errors without root or real endpoint configuration. `npm test` still covers 4 version tooling cases; no Angular UI runner is configured. Operator smoke confirms Angular dev serving and launcher shutdown; this checkpoint changes no UI. The legacy npm v1 lock remains technical debt, as do full fresh-cache source-install and vulnerability audits. Cache v2 checks hashes/glibc; older caches require rebuilding and installed configuration/data are preserved.

## Security principles

The agent is intended to audit first, run with least privilege, work independently of the UI, and treat unobservable checks as unknown rather than passing. Server policy must authorize checks; custom artifacts require local approval and identity validation. No remote shell or implicit remediation is allowed. This checkpoint enforces read-only native probing and honest result states. Policy authorization, custom checks and authenticated evidence remain future work; local observations are not tamper-resistant certification.

## Requirements and roadmap

The canonical requirements and milestone gates are in the parent workspace's local `REQUIREMENTS.md` (§§ 2–14). That file is a local development document and is not a dependency or public file in this repository.

## Repository map

```text
Cargo.toml                 Rust workspace
crates/agent/               Standalone audit executable/library and future boundaries
crates/agent/tests/         Contracts, command tests, synthetic Fedora fixtures
web/                        Independent Angular local status viewer
install.sh                  Linux source installer; service setup deferred
packaging/README.md         Linux/Windows/macOS package plan
packaging/product.toml      Package paths and ownership metadata (plan only)
```
