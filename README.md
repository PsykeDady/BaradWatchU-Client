# BaradWatchU Client

*Nine were given to the Devs, who await their sorrowful bugs; seven to the SysAdmins, in their halls of servers; three to the Security Officers, keepers of the secret policies.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU is an endpoint security compliance auditing platform. This repository contains the independent Rust agent and its local Angular status viewer. The agent will audit endpoints offline and later communicate evidence to the separate server repository.

## Status

**Implemented in L0.1:** a Rust bootstrap executable that prints its detected compile-time platform and exits; Linux, Windows and macOS adapter boundaries; an Angular local status viewer scaffold that reports that no service or audit data is connected.

**Implemented in L0.1.1:** product version `0.0.1`; Rust `--version`/`-V` and `--help`/`-h`; a Linux source-installer foundation with dependency audit, dry-run, build-cache validation, user/system prefixes and hash-manifest uninstall. Installer/service lifecycle and actual release artifacts remain unverified; no distribution channel is claimed as production-ready.

**Planned:** background service integration, audit engine, built-in and authorized custom checks, policy validation, platform-specific inspection, local result storage and authenticated server communication. No checks, service installation, policy processing, enrollment, synchronization, privileged helper or remediation is implemented.

## Architecture

- `crates/agent/src/main.rs`: cleanly exits after bootstrap identification.
- `service.rs`: background service lifecycle boundary.
- `audit.rs`, `checks/builtin.rs`, `checks/custom.rs`: audit and check boundaries; no checks execute.
- `policy.rs`, `communication.rs`: policy and server transport boundaries; no policy or network behavior exists.
- `platform/{linux,windows,macos}.rs`: compile-time platform adapter boundaries.
- `web`: Angular local status viewer, independent of the background agent. No local IPC is implemented.

## Version and CLI

Server and Client have independent release lifecycles. The Client's authoritative product version is `[workspace.package].version` in this repository's root `Cargo.toml`; Rust packages inherit it. Angular `package.json` and the displayed version are generated/synchronized from that source by `node web/sync-version.mjs` (also run automatically by `npm run build`). Change the workspace version using SemVer, then run the sync command. Product version is independent of future API/protocol/schema versions; those contracts are not defined yet.

```sh
cargo run -p baradwatchu-agent -- --version
cargo run -p baradwatchu-agent -- --help
```

The release executable supports these flags without starting a background service. The current bootstrap prints the platform and exits when run without options.

## Prerequisites

- Rust stable toolchain with Cargo and rustfmt (workspace baseline: Rust 1.80+).
- Node.js 20.11+ and npm 8+ for Angular 18 (Node 20 recommended).
- Network access on first dependency resolution unless dependencies are already cached.
- GNU/Linux with glibc 2.17+ for this source-build target.

## Commands

From the repository root:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p baradwatchu-agent
cargo run -p baradwatchu-agent -- --version
cargo run -p baradwatchu-agent -- --help
```

Build the status viewer separately:

```sh
cd web
npm install
npm run build
```

## Linux source installation

Supported installer detection: Arch Linux, Fedora, Debian and Ubuntu, including `ID_LIKE`. `--missing-deps` only inspects dependencies, reports missing local Angular packages and prints package-manager/project commands; it never installs system packages. Required source-build tools are Rust/Cargo 1.80+, Node.js 20.11+ and npm 8+; glibc 2.17+ is the GNU/Linux runtime baseline. A validated prebuilt cache does not require Node/Angular tooling, but this source installer builds those assets when building from source.

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

`--build-only` prepares and validates a cache without touching an installation. `-h` aliases `--help`, `-U` aliases `--uninstall`, and `--build-dir=DIR` selects the marked build cache. Exit codes are 0 for success, 1 for execution/validation failures, and 2 for invalid or conflicting options.

Source installation builds from this checkout. Arch `pacman`, Debian/Ubuntu `.deb`, and Fedora `.rpm` are planned in [`packaging/README.md`](packaging/README.md). Windows `setup.exe` and macOS `.dmg` are also planned there; none of these package artifacts has been built or tested. The source installer refuses to mix with package-manager ownership.

No Angular test runner or tests are configured. Rust tests run with `cargo test --workspace`. Angular and server release builds remain unverified where dependency registries are unavailable; the source installer is not claimed as end-to-end validated until real release builds pass.

## Security principles

The agent is intended to audit first, run with least privilege, work independently of the UI, and treat unobservable checks as unknown rather than passing. Server policy must authorize checks; custom artifacts require local approval and identity validation. No remote shell or implicit remediation is allowed. These are design principles; enforcement is future work.

## Requirements and roadmap

The canonical requirements and milestone gates are in the parent workspace's local `REQUIREMENTS.md` (§§ 2–14). That file is a local development document and is not a dependency or public file in this repository.

## Repository map

```text
Cargo.toml                 Rust workspace
crates/agent/               Agent executable and modular boundaries
web/                        Independent Angular local status viewer
install.sh                  Linux source installer; service setup deferred
packaging/README.md         Linux/Windows/macOS package plan
packaging/product.toml      Package paths and ownership metadata (plan only)
```
