# BaradWatchU Client

*Nine were given to the Devs, who await their sorrowful bugs; seven to the SysAdmins, in their halls of servers; three to the Security Officers, keepers of the secret policies.*

[Leggi in italiano](LEGGIMI.md)

BaradWatchU is an endpoint security compliance auditing platform. This repository contains the independent Rust agent and its local Angular status viewer. The agent will audit endpoints offline and later communicate evidence to the separate server repository.

## Status

**Implemented in L0.1:** a Rust bootstrap executable that prints its detected compile-time platform and exits; Linux, Windows and macOS adapter boundaries; an Angular local status viewer scaffold that reports that no service or audit data is connected. Rust was built and run; the Angular build remains unverified here because dependency registries were unreachable.

**Planned:** background service integration, audit engine, built-in and authorized custom checks, policy validation, platform-specific inspection, local result storage and authenticated server communication. No checks, service installation, policy processing, enrollment, synchronization, privileged helper or remediation is implemented.

## Architecture

- `crates/agent/src/main.rs`: cleanly exits after bootstrap identification.
- `service.rs`: background service lifecycle boundary.
- `audit.rs`, `checks/builtin.rs`, `checks/custom.rs`: audit and check boundaries; no checks execute.
- `policy.rs`, `communication.rs`: policy and server transport boundaries; no policy or network behavior exists.
- `platform/{linux,windows,macos}.rs`: compile-time platform adapter boundaries.
- `web`: Angular local status viewer, independent of the background agent. No local IPC is implemented.

## Prerequisites

- Rust stable toolchain with Cargo and rustfmt (workspace baseline: Rust 1.80+).
- Node.js 20.11+ and npm 8+ for Angular 18 (Node 20 recommended).
- Network access on first dependency resolution unless dependencies are already cached.

## Commands

From the repository root:

```sh
cargo fmt --all -- --check
cargo test --workspace
cargo run -p baradwatchu-agent
```

Build the status viewer separately:

```sh
cd web
npm install
npm run build
```

No Angular test runner or tests are configured in this bootstrap; Rust tests run with `cargo test --workspace`.

## Security principles

The agent is intended to audit first, run with least privilege, work independently of the UI, and treat unobservable checks as unknown rather than passing. Server policy must authorize checks; custom artifacts require local approval and identity validation. No remote shell or implicit remediation is allowed. These are design principles; enforcement is future work.

## Requirements and roadmap

The canonical requirements and milestone gates are in the parent workspace's local `REQUIREMENTS.md` (§§ 2–14). That file is a local development document and is not a dependency or public file in this repository.

## Repository map

```text
Cargo.toml                 Rust workspace
crates/agent/               Agent executable and modular boundaries
web/                        Independent Angular local status viewer
```
