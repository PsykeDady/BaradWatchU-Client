# BaradWatchU remote audit protocol v1

Contract between a BaradWatchU Server (the *requester*) and a BaradWatchU Client
(Milestone 2). The Server MVP uses this contract; the Client ships the reference types and
TLS helpers (`baradwatchu_agent::remote`) and an executable harness that plays
the Server role (`crates/agent/tests/remote_service.rs`).

**Rule zero: a trusted Server may *ask* for an audit; only the user's explicit acceptance,
given locally on the workstation, runs it.** There is no automatic acceptance, no
standing grant and no way for a Server to run commands, change keys or the trust store.

## 1. Prerequisites (out of band, never over the network)

1. The user generates the Client identity (`baradwatchu-agent identity generate`) and
   exports it (`identity export`): `baradwatchu.public-identity.v1`, role `client`, with
   the Device ID `BWU-XXXX-XXXX-XXXX-XXXX` and the Ed25519 public key.
2. The user imports the Server public key file after checking its fingerprint
   (`trust import FILE`). The Server imports the Client file the same way.
3. An administrator installs the system service and configures the listener (§6); the
   user runs `baradwatchu-agent remote enable` (explicit, per user).

No discovery, pairing, TOFU or key import from the network exists.

## 2. Transport: TLS 1.3, mutual authentication with raw Ed25519 keys

- TLS 1.3 only (rustls). Certificate type: **raw public key** (RFC 7250) on both sides;
  signature scheme `ed25519` only. Session tickets and resumption are disabled: every
  connection authenticates from scratch, so a revocation applies to the next connection.
- **The TLS keys are the Milestone 1 identity keys themselves.** The key that proves
  possession in the handshake (CertificateVerify) is the key compared with the trust
  store; there is no X.509 certificate, CA or second chain of trust.
- **SNI = the Client's Device ID** (any case). One service can serve several registered
  users on one port; an unknown or stale Device ID aborts the handshake.
- The Client accepts the handshake only if the Server's key is `TRUSTED` (not revoked) in
  the trust store of the user who owns that Device ID. Unknown keys, revoked keys,
  another user's Server, TLS 1.2 or certificate chains are refused **before any HTTP
  byte is read**.
- The Server must pin the Client key it imported (helper:
  `remote::tls::requester_config(server_signing_key, client_public_key)`).
- Encodings: SubjectPublicKeyInfo DER = `302a300506032b6570032100` + 32 key bytes.

Authorization never relies on IP address, hostname or identifiers in the payload.

## 3. HTTP API

HTTP/1.1, one request per connection (`Connection: close`), JSON bodies
(`Content-Type: application/json`), request body ≤ 16 KiB, no chunked encoding.
Only these endpoints exist; the local dashboard API is never reachable here.

| Method and path | Purpose |
|---|---|
| `POST /v1/audit-requests` | Ask for an audit (asynchronous: returns immediately) |
| `GET /v1/audit-requests/{requestId}` | Status of one of *your* requests |
| `GET /v1/audit-requests/{requestId}/result` | Report of one of *your* completed requests |

A Server only ever sees requests it created (matched on its key and the Device ID); others
answer 404.

### 3.1 Create

```json
{
  "schemaVersion": "baradwatchu.remote-audit-request.v1",
  "requestId": "2026-11-10-ops-0001",
  "operation": "AUDIT_REPORT",
  "issuedAtUnixMs": 1794300000000,
  "requester": {
    "operatorDisplayName": "Mario Rossi",
    "serverDisplayName": "Company Server"
  }
}
```

- `requestId`: chosen by the Server, unique per Server, 8–64 characters `A-Z a-z 0-9 . _ -`.
- `operation`: only `AUDIT_REPORT`.
- Optional `requester` (Server MVP): `operatorDisplayName` required, `serverDisplayName`
  optional; each 1–128 characters, no control/bidi override characters. These are
  descriptive claims from the mTLS-authenticated Server. The Client derives the Server
  ID and fingerprint from its own trust store, never from the payload. The Server builds
  the operator name from a verified Google OIDC session, never from browser input.
- Compatibility: upgraded Clients still accept requests without `requester`; old strict
  v1 Clients reject the new field. Upgrade the service and user agent together before
  using the Server MVP. The Server never silently strips attribution to bypass rejection.
- `issuedAtUnixMs`: must be within ±5 minutes of the Client clock (`STALE_REQUEST`).

| HTTP | `state` | Meaning |
|---|---|---|
| 202 | `PENDING_CONSENT` | Consent window shown; `consentExpiresAtUnixMs` = now + 120 s |
| 200 | any | **Duplicate**: this `requestId` already exists for this Server; its current status is returned, nothing is executed again |
| 409 | `BUSY` | A request is waiting for consent or an audit is running (any origin: CLI, tray, dashboard, remote). No queue |
| 503 | `UNAVAILABLE` | Nobody can be asked: no linked user session (`NO_USER_SESSION`), tray not running (`TRAY_NOT_RUNNING`), session not answering, identity changed |
| 200 | `REJECTED`/`FAILED` | Refused on the Client before the prompt (e.g. `SERVER_NOT_TRUSTED`) |
| 400 | — | `INVALID_REQUEST`, `STALE_REQUEST`, `INVALID_HTTP` |

`BUSY` and `UNAVAILABLE` answers are **not stored**: the Server may retry later with the
same `requestId`. Every other outcome is stored and makes the `requestId` final.

### 3.2 Status document (`baradwatchu.remote-audit-status.v1`)

```json
{
  "schemaVersion": "baradwatchu.remote-audit-status.v1",
  "requestId": "2026-11-10-ops-0001",
  "deviceId": "BWU-1A2B-3C4D-5E6F-7A8B",
  "state": "PENDING_CONSENT",
  "reason": null,
  "createdAtUnixMs": 1794300000123,
  "updatedAtUnixMs": 1794300000456,
  "consentExpiresAtUnixMs": 1794300120456,
  "resultAvailable": false
}
```

States: `PENDING_CONSENT` → `RUNNING` → `COMPLETED`; terminal alternatives `REJECTED`,
`EXPIRED`, `FAILED`; immediate answers `BUSY`, `UNAVAILABLE`.

| `reason` (informative) | When |
|---|---|
| `USER_REJECTED` | The user clicked Reject |
| `CONSENT_EXPIRED` | No acceptance within 120 s, or the request was withdrawn by revocation, `trust clear` or `identity reset` |
| `SERVER_NOT_TRUSTED` | The Server was revoked between acceptance and execution |
| `SESSION_LOST`, `SERVICE_DISCONNECTED` | The user session/agent went away |
| `SERVICE_RESTARTED` | The service restarted; the request is never resumed |
| `AUDIT_FAILED`, `AUDIT_TIMEOUT` | The audit itself failed or exceeded 35 minutes |

### 3.3 Result (`baradwatchu.remote-audit-result.v1`)

`200` with `{schemaVersion, requestId, deviceId, report}` where `report` is the standard
audit report (`baradwatchu-agent audit --json`). `409` + status document while not
completed; `410 RESULT_EXPIRED` when the result is no longer held (results are kept in
memory only, for one hour, and are lost on restart).

### 3.4 Polling, retries, replay

- Poll the status every few seconds; the HTTP connection is never held during consent
  or audit.
- Network errors on `POST`: resend **the same** `requestId`. The Client answers with the
  stored request (200) instead of starting a new one.
- Records (without results) are kept 24 hours, longer than the accepted clock skew: a
  replayed request is either a duplicate (200, no execution) or stale (400).
- Errors use `{"schemaVersion":"baradwatchu.remote-error.v1","error":"CODE"}`.

## 4. Consent and timing on the Client

- With requester metadata, the consent names the operator and declared Server display
  name, followed by the locally trusted Server name/ID/fingerprint. Names never authorize.
- The consent window (tray) names the Server (name given at import, `SRV-…` ID and
  key fingerprint) and the operation (audit + sending the report to that Server).
- The 120-second timer starts when the request is shown. Screen locked: the request just
  waits; if the user unlocks and accepts in time, the audit runs; otherwise it expires.
  The lock screen is never bypassed.
- A late acceptance is refused. Revoking the Server, `trust clear` or `identity reset`
  withdraws the pending request immediately.
- The audit runs as the user, with the standard engine; it is also recorded in the user's
  local history and events.

## 5. Local architecture (for reference)

```
Server ──mTLS (SNI=Device ID)──► service run (root/LocalSystem, always on)
                                   │  registrations: user ⇄ identity folder ⇄ Device ID
                                   │  reads the user's owner-only key + trust store
                                   ▼  local IPC (Unix socket / named pipe, peer = OS account)
                                 remote link (user, started by the tray)
                                   │  consent request (REMOTE_SERVER) ─► tray window
                                   ▼  accepted → requirements::run_audit
```

IPC `baradwatchu.ipc.v1`: newline-delimited JSON, ≤ 8 MiB per message; `Hello{intent}`
with intents `REGISTER`, `UNREGISTER`, `STATUS`, `LINK`, `UPDATE`; the service answers
`Reply`, then pushes `Job`/`Ping` on `LINK` connections. The service learns the caller's
account from the OS (`SO_PEERCRED`, `getpeereid`, pipe impersonation) and acts only for
that account. The agent accepts only a service running as root/LocalSystem.

## 6. Service configuration

`service.json` in the service data folder (`/var/lib/baradwatchu`, macOS
`/Library/Application Support/BaradWatchU/service`, Windows
`%ProgramData%\BaradWatchU\service`), written by an administrator:

```json
{ "schemaVersion": "baradwatchu.service-config.v1", "remote": { "listen": "10.20.30.40:7443" } }
```

Without the file, or without `remote`, the listener is **disabled**. Restart the service
after a change. Firewall rules are managed by the operator/IT.

## 7. Report attribution (Server MVP)

New audits include `initiator: {"origin":"LOCAL"}` or
`initiator: {"origin":"REMOTE", "operatorDisplayName":"Mario Rossi",
"serverId":"SRV-…", "serverDisplayName":"Company Server",
"serverTrustedName":"Locally imported name", "serverFingerprint":"SHA256:…"}`.
For legacy remote requests without requester metadata, `operatorDisplayName` is null.
The same object is persisted before generating the local PDF and returning the report.
The local dashboard/history and PDF show the origin and remote requester. Old reports
without `initiator` remain readable; their origin is unknown, never inferred as LOCAL.
Neither operator email nor Google subject is transmitted to the Client.
The Server keeps only bounded request routing records in memory (24 hours), not audit
reports. Results remain governed by the Client's one-hour in-memory retention; local
Client history is independent of both timers and survives service/Server restarts.
