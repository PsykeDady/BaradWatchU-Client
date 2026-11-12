# BaradWatchU remote audit protocol v1

Contract between a BaradWatchU Server (the *requester*) and a BaradWatchU Client
(Milestone 2). The Server MVP uses this contract; the Client ships the reference types and
TLS helpers (`baradwatchu_agent::remote`) and the existing consent and report contracts.

**Rule zero: a trusted Server may *ask* for an audit; only the user's explicit acceptance,
given locally on the workstation, runs it.** There is no automatic acceptance, no
standing grant and no way for a Server to run commands, change keys or the trust store.

## 1. Prerequisites (out of band, never over the network)

1. The user generates the Client identity (`baradwatchu-agent identity generate`) and
   exports it (`identity export`): `baradwatchu.public-identity.v1`, role `client`, with
   the Device ID `BWU-XXXX-XXXX-XXXX-XXXX` and the Ed25519 public key.
2. The user imports the Server public key file after checking its fingerprint
   (`trust import FILE`). The Server imports the Client file the same way.
3. An administrator installs the system service; the user runs `baradwatchu-agent remote enable` and configures a Server DNS name or IP and port in **Active connections**. Start is explicit per trusted Server.

No discovery, pairing, TOFU or key import from the network exists.

## 2. Transport: outbound mutual TLS tunnel

- The Client system service opens an outbound TCP connection to each enabled Server address. The Server listens for tunnels on `0.0.0.0:7445` by default (`BARADWATCHU_SERVER_TUNNEL_ADDR` overrides it). Its LOCAL dashboard remains loopback-only on port 3000.
- TLS 1.3 uses the existing RFC 7250 raw Ed25519 public identity keys on both sides. The Client pins the imported Server key; the Server accepts only an imported Client key and matches the authenticated key to the Device ID in the hello frame. Session tickets/resumption are disabled on the Server.
- The Client sends `{"schemaVersion":"baradwatchu.tunnel.v1","deviceId":"BWU-…","name":"…"}`. The name is informational. The Server acknowledges only after checking reciprocal trust. The Server holds this connection open and sends a ping frame every 10 seconds. Loss is reflected in the fleet badge; enabled Clients retry after five seconds. Stop disables retry persistently; Start and Refresh/repair replace the active connection.
- Frames contain a four-byte big-endian JSON length followed by that many JSON bytes, at most 9 MiB each. Requests are `{schemaVersion,sequence,method,path,body}`; replies are `{schemaVersion,sequence,code,body}`. Sequence numbers bind replies to requests. One exchange at a time per Client. Network errors close the channel and trigger reconnection.
- SNI is the Server ID. The TLS key is the identity/trust-store key, not a new credential. Addresses and the hello name never authorize a request. Neither a Client listener nor LAN discovery is used.

## 3. Audit operations on the tunnel

The Server sends the existing audit operations as request frames. The local dashboard API is never reachable on this channel.

| Method and path | Purpose |
|---|---|
| `POST /v1/audit-requests` | Ask for an audit (asynchronous) |
| `GET /v1/audit-requests/{requestId}` | Status of this Server's request |
| `GET /v1/audit-requests/{requestId}/result` | Client-produced report |
| `GET /v1/ping` | Connection liveness only |

A Server only sees requests it created (matched on its TLS key and the Device ID); others answer 404.

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

| Code | `state` | Meaning |
|---|---|---|
| 202 | `PENDING_CONSENT` | Consent window shown; `consentExpiresAtUnixMs` = now + 120 s |
| 200 | any | **Duplicate**: this `requestId` already exists for this Server; its current status is returned, nothing is executed again |
| 409 | `BUSY` | A request is waiting for consent or an audit is running (any origin: CLI, tray, dashboard, remote). No queue |
| 503 | `UNAVAILABLE` | Nobody can be asked: no linked user session (`NO_USER_SESSION`), tray not running (`TRAY_NOT_RUNNING`), session not answering, identity changed |
| 200 | `REJECTED`/`FAILED` | Refused on the Client before the prompt (e.g. `SERVER_NOT_TRUSTED`) |
| 400 | — | `INVALID_REQUEST`, `STALE_REQUEST` |

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

- Poll the status every few seconds; the tunnel remains open during consent and audit; each request frame gets a prompt response.
- Tunnel errors on `POST`: resend **the same** `requestId`. The Client answers with the
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

## 5. Local architecture

```
service run (root/LocalSystem) ──outbound mTLS──► Server tunnel listener
  │ registered user identity and trusted Server key       │ fleet badge / audit requests
  │ Client-owned DNS or IP:port, enabled state             │ no Client endpoint stored
  ▼ local IPC (OS peer credentials)
remote link (user, started by tray) ─► local consent ─► user audit engine
```

IPC `baradwatchu.ipc.v1` carries registration, connection control/status, linked agent jobs and updates. The service learns the caller's account from the OS and changes only that account's registration. It reads the registered user's owner-only identity and trust store, never invents a key, never runs an audit, and stores no report on disk. The per-user connection configuration is persisted in the service's `users/<principal>.json`; it survives service restarts. The Server stores only Client identity keys and names in SQLite, not Client addresses.

## 6. Connection controls

The Client dashboard's **Active connections** tab lists trusted Servers. The user supplies the Server's DNS name or IP and port, then selects **Start**. **Stop** closes the channel and suppresses automatic retry until a later Start. **Refresh / repair** restarts it immediately and can apply a changed address. These controls require the user's local dashboard session; they do not require administrator elevation. The system service must be installed/running and this user must have enabled remote requests. The tray remains necessary for consent, but the connection itself can remain up while no tray session is linked.

The Server's tunnel port must be reachable from the Client. The Server dashboard in LOCAL mode remains bound to loopback. Only a Client with a key that the Server already trusts can register a tunnel, and the Client verifies the Server key it imported. Audit requests still require the user's 120-second local consent.

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
