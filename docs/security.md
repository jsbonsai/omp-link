# Operator security guide

How to *operate* omp-link safely: what each capability actually permits, how to pair, how
to read the audit log, and how to take access away.

The threat model — assumptions, boundaries, non-goals — lives in
[../SECURITY.md](../SECURITY.md) and is authoritative. This page does not repeat it. If
something here disagrees with it, that document wins.

- [Capabilities](#capabilities)
- [Granting and editing capabilities](#granting-and-editing-capabilities)
- [The pairing flow](#the-pairing-flow)
- [Exec grants](#exec-grants)
- [Reading the audit log](#reading-the-audit-log)
- [/link shared](#link-shared)
- [Revoking](#revoking)
- [Operator checklist](#operator-checklist)

Related: [concepts.md](concepts.md), [commands.md](commands.md), [tools.md](tools.md).

---

## Capabilities

`DevicePermissions` (`src/identity.ts`) is stored **per paired device, on the machine that
grants it**. It is never sent by the peer and never inferred from a role: a hub's
capabilities against a client come from that client's own
`paired-devices.json`.

| Capability | Permits the peer to | Gated frames / RPC actions | In `DEFAULT_PERMISSIONS` |
|---|---|---|---|
| `observe` | See you in the roster and read `system_status`: your principal, fingerprint, room id, role, terminal name, agent instance, connected peers, and your active exec grants | `status_update`; `rpc_request{action:"system_status"}`; any unknown frame type | **yes** |
| `message` | Send you chat and direct messages, which reach your model as content | `chat`, `direct_message` | **yes** |
| `compact` | Force your context to compact, with instructions it chooses | `compact_request` | no |
| `inspectMetadata` | Run `git status`, `git log`, and list directories inside your workspace | `rpc_request{git_status, git_log, list_dir}` and the default arm for unrecognised actions | no |
| `readContent` | Read the contents of non-sensitive files, and `git grep` your tree | `rpc_request{read_file, search_text}` | no |
| `readDiff` | Read your uncommitted diff | `rpc_request{git_diff}` | no |
| `fileInbox` | Push files into your quarantine inbox (≤ 50 MB each, ≤ 250 MB total) | `file_offer`, `file_chunk` | no |
| `execRequest` | *Request* shell execution. Insufficient alone — also needs a live `ExecGrant` | `rpc_request{action:"exec"}` | no |
| `inspect` | Legacy alias. Honoured **positive-only** and only where the granular capability is unset | `inspectMetadata`, `readContent`, `readDiff` | no |

Evaluation is deny-biased (`isActionPermitted`):

1. `permissions === undefined` → denied,
   `No device permissions attached to connection`.
2. Granular `true` → permitted.
3. Granular **explicitly `false`** → denied,
   `Permission denied: "<cap>" is explicitly denied for this device`.
   An explicit `false` always wins; `inspect: true` cannot override it.
4. `inspect === true` and the granular capability is *unset* → permitted (legacy records).
5. Otherwise denied,
   `Permission denied: action requires "<cap>" capability, which is not granted to this device`.

Correlated responses (`rpc_response`, `compact_response`, `file_ack`) carry **no**
capability requirement. They are authorized by the pending request they answer, and the
responder's origin principal must match the peer the request went to
(`resolveExpectedResponder` + `originMatchesPending`). This is why a denied peer's error
reply still reaches you instead of hanging you for the full timeout.

Read the three preset sets as a policy ladder:

| Set | Contents | Used for |
|---|---|---|
| `NO_PERMISSIONS` | everything `false` | A client's starting point for its hub, before the stored record is applied |
| `DEFAULT_PERMISSIONS` | `observe`, `message` | Every fresh pairing, and every invite-based pairing |
| `FULL_PERMISSIONS` | everything `true` | **Local siblings only** — a peer presenting this device's own certificate |

## Granting and editing capabilities

Two entry points, with different semantics. This trips people up.

**At pairing time** — `--allow` **replaces** the whole set:

```
/link accept 1 canyon-ember-violet-rapid --allow message,metadata
```

`parsePermissionList` builds a complete `DevicePermissions`, so anything you do not name
becomes `false`. It always sets `observe: true`.

**Afterwards** — `devices allow` / `devices deny` **merge** only the named keys:

```
/link devices allow linux-box metadata,diff
```

```
linux-box can now: send messages, see repo status, read diffs
```

Accepted tokens, in both places:

| Token(s) | Sets |
|---|---|
| `message` | `message` |
| `compact` | `compact` |
| `inspect` | `inspect` + `inspectMetadata` + `readContent` + `readDiff` (all three at once) |
| `metadata`, `inspectmetadata` | `inspectMetadata` |
| `content`, `readcontent` | `readContent` |
| `diff`, `readdiff` | `readDiff` |
| `file`, `fileinbox` | `fileInbox` |
| `exec`, `execrequest` | `execRequest` |

Tokens are lower-cased and comma-separated. An unrecognised token is refused, not skipped:
`Unknown capability: frob. Nothing was approved.` from `accept --allow`,
`Unknown capability: frob. Nothing was changed.` from `devices allow`/`deny`, each followed
by the accepted list — the whole command is a no-op. There is no token for `observe`: it is
set at pairing and `devices deny` cannot remove it.

Changes to a live connection take effect immediately — `updatePeerPermissions` rewrites
the stored record, patches every matching `ConnectionContext`, and (for a client) reapplies
its own hub context. It also audits `permissions_updated`.

The human-readable rendering (`permissionSummary`) is what you see everywhere:

| Capability | Rendered as |
|---|---|
| `message` | send messages |
| `inspectMetadata` | see repo status |
| `readContent` | read approved files |
| `readDiff` | read diffs |
| `fileInbox` | send files |
| `compact` | request compaction |
| `execRequest` | request commands |
| none of the above | nothing |

`observe` is never rendered, so a peer holding only `observe` shows as `can: nothing`
while still being able to read `system_status`. Use `/link devices show <device>` for the
record.

## The pairing flow

```mermaid
sequenceDiagram
  participant B as Joiner
  participant A as Host
  B->>A: TLS 1.3 mutual auth (both present device certs)
  A->>A: extractPeerCertificate; no cert => close 4403
  B->>A: client_hello{clientNonce, displayName, agentInstanceId, cwd}
  A->>A: unknown device => initiatePairingForSocket
  A->>A: deriveLocalSas(tlsSocket, ...) => 4 words
  A->>B: server_hello{roomId, hubPrincipalId, hubFingerprint, hubNonce, requiresPairing:true}
  B->>B: deriveLocalSas(tlsSocket, ...) => same 4 words
  Note over A,B: Human compares the words out of band
  A->>A: /link accept <id> <code> => timingSafeEqual
  A->>B: pair_response{approved:true, permissions}
  A->>A: savePairedDevice: SPKI pinned permanently
```

What makes the code trustworthy:

- **It is never transmitted.** `server_hello` carries `hubNonce`, not the code. Both sides
  compute it independently.
- **It is bound to the live TLS session.** `deriveLocalSas` builds
  `SHA256("omp-link/pairing/v5\0" || hubSpki || clientSpki || hubNonce || clientNonce)`,
  exports 32 bytes of RFC 5705 keying material under the label
  `EXPORTER-omp-link-pairing-v5`, and HMACs the context with it. A man-in-the-middle
  terminating two separate TLS sessions gets two different exporter keys, so the two
  displayed codes will not agree.
- **There is no fallback.** A runtime without `exportKeyingMaterial` throws
  `PAIRING_UNSUPPORTED_RUNTIME` and pairing fails closed. A fallback keyed on public
  handshake values would be forgeable by exactly the attacker the SAS exists to stop.
- **The word list is exactly 256 unique frozen words**, so every byte of the digest maps to
  a word and every code is comparable. `encodeSasWords` indexes bytes 0–3 directly.
- **Comparison is mandatory and constant time.** `approvePairing(id, perms, code)` requires
  the code, normalises both sides (`replace(/[^a-zA-Z0-9]/g, "").toUpperCase()`), and uses
  `crypto.timingSafeEqual`.

Compare the words over a channel that is not this link: look at the other screen, or read
them on a phone call. Comparing them *through* omp-link defeats the purpose.

Refusal paths and what the peer learns:

| Situation | Host audit event | Peer is told |
|---|---|---|
| No code given to `approvePairing` | `pairing_rejected_missing_sas` | `pair_response{approved:false, reason:"Verification code required"}`, close `4403` |
| Wrong code | `pairing_rejected_invalid_sas` | `pair_response{approved:false, reason:"Verification code did not match"}`, close `4403` |
| `/link deny <id>` | `pairing_denied` | `reason: "Pairing request was denied by the host"`, close `4403` |
| No exporter support | `pairing_aborted_no_channel_binding` | close `4409 Pairing unsupported on this runtime` |
| `pairingWindowMs` elapsed (60 s by default) | — | close `4408 Pairing request timed out after <n>s` |
| Peer sends a mismatched `pair_verify` | — | close `4403 SAS verification mismatch` |

Rate limits protect the queue: 60 connections/min and 10 pairing attempts/min per IP
(`4429`), pairing queue capped at 16 (`4429 Pairing queue full (maximum 16 requests)`).

**Two paths skip the SAS, both deliberately:**

1. A valid single-use **invite** secret. Possession of the secret substitutes for the
   comparison; the record is still written with `DEFAULT_PERMISSIONS`.
2. A peer presenting **this device's own certificate** — a sibling terminal. Audited
   `local_sibling_admitted`, given `FULL_PERMISSIONS`. See
   [../SECURITY.md](../SECURITY.md) §7 and
   [scenarios.md#a-two-codebases-on-one-machine](scenarios.md#a-two-codebases-on-one-machine).

## Exec grants

Shell execution needs **three** independent gates:

1. `allowRemoteExec` on the receiving node — **off by default**. `index.ts` sets it from
   the `--unsafe-remote-exec` launch flag and never persists it to `link.json`, so a
   terminal that wants exec must be started with the flag every time.
2. The `execRequest` capability on the caller's paired-device record.
3. A live single-use `ExecGrant` keyed `(principalId, agentInstanceId)`.

A grant is bound to a `workspaceId` (default `*`), an expiry (`grantDefaultMs`, 10 min by
default, overridden per grant by the approver) and a use count (default 1). On first use
`checkAndConsumeExecGrant` records a sha256 `commandDigest`, so the remaining uses are
locked to that exact command string.

Grants are in-memory only and are destroyed by: expiry (`grant_expired`), exhaustion,
`revokeGrantsForPrincipal` (`grant_revoked`), peer disconnect
(`revokeGrantsForPrincipal(principalId, agentInstanceId, "Peer disconnected")`),
`LinkNode.stop()` (`revokeAllGrants("Link stopping")`) and `/link off`
(`revokeAllGrants("Link deactivated")`). They never touch disk and never survive a restart.

`/link grant` prints the advisory verbatim, and you should read it as written:

```
Full shell access granted. Mutation Guard is advisory and does not provide containment. Treat this peer as having local-user access.
```

Live grants are shown on the status card and counted in `link_status.details.activeGrants`:

```
Live command grants: linux-box (9m, 1 use(s))
```

## Reading the audit log

`<OMP_DIR>/audit.log`, JSONL, mode `0600`, append-only via `appendAuditLog`. One object per
line, always with `type`, `timestamp` (ms epoch) and `logSeq`.

Three properties matter when you read it:

- **One line, one `write(2)`.** The file is held open on a single `O_APPEND` descriptor for
  the life of the process, so sibling terminals writing at once interleave whole lines and
  never fragments. A stale descriptor (rotation, a recreated directory) is re-opened once
  and the write retried before the line is given up on.
- **`logSeq` and `agentInstanceId` say who wrote what, in what order.** `logSeq` is
  monotonic within the writing process — a gap means a lost write — and it is called
  `logSeq`, not `seq`, because an event is free to carry its own sequence number and the
  log silently overwriting a caller's field would corrupt the record it exists to preserve.
  `agentInstanceId` is stamped globally by the extension
  (`setAuditAgentInstanceId`), so with several OMP windows on one machine appending to one
  file you can still tell which terminal made each decision. The two together are how you
  read a file that has more than one writer.
- **A write failure is remembered, not swallowed.** `appendAuditLog` still never throws —
  the security decision the line describes has already been taken, and an unwritable log
  must not turn a clean denial into a crash — but the failure is recorded and exposed by
  `getAuditLogStatus()`. `/link doctor` prints it:

  ```
    AUDIT LOG          NOT WRITABLE — security decisions are not being recorded
                       /Users/you/.omp/audit.log: EACCES: permission denied, open '…'
                       Fix write access to /Users/you/.omp or set OMP_DIR to a writable directory.
  ```

  and `/link shared` refuses to print the reassuring "no decision is recorded yet" when the
  truth is "nothing could be recorded". It is still not a hard control: it records
  decisions, it does not enforce them.

```bash
tail -5 ~/.omp/audit.log
```

```json
{"type":"hub_started","timestamp":1757500000000,"roomId":"6f1c...","port":9900,"principalId":"ed25519-sha256:AA:...","agentInstanceId":"1f0b...","bindHost":"0.0.0.0","networkMode":"lan","logSeq":1}
{"type":"pairing_approved","timestamp":1757500120000,"principalId":"ed25519-sha256:CC:...","deviceName":"linux-box","permissions":{"observe":true,"message":true,"compact":false,"inspectMetadata":false,"readContent":false,"readDiff":false,"fileInbox":false,"execRequest":false,"inspect":false},"logSeq":2}
{"type":"authorization_denied","timestamp":1757500140000,"roomId":"6f1c...","principalId":"ed25519-sha256:CC:...","agentInstanceId":"1f0b...","action":"rpc_request","required":"inspectMetadata","reason":"Permission denied: action requires \"inspectMetadata\" capability, which is not granted to this device","logSeq":3}
{"type":"permissions_updated","timestamp":1757500200000,"target":"linux-box","updates":{"inspectMetadata":true},"logSeq":4}
{"type":"peer_liveness_timeout","timestamp":1757500900000,"roomId":"6f1c...","principalId":"ed25519-sha256:CC:...","agentInstanceId":"1f0b...","peer":"linux-box","silentMs":31004,"logSeq":5}
```

`AuditEventType` (`src/audit.ts`) is a **closed union of every event this codebase emits**.
If a type is not in the table below it is not written by omp-link; if you add an emitter,
add it to the union first.

Every event type, and what it tells you:

| Type | Emitted by | Read it as |
|---|---|---|
| `hub_started` | `startHub` | You began hosting; note `bindHost` and `networkMode` |
| `hub_start_failed` | `handleServerError` (startup) | Port conflict or bind failure; `code` is e.g. `EADDRINUSE` |
| `hub_server_error` | `handleServerError` (runtime) | The transport died after a good start; the node tore itself down |
| `local_sibling_admitted` | `handleHubClientHello` | Another terminal on **this machine** joined with full capabilities, no pairing |
| `local_hub_succession` | `attemptLocalSuccession` (`index.ts`) | A sibling terminal on this machine claimed the vanished hub's port; the room continues under the same device certificate, so pins stay valid ([scenarios.md#d-the-hosting-terminal-exits](scenarios.md#d-the-hosting-terminal-exits)) |
| `display_name_collision` | `uniqueDisplayName` | Two live connections wanted the same name; the newcomer was suffixed `@<6 hex>`. `requested` and `assigned` say which |
| `pairing_approved` | `approvePairing` | A device was pinned. `permissions` is exactly what it got |
| `pairing_denied` | `denyPairing` | You refused explicitly |
| `pairing_rejected_missing_sas` | `approvePairing` | An approval was attempted with no code |
| `pairing_rejected_invalid_sas` | `approvePairing` | **Investigate.** Wrong code — fat finger, or someone else answered |
| `pairing_aborted_no_channel_binding` | `initiatePairingForSocket` | Runtime cannot export keying material |
| `paired_store_reset` | `loadPairedDevices` | Schema upgrade wiped the store; everyone re-pairs |
| `device_revoked` | `revokeDevice` | Unpaired. `target` names it |
| `permissions_updated` | `updatePeerPermissions` | Capability change. `target` + `updates` |
| `authorization_denied` | `gateInboundApplicationMessage` | A peer asked for something it does not have. The denial oracle |
| `hub_pin_mismatch` | `connectToHub` | **Investigate.** A host's SPKI did not match the pin |
| `client_frame_rejected` | client dispatcher | Schema drift or a malformed frame from the hub |
| `client_phase_violation` | client dispatcher | The hub sent something out of phase |
| `rpc_response_origin_mismatch` | dispatcher | **Investigate.** Someone answered a request that was not theirs |
| `file_ack_origin_mismatch` | dispatcher | same |
| `compact_response_origin_mismatch` | dispatcher | same |
| `grant_created` / `grant_used` / `grant_revoked` / `grant_expired` | `src/authorization.ts` | Exec grant lifecycle |
| `exec_blocked` | `handleLocalRpcRequest` | An exec attempt without a valid grant. `reason` says why |
| `exec_executed` | `handleLocalRpcRequest` | A shell command **ran on this machine**. `command` is recorded |
| `file_transfer_received` | `handleLocalApplicationMessage` | A file landed in quarantine. `finalPath` is where |
| `peer_disconnected` | `handleHubSocketClose` | Socket closed; that peer's grants were revoked |
| `peer_liveness_timeout` | `sweepHubLiveness` | A peer went silent past `heartbeatIntervalMs * heartbeatMissesBeforeDrop` and was dropped (close `4408`). `silentMs` says how long ([concepts.md#liveness-and-ttl](concepts.md#liveness-and-ttl)) |
| `hub_liveness_timeout` | `sweepClientLiveness` | This client gave up on its hub after `clientHubSilenceTimeoutMs` and went `disconnected` |
| `peer_connection_superseded` | `evictSupersededInstance` | The same `agentInstanceId` reconnected; the older connection was evicted (close `4409`). Routine after a crash or a sleep — a burst of them is not |
| `unexpected_handshake_frame` / `client_unexpected_handshake_frame` | Hub / client dispatcher | A handshake frame arrived on an authenticated connection |
| `roster_update_rejected` | Client dispatcher | **Investigate.** A `status_update` carrying membership came from something other than this client's hub; membership is the hub's attestation alone |
| `message_dispatch_failed` / `client_message_dispatch_failed` | Hub / client dispatcher | A frame threw while being handled; the connection survived, the message did not |

Useful queries:

```bash
# every denial, newest last
grep '"authorization_denied"' ~/.omp/audit.log | tail -20

# anything that should never be routine
grep -E '"(pairing_rejected_invalid_sas|hub_pin_mismatch|.*_origin_mismatch)"' ~/.omp/audit.log

# what has actually executed on this machine
grep '"exec_executed"' ~/.omp/audit.log

# where received files went
grep '"file_transfer_received"' ~/.omp/audit.log | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{for(const l of s.split("\n").filter(Boolean))console.log(JSON.parse(l).finalPath)})'
```

Rotation: there is none. The file grows without bound; `readAuditLogs(limit)` only ever
parses the last `limit` lines, so a large file costs a full read. Archive it yourself if it
matters.

## /link shared

The sharing receipt. Rendered from `audit.log`, not from memory, so it survives restarts.

From a shell (the more complete of the two):

```bash
omp-link shared --limit 5
```

```
Sharing receipt — 5 of 5 security event(s) from /Users/you/.omp/audit.log

  2026-09-10 12:00:00  pairing_approved
    peer ed25519-sha256:CC:...
  2026-09-10 12:01:00  authorization_denied
    peer ed25519-sha256:CC:...
    action=rpc_request reason=Permission denied: action requires "inspectMetadata" capability, which is not granted to this device
  2026-09-10 12:02:00  permissions_updated
    peer linux-box
  2026-09-10 12:03:00  grant_created
    peer ed25519-sha256:CC:...
    workspace=default
  2026-09-10 12:03:20  exec_executed
    peer ed25519-sha256:CC:...

Revoke a device and all of its grants from inside the agent: /link revoke <device>
```

It selects 14 event types: the pairing decisions (approved, denied, both rejections), the
four grant lifecycle events, `exec_executed`, `exec_blocked`, `file_transfer_received`,
`permissions_updated`, `device_revoked`, `authorization_denied`. `--limit` clamps to
1..500, default 20; `--json` emits `{auditLog, exists, total, shown, entries}`.

Inside the agent:

```
/link shared
```

```
Security decisions on this machine (4 of 12 recorded):
  12:00:00Z pairing_approved             ed25519-sha256:CC:...
  12:01:00Z authorization_denied         ed25519-sha256:CC:...
  12:02:00Z permissions_updated          linux-box
  12:03:20Z exec_executed                ed25519-sha256:CC:...

Note: a served inspection RPC is not logged individually; denials are.
Full record: /Users/you/.omp/audit.log
Revoke every live command grant: /link revoke
```

The agent-side filter is `RECEIPT_EVENT_TYPES` in `index.ts`: the same decisions as the
CLI plus `local_sibling_admitted` and `hub_pin_mismatch`, minus `grant_expired`. Every name
in it is an event `src/` really emits, `file_transfer_received` included, so a file
transfer shows up on both surfaces. `--limit` clamps to 1..200, default 15; oldest of the
selected window first.

One thing to know before you trust a receipt: the peer column is the first identifying
field the record happens to carry. The agent tries `peer`, `displayName`, `principalId`,
`target`, `from` (truncated to 28 characters); the CLI tries `principalId`,
`peerPrincipalId`, `from`, `device`, `target`. Both lists include `target`, so
`permissions_updated` and `device_revoked` name the device instead of printing
`(unknown peer)`. A record carrying none of them falls back to `(unknown peer)` on the CLI
and `unknown` in the agent — read the raw line.

## Revoking

| Goal | Command | Effect |
|---|---|---|
| Kill all exec elevation now, keep pairings | `/link revoke` | `revokeAllGrants("Manual revoke all")` → `Revoked N active command grant(s). Paired devices are unchanged.` |
| Remove one device entirely | `/link revoke <device>` | Its grants revoked, record deleted, live socket closed `4403 Device pairing revoked`, audits `device_revoked` |
| Narrow a device without unpairing | `/link devices deny <device> content,diff,file` | Merges those capabilities off, live |
| Unpair without touching grants explicitly | `/link devices remove <device>` | `revokeDevice` — same underlying call |
| Cut this terminal off the mesh | `/link off` | `stop()` + `revokeAllGrants("Link deactivated")` |
| Stop hosting for everyone | `/link end --yes` | Every peer dropped |

Revocation is device-wide by design. `revokeGrantsForPrincipal(principalId)` without an
`agentInstanceId` removes grants for every terminal of that device — which is what
unpairing means. Pass an instance only when you intend to leave sibling terminals
elevated.

Re-pairing after a revoke requires a fresh SAS. The record is gone, so the next connection
takes the unpaired path.

If you suspect a key compromise on **your** machine, the device certificate is the thing
to replace:

```bash
# every peer that pinned the old SPKI will refuse the new one until re-paired
rm -rf ~/.omp/identity
```

## Operator checklist

Before you host a room:

- [ ] Would you accept the host reading every message and file in this room? It does.
- [ ] Is the export directory the one you meant? The workspace is `process.cwd()` —
      [concepts.md#workspace](concepts.md#workspace).
- [ ] Are you on a network where `9900` should be reachable? `lan` mode binds `0.0.0.0`.
- [ ] For experiments, is `OMP_DIR` pointed at a scratch directory?

Before you approve a pairing:

- [ ] Did you read the four words off the **other** screen, not off this link?
- [ ] Is `DEFAULT_PERMISSIONS` (messages + status) enough for now? Add capabilities later,
      per request.

Recurring:

- [ ] `omp-link shared` after any session where you granted something.
- [ ] `grep -E '"(pairing_rejected_invalid_sas|hub_pin_mismatch|.*_origin_mismatch)"' ~/.omp/audit.log`
      should stay empty.
- [ ] `/link devices` — anything in there you no longer recognise, `/link revoke`.
- [ ] `ls ~/.omp/inbox/*/*/` — quarantined files are untrusted until you read them.
