# Troubleshooting

Symptom → cause → fix. Symptoms are the literal strings the source produces; grep for them
if you are not sure which one you have.

- [Port 9900 is in use](#port-9900-is-in-use)
- [PAIRING_UNSUPPORTED_RUNTIME](#pairing_unsupported_runtime)
- [Pin mismatch](#pin-mismatch)
- ["Access Denied" and permission denials](#access-denied-and-permission-denials)
- [Transfers land in the inbox](#transfers-land-in-the-inbox)
- [Discovery finds nothing on Tailscale](#discovery-finds-nothing-on-tailscale)
- [Roster mismatch](#roster-mismatch)
- [A peer vanished from the roster](#a-peer-vanished-from-the-roster)
- [A peer looks stale, or appears twice](#a-peer-looks-stale-or-appears-twice)
- [A refused join](#a-refused-join)
- [The link went off and stayed off](#the-link-went-off-and-stayed-off)
- [Reading `doctor` line by line](#reading-doctor)
- [Close codes](#close-codes)

Related: [getting-started.md](getting-started.md), [security.md](security.md),
[commands.md](commands.md), [concepts.md](concepts.md). MCP-specific symptoms are in
[mcp.md](mcp.md#troubleshooting).

---

## Port 9900 is in use

### Symptom

```
Port 9900 is in use by something that is not an omp-link hub. Free the port or run /link doctor to see what is holding it.
```

or, when the holder *is* an omp-link hub on this machine:

```
A terminal on this machine is already hosting on port 9900. Joined it instead of starting a second room.
```

### Cause

`DEFAULT_PORT = 9900` is hardcoded (`src/discovery.ts`, `bin/omp-link.mjs`, `setup.sh`).
`startHub()` got `EADDRINUSE`, delivered through `handleServerError`. That handler is
attached to **both** `httpsServer` and `wss` before `listen()`, because `ws` forwards the
HTTP server's `error` event to the `WebSocketServer` — an unhandled emit there would kill
the terminal on a later tick, where no `try/catch` can see it. The audit line is
`hub_start_failed` with `code: "EADDRINUSE"`.

The second message is not a failure: `hostRoom` probed `127.0.0.1:9900/status`, got an
omp-link answer, and joined that sibling instead of pretending to create a second room.

### Fix

Identify the holder:

```bash
omp-link doctor
```

```
  tcp 9900:
    pid 54120 user you cmd node (this user)
    /status did not answer (ECONNREFUSED)
```

- **`/status did not answer` and it is your process** — probably a dead-ish agent or an
  unrelated dev server. Stop it yourself, or:

  ```bash
  omp-link cleanup --apply --yes
  ```

  which will still refuse unless it can prove the listener is an omp-link hub you own:

  ```
        REFUSING to stop it: the listener did not answer /status as an omp-link hub
        This CLI never signals a process it cannot prove is an omp-link hub owned by you.
  ```

- **`unknown (<reason>)`** — `lsof` was unavailable or gave nothing parseable. Ownership is
  unproven, so nothing will be signalled. Investigate by hand.
- **`/status answered`** — a real hub is running. Do not fight it. Join it:
  `/link on`, or `/link join 127.0.0.1:9900`.

There is no flag to move the port. If you need `9900` free, stop the holder.

---

## PAIRING_UNSUPPORTED_RUNTIME

### Symptom

On the joining side:

```
This runtime cannot derive a channel-bound verification code (TLS keying material export unavailable). Pairing is not possible here.
```

then close code `4409 Pairing unsupported`.

On the hosting side:

```
Pairing refused: no channel-bound verification code could be derived (PAIRING_UNSUPPORTED_RUNTIME)
```

then close `4409 Pairing unsupported on this runtime`, audited
`pairing_aborted_no_channel_binding`.

### Cause

`deriveLocalSas` throws `PAIRING_UNSUPPORTED_RUNTIME` when the socket it is handed has no
`exportKeyingMaterial` function:

```ts
if (!socket || typeof socket.exportKeyingMaterial !== "function") {
  throw new Error("PAIRING_UNSUPPORTED_RUNTIME");
}
```

Either the runtime does not implement RFC 5705 keying-material export (notably **Bun** —
this project is Node-only for exactly this class of reason), or the TLS socket could not be
reached through the WebSocket wrapper.

There is deliberately **no fallback**. A code derived from public handshake values alone
(SPKIs and nonces) is computable by a man-in-the-middle terminating both TLS sessions, who
could then make both displayed codes agree. Failing closed is the correct behaviour, not a
bug to work around.

### Fix

1. Run under Node, not Bun. Shebangs are `#!/usr/bin/env node` and `setup.sh` hard-fails
   below Node 18.

   ```bash
   node --version   # expect v18 or newer; v22 is what the suite runs on
   which -a node
   ```

2. Confirm which runtime the *agent* is using — the extension inherits the agent's process,
   not your shell:

   ```
   /link doctor
   ```

   ```
     version            3.4.0 (protocol 5)
   ```

   and from a shell, `omp-link doctor` prints the interpreter it is running under:

   ```
     node              22.23.2
   ```

3. If you are already on Node and still see this, use the **invite** path, which does not
   need a SAS: `/link invite` on the host, then
   `/link join <endpoint> <secret> <fingerprint>` on the joiner. Note the trade: possession
   of the secret replaces the out-of-band comparison.

---

## Pin mismatch

### Symptom

The common one, raised inside the TLS handshake by `checkServerIdentity` (`src/tls.ts`):

```
Could not rejoin "backend" at 192.168.1.42:9900: Server certificate pinning mismatch! Expected AA:BB:...:FF, received 11:22:...:99
```

The second, from the post-handshake re-check in `connectToHub`:

```
Could not join 192.168.1.42:9900: SPKI fingerprint mismatch: expected AA:BB:...:FF
```

and, when a fingerprint was supplied but the whole connection is refused as unpinned:

```
Unpinned hub certificate rejected (11:22:...:99). Initial pairing requires explicit trust confirmation.
```

### Cause

The SPKI fingerprint presented by the host does not equal the one this machine pinned.
Legitimate causes: the host reinstalled and lost `~/.omp/identity/`, you are talking to a
different machine at the same address, or a `paired_store_reset` wiped one side. The
illegitimate cause is someone else answering on that endpoint.

Nothing was sent either way. Pinning happens during the handshake, before any application
frame exists.

### Fix

1. **Compare fingerprints out of band.** On the host:

   ```
   /link status --verbose
   ```

   ```
   [verbose]
     device principal  ed25519-sha256:11:22:...:99
     device SPKI       11:22:...:99
   ```

   On the joiner:

   ```
   /link devices show mac-mini
   ```

   ```
   mac-mini
     principal    ed25519-sha256:AA:BB:...:FF
     SPKI         AA:BB:...:FF
     can          send messages
     workspaces   all registered
     paired       2026-09-10T12:00:00.000Z
     last seen    2026-09-10T12:04:11.000Z
   ```

2. **If the change is expected**, drop the stale pin and pair again with a fresh SAS:

   ```
   /link revoke mac-mini
   /link join 192.168.1.42:9900
   ```

3. **If it is not expected**, stop. Do not re-pair. Check the log on both machines:

   ```bash
   grep -E '"(hub_pin_mismatch|paired_store_reset)"' ~/.omp/audit.log
   ```

### Note: both mismatch wordings reach the blocked card

`joinEndpoint` sets `blockedReason` — which is what renders the
`Link · Blocked — identity changed` card and makes `requireUsable()` say
`Link is blocked: …` — whenever the error matches
`/fingerprint mismatch|pinning mismatch/i`. That covers both paths: the TLS-level failure
(`Server certificate pinning mismatch! …`, raised first by `checkServerIdentity`) and the
post-handshake re-check in `connectToHub` (`SPKI fingerprint mismatch: …`). In practice the
TLS one is what you see, because `checkServerIdentity` runs first.

The card and the error text say the same thing, and both mean:
**do not proceed until you have compared fingerprints.**

---

## "Access Denied" and permission denials

A denial always answers in the request's own protocol shape (`sendDenial`), so you learn
immediately instead of waiting out a timeout.

| You did | You get back | Rendered as |
|---|---|---|
| `link_exec` any inspection action | `rpc_response{error}` | `RPC execution error on "<peer>": Permission denied: action requires "<cap>" capability, which is not granted to this device` |
| `link_compact` | `compact_response{reason}` | `Compact request declined by "<peer>": Permission denied: …` |
| `link_send_file` | `file_ack{error}` | `File transfer failed: Permission denied: …` |
| `link_send`, or a `status_update` | `chat{text}` | `[<peer>] [Access Denied] Permission denied: action requires "message" capability, which is not granted to this device` |

The literal `[Access Denied]` prefix is the fallback arm of `sendDenial`, used for frame
types that have no reply shape of their own — chat, direct messages, status updates.

### Cause

`isActionPermitted` refused on the **receiving** machine. Read the `required` field in
its audit line to see which capability:

```bash
grep '"authorization_denied"' ~/.omp/audit.log | tail -3
```

```json
{"type":"authorization_denied","timestamp":1757500140000,"roomId":"6f1c...","principalId":"ed25519-sha256:CC:...","agentInstanceId":"1f0b...","action":"rpc_request","required":"inspectMetadata","reason":"Permission denied: action requires \"inspectMetadata\" capability, which is not granted to this device"}
```

Two distinct reason strings mean two different things:

- `…requires "<cap>" capability, which is not granted to this device` — the capability is
  **unset**. Grant it.
- `"<cap>" is explicitly denied for this device` — someone ran
  `/link devices deny <you> <cap>`. An explicit `false` always wins and `inspect: true`
  cannot override it. Someone must allow it again.
- `No device permissions attached to connection` — there is no record at all, e.g. the
  connection authenticated but the paired-device record was removed underneath it.
  Reconnect.

### Fix

Consent belongs to the machine that owns the files. **On the receiving machine:**

```
/link devices allow linux-box metadata
```

```
linux-box can now: send messages, see repo status
```

Capability-to-action mapping: [security.md#capabilities](security.md#capabilities). Default
pairings get `observe` and `message` only, so a fresh peer will be denied every inspection
action until someone opts in — that is the design, not a misconfiguration.

Three refusals that look like permission problems but are not:

| Text | Actually |
|---|---|
| `Remote execution is disabled on this node (requires --unsafe-remote-exec)` | That terminal was not launched with `--unsafe-remote-exec`; the flag is per-launch and never persisted, so it has to be given at every start. It is only the first gate — `execRequest` and a single-use grant still apply, and a peer past all three has local-user access — so prefer the structured actions |
| `Inspection concurrency limit exceeded (max 3 in flight)` | `MAX_CONCURRENT_RPCS` per peer. Serialise your calls |
| `Target peer "<x>" is not online` / `Peer "<x>" not found` | A routing miss. Run `link_list` and use a `name` from it verbatim |

---

## Transfers land in the inbox

### Symptom

```
File "schema.sql" transferred successfully to "mac-mini".
```

…and the receiving agent cannot find `schema.sql` anywhere in its repository.

### Cause

This is correct behaviour, not a bug. Received files are **quarantined outside the working
tree**:

```
<OMP_DIR>/inbox/<workspace>/rx-<pid>-<rand>-XXXXXX/<safeFilename>
```

- `<workspace>` is the receiver's session label, sanitised to `[a-zA-Z0-9_-]`.
- `rx-<pid>-<rand>-XXXXXX` is a staging directory created with `fs.mkdtempSync`, mode
  `0700`; the pid identifies the owning process so a concurrent terminal cannot reclaim a
  live transfer.
- `<safeFilename>` is `path.basename(offer.filename)` with everything outside
  `[a-zA-Z0-9._-]` replaced by `_`; a name starting `.` is refused outright
  (`Invalid or dangerous filename`).
- The file is `0600`.

`SECURITY.md` §6: files in the quarantine inbox are untrusted until explicitly audited and
copied into a working directory by the user. Nothing in omp-link will move them for you.

### Fix

Find it:

```bash
ls -la ~/.omp/inbox/*/*/
grep '"file_transfer_received"' ~/.omp/audit.log | tail -1
```

```json
{"type":"file_transfer_received","timestamp":1757500500000,"transferId":"c3f1...","from":"linux-box","finalPath":"/Users/you/.omp/inbox/backend/rx-54120-9a1b2c3d-Xk7Qp2/schema.sql"}
```

Then review and move it yourself:

```bash
cp ~/.omp/inbox/backend/rx-*/schema.sql ./migrations/
```

Both receipts list the transfer: the agent-side filter (`RECEIPT_EVENT_TYPES` in
`index.ts`) and the CLI's `SHARE_TYPES` each select the real `file_transfer_received`
event. Neither prints the destination path, so read `finalPath` from `audit.log` as above.

### If the transfer failed instead

| Error | Meaning |
|---|---|
| `Quarantine storage quota exceeded (max 250MB)` | Disk usage plus reserved bytes for in-flight offers would exceed `MAX_QUARANTINE_BYTES`. Clear the inbox |
| `Maximum concurrent transfers reached (max 5)` / `In-flight transfer limit reached for peer (max 2)` | Wait and retry |
| `Transfer timed out due to inactivity` (`transferInactivityMs`, 30 s by default) / `Absolute transfer timeout exceeded (<n>s)` (`transferAbsoluteMs`, 120 s by default) | Link stalled mid-transfer |
| `SHA-256 verification mismatch: expected <a>, got <b>` | Integrity failure; the staging file is discarded |
| `Staging file was deleted while the transfer was in flight; received data is lost` | Something removed the `.part` underneath the writer. The in-memory byte count and hash would both still pass, so this check is what turns silent loss into a visible failure |
| `Staging file was replaced before finalize; received data is lost` | Same class: the inode at the path is no longer the one written into |
| `Chunk order violation: expected index <n>, got <m>` | Chunks must be strictly sequential |
| `Outbound transfer of sensitive file ".env" is blocked` | Sender-side `isSensitivePath` |
| `File path escapes workspace root (<root>)` | Sender-side confinement |

Retention: completed quarantine files older than 7 days are purged on `TransferReceiver`
construction (`purgeQuarantineOlderThan`). Copy out anything you care about.

Housekeeping for abandoned staging directories:

```bash
omp-link cleanup            # preview
omp-link cleanup --apply    # remove only: owner pid dead AND idle past transferAbsoluteMs (120s by default)
```

---

## Discovery finds nothing on Tailscale

### Symptom

```
No hubs responded on tailscale.
```

or from the tool:

```
No omp-link hubs responded on LAN or Tailscale.
```

### Cause and fix, in check order

**1. Is the mode actually `tailscale`?**

```
/link doctor
```

```
  network            lan · lan 192.168.1.42 · tailscale 100.94.12.7
```

If that says `lan`, the Tailnet branch of `discoverAllHubs` never runs — the mode gates it.
There is no command to change this; `link-network` was removed with no replacement. Edit
`<OMP_DIR>/link.json` and restart the agent:

```bash
node -e '
const fs=require("fs"),p=process.env.HOME+"/.omp/link.json";
const c=fs.existsSync(p)?JSON.parse(fs.readFileSync(p,"utf8")):{};
c.network="tailscale";
fs.writeFileSync(p,JSON.stringify(c,null,2)+"\n",{mode:0o600});'
```

**2. Does omp-link find the `tailscale` binary?**

```bash
omp-link doctor
```

```
  tailscale         /Applications/Tailscale.app/Contents/MacOS/Tailscale
```

`(not found)` means `resolveTailscaleBin` failed all four candidates: `tailscale`,
`/Applications/Tailscale.app/Contents/MacOS/Tailscale`, `/usr/local/bin/tailscale`,
`/opt/homebrew/bin/tailscale`. Symlink yours into one of those paths.

**3. Does this machine have a Tailscale IPv4 that omp-link recognises?**

```
  network            tailscale · lan 192.168.1.42 · tailscale not detected
```

`getNetworkInfo` accepts a non-internal IPv4 starting `100.` whose second octet is 64–127.
`tailscale ip -4` should print such an address. Without one, hosting fails outright:

```
Failed to host "backend": Tailscale IPv4 address not found. Ensure Tailscale is running or switch to LAN mode.
```

**4. Is the peer reported *online*?** Offline peers are skipped entirely:

```bash
tailscale status --json | node -e '
let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{
const j=JSON.parse(s);
for (const p of Object.values(j.Peer||{}))
  console.log((p.Online?"online ":"offline"), (p.TailscaleIPs||[]).find(i=>i.startsWith("100.")), p.HostName);
});'
```

```
online  100.94.12.9 linux-box
offline 100.94.12.31 old-laptop
```

**5. Is the hub actually reachable and answering?** Discovery only counts an endpoint that
returns valid JSON from `GET /status` with `service === "omp-link"` and
`protocolVersion === 5`:

```bash
curl -sk --max-time 3 https://100.94.12.9:9900/status
```

```json
{"service":"omp-link","protocolVersion":5,"roomId":"6f1c0a5e-...","spkiFingerprint":"AA:BB:...:FF","certificateFingerprint":"AA:BB:...:FF","principalId":"ed25519-sha256:AA:BB:...:FF","pairingAvailable":true,"transport":"wss"}
```

No answer means it is a reachability or hosting problem, not a discovery problem. A hub in
`tailscale` mode binds **only** to its `100.x` address, so probe that address, not the LAN
one.

**6. Do not wait for discovery.** Discovery is a convenience; joining by address is always
available and is the same trust path:

```
/link join 100.94.12.9:9900
```

Also note: in `tailscale` mode the LAN UDP sweep is skipped and nothing listens on UDP
`9901`, so a Tailnet host is invisible to LAN discovery by design.

---

## Roster mismatch

### Symptom

The hub lists two agents; the client lists only itself.

### Cause

A client has no inbound connections of its own. `getConnectedTerminalsList()` returns
`[self, ...hubRoster]`, and `hubRoster` is only ever populated by `absorbRoster`, from
`server_hello.terminals` at authentication and from later `status_update` frames.

Two ways it can be empty:

- The hub authenticated the client through a path that sends `server_hello` **without**
  `terminals`. The invite branch inside `initiatePairingForSocket` is such a path.
- `status_update` frames are being denied. They require the `observe` capability, and
  `broadcastTerminalList` sends them as ordinary application frames — so a client whose
  stored record for the hub lacks `observe` drops its own roster updates and audits
  `authorization_denied` with `required: "observe"`.

### Fix

```bash
grep '"authorization_denied"' ~/.omp/audit.log | grep observe
```

If that matches, the client's stored record for the hub is missing `observe` — and you
cannot add it back with `devices allow`, because there is no `observe` token in
`CAPABILITY_FIELDS`:

```
/link devices allow hub observe
```

```
Unknown capability: observe. Nothing was changed.
Capabilities: message, compact, inspect, metadata, inspectmetadata, content, readcontent, diff, readdiff, file, fileinbox, exec, execrequest
```

Fix the record another way: `/link revoke hub` then re-join, which writes a fresh
`DEFAULT_PERMISSIONS` record (which includes `observe`).

Otherwise force a fresh roster broadcast by having any peer connect or disconnect —
`broadcastTerminalList` runs on both — or reconnect the client with `/link off` then
`/link on`.

---

## A peer vanished from the roster

### Symptom

```
"linux-box" stopped responding (30s) and was removed from the room.
```

On the peer's own machine, if it is alive enough to say so:

```
Lost contact with the link hub (silent for 45s). Disconnected.
```

### Cause

This is the liveness sweep doing its job, not a bug. Every `heartbeatIntervalMs` each side
pings; a hub drops an authenticated peer once `heartbeatIntervalMs *
heartbeatMissesBeforeDrop` passes with **nothing** inbound — no pong and no frame — and a
client declares its hub gone after `clientHubSilenceTimeoutMs`. Defaults are 15 s × 2 = 30 s
on the hub and 45 s on the client
([concepts.md#liveness-and-ttl](concepts.md#liveness-and-ttl)).

The usual real causes, in order of frequency: the peer's laptop slept, the peer process was
suspended (`SIGSTOP`, a debugger, a `Ctrl-Z`), or Wi-Fi dropped. A `SIGSTOP`ped process
still ACKs at the TCP layer, which is exactly why the socket staying "open" proves nothing.

In `audit.log` the drop is two lines, in this order:

```bash
grep -E '"(peer_liveness_timeout|peer_disconnected|hub_liveness_timeout)"' ~/.omp/audit.log | tail -5
```

```json
{"type":"peer_liveness_timeout","timestamp":1757500900000,"roomId":"6f1c...","principalId":"ed25519-sha256:CC:...","agentInstanceId":"1f0b...","peer":"linux-box","silentMs":31004,"logSeq":42}
{"type":"peer_disconnected","timestamp":1757500900001,"principalId":"ed25519-sha256:CC:...","peer":"linux-box","logSeq":43}
```

| Event | Written by | Read it as |
|---|---|---|
| `peer_liveness_timeout` | The hub | *This* machine gave up on a peer after `silentMs` of silence; close `4408` |
| `hub_liveness_timeout` | The client | *This* machine gave up on its hub; the node went `disconnected`, which is what can trigger local succession |
| `peer_disconnected` | The hub | The ordinary teardown that follows: grants revoked, transfers cleaned, roster rebroadcast |

A liveness drop is not a separate code path: grants are revoked, in-flight transfers and
pending requests are failed with a real reason, and the roster is rebroadcast, exactly as
for a clean disconnect.

### Fix

Nothing to repair on the hub — the roster is now correct. On the peer, reconnect with
`/link on`; there is no reconnect backoff, so a client of a remote hub stays off until
someone acts.

If peers are being dropped while they are demonstrably alive (a slow link, a heavily
loaded machine, a VM that stalls for seconds at a time), raise the budget in
`<OMP_DIR>/link.json` and restart the terminal:

```json
{ "timings": { "heartbeatIntervalMs": 30000, "heartbeatMissesBeforeDrop": 3, "clientHubSilenceTimeoutMs": 120000 } }
```

Keep the client's timeout comfortably longer than the hub's `interval × misses`. If a
client gives up first it moves to `disconnected` and may trigger a local hub takeover for
a hub that was merely slow, which is the worse failure
([concepts.md#liveness-and-ttl](concepts.md#liveness-and-ttl)).

---

## A peer looks stale, or appears twice

### Symptom

`link_list` names an agent you know is gone, or the same terminal appears twice — often one
of them suffixed `@<6 hex>`.

### Cause

Two different things, with two different audit lines.

**Stale, briefly.** Until the sweep fires, a peer that died without closing its socket is
still in the roster. That window is bounded by the detection budget, not by TCP: worst case
`heartbeatIntervalMs * (heartbeatMissesBeforeDrop + 1)` — 45 s at the defaults — because
the check itself only runs once per interval. Before this existed there was no bound at all.

**Twice.** A terminal that reconnects after a crash, a sleep or a flap presents the same
`agentInstanceId` on a fresh TLS session. The hub evicts the older connection rather than
carrying both:

```bash
grep '"peer_connection_superseded"' ~/.omp/audit.log | tail -3
```

The evicted socket is closed `4409 Superseded by a newer connection from the same agent`.
If instead you see two entries that *persist*, they are two real terminals on one machine:
same device principal, different `agentInstanceId`, and `uniqueDisplayName` suffixed the
second one `@<6 hex>` and audited `display_name_collision`. Give them distinct names with
`--link-name` (or `--name` for the MCP server, [mcp.md](mcp.md)).

### Fix

Wait out the detection budget before concluding anything is wrong; `link_list` is a cache
of the hub's roster, and the hub only learns by ping. If a name is still there a minute
later, check that terminal's own state — a peer that is answering pings is not gone.

---

## A refused join

### Symptom

You ran `/link join`, the host denied the request or the code did not match, and you want
to know whether this terminal is left half-connected.

### What happens

A refusal is a closed socket. `LinkNode` reports it through `onHubDisconnected`, and the
extension clears `awaitingPairing`, drops the transition, redraws the status line and says
so:

```
The host at 192.168.1.42:9900 closed the connection before admitting this agent.
Nothing was shared. It was refused, timed out, or the code did not match — ask for a new code and run /link join 192.168.1.42:9900 again.
```

`linkState()` consults `awaitingPairing` before it looks at the node, so with the flag
cleared the card falls back to `Link · Off` by itself. No `/link off` is required, and the
tools stop answering `Not connected yet: this agent is waiting to be verified by the host.`

### Fix

Re-run `/link join <ip:port>` for a fresh request id and code. Trust the notification you
received —

```
Pairing rejected: Verification code did not match
```

— and if the card is somehow still on `Link · Pairing — not connected yet` while the host
says it refused you, the close never reached this process: `/link off` resets the terminal
unconditionally.

---

## The link went off and stayed off

### Symptom

```
Link · Off
No room. Nothing on this machine is shared.
```

after having been connected, with no action from you.

### Cause

The hub's process exited, the transport failed, or the hub went silent. On the client
`ws.on("close")` sets `role = "disconnected"` and fires `onHubDisconnected`; a hub that
stops answering without closing anything reaches the same state through the client's
liveness sweep after `clientHubSilenceTimeoutMs` (45 s by default), audited
`hub_liveness_timeout`. `linkState()` maps a node in that role to `off`. **There is no
reconnect backoff in v3.4.0**, so a client of a *remote* hub stays off until you act.

If the hub was a sibling terminal on **this machine**, it is different:
`onHubDisconnected` calls `attemptLocalSuccession`, and one of the survivors takes the room
over on its own. After a randomised 0.4–1.6 s delay (`SUCCESSION_BASE_DELAY_MS` plus
jitter, so two survivors do not race in lockstep) it re-probes `127.0.0.1:9900` and either
joins whoever won the port or calls `startHub()` itself, audits `local_hub_succession` and
announces it:

```
The terminal hosting "backend" exited. This terminal is now hosting the room; peers keep the same pinned identity and reconnect automatically.
```

Read that last clause narrowly: remote peers keep a valid pin because the successor
presents the same device certificate, but with no reconnect backoff they still rejoin by
running `/link on`.

Two limits on that. `/link off` sets `intentionalDisconnect`, so leaving deliberately never
triggers a takeover — only a hub that vanished does. And succession is **local only**: when
the last terminal on the hosting machine exits there is nobody left to succeed it and the
room ends. Remote peers then have no hub to reconnect to.

If the hub tore *itself* down, there is a log line:

```bash
grep -E '"(hub_server_error|hub_start_failed)"' ~/.omp/audit.log | tail -2
```

### Fix

Wait a couple of seconds first: if another terminal on the hosting machine is still alive,
succession has probably already happened and the card comes back by itself. Otherwise:

```
/link on
```

On the machine that used to host, this re-hosts the **same** `roomId` under the **same**
device certificate, so remote pins stay valid and nobody re-pairs. On a remote machine it
rejoins the remembered endpoint pinned to the remembered fingerprint — including after a
local succession on the other side, because the successor presents the same device
certificate. Full walkthrough:
[scenarios.md#d-the-hosting-terminal-exits](scenarios.md#d-the-hosting-terminal-exits).

Do **not** use `/link create` to recover — it mints a new `roomId`.

---

## Reading `doctor`

Two different reports share the name. `omp-link doctor` inspects the **installation and the
machine**; `/link doctor` inspects the **live node**. Run both.

### `omp-link doctor`

```
omp-link doctor — measured values only

  version           3.4.0
  repo              /Users/you/omp-link
  node              22.23.2
  platform          darwin arm64
  state dir         /Users/you/.omp
  agent binary      omp
  tailscale         /Applications/Tailscale.app/Contents/MacOS/Tailscale

  identity:
    device-cert.pem   mode 600
    device-key.pem    mode 600

  install links:
    ok            /Users/you/.local/bin/omp-link -> /Users/you/omp-link/bin/omp-link.mjs
    ok            /Users/you/.local/bin/pi-link -> /Users/you/omp-link/bin/omp-link.mjs
    ok            /Users/you/.omp/agent/extensions/omp-link -> /Users/you/omp-link
    ok            /Users/you/.pi/agent/extensions/omp-link -> /Users/you/omp-link

  tcp 9900:
    nothing listening
    /status did not answer (ECONNREFUSED)

  Note: the hub terminates TLS and routes every message. There is no client-to-client
  end-to-end encryption; see SECURITY.md section 1.
```

| Line | Reads | Bad value means |
|---|---|---|
| `version` | `package.json` at runtime | `unknown` → the manifest could not be read |
| `repo` | The checkout `bin/omp-link.mjs` lives in | Not where you expect → you are running a different copy; `omp-link update` will update *that* one |
| `node` | `process.versions.node` | `(UNSUPPORTED: needs >= 18)` → exit code `3`; upgrade Node |
| `platform` | `process.platform` + arch | — |
| `state dir` | `resolveOmpDir()` | `(missing)` → nothing has been created yet, which is fine before first use |
| `agent binary` | `OMP_BIN`, `PI_BIN`, then `omp`/`pi` on PATH and known install dirs | `(not found: install omp or set OMP_BIN)` → the launcher cannot start the agent |
| `tailscale` | Four candidate paths | `(not found)` → Tailnet discovery is impossible |
| `identity:` | Mode bits of `device-{cert,key}.pem` | `absent (created on first use)` before first run. **Anything other than `mode 600` on the key is a finding** |
| `install links:` | `lstat` + `readlink` of four paths | `dangling` → re-run `./setup.sh`, or `omp-link cleanup --apply`. `not-a-symlink` → a real directory is shadowing the symlink; remove it. `absent` for both `.omp` and `.pi` → the extension will not load |
| `tcp 9900:` | `lsof`-based owner probe | `nothing listening` → no hub here. `pid … (this user)` → you own it. `ownership NOT proven: <reason>` → cleanup will refuse to touch it |
| `/status …` | HTTPS probe of `127.0.0.1:9900` | `answered: room <id>, protocol v5, TLSv1.3` → a healthy local hub. `did not answer (ECONNREFUSED)` → nothing there. Answering on the port but **not** as omp-link → a foreign listener |
| `certificate chain NOT validated by this probe` | Always printed when it answers | Expected. The probe uses `rejectUnauthorized: false`; real verification is app-level pinning |
| `Note:` | Always printed | The honest topology statement. Not a warning |

Machine-readable form, same fields:

```bash
omp-link doctor --json
```

### `/link doctor`

```
omp-link doctor
  version            3.4.0 (protocol 5)
  device principal   ed25519-sha256:AA:BB:...:FF
  state directory    /Users/you/.omp
  paired devices     1
  link state         hosting
  listening          0.0.0.0:9900
  port 9900          omp-link hub, room 6f1c0a5e-...
  network            lan · lan 192.168.1.42 · tailscale 100.94.12.7
  config             /Users/you/.omp/link.json (file values in force)
  audit events       50 recent
```

| Line | Reads | Bad value means |
|---|---|---|
| `version` | Registry + `PROTOCOL_VERSION` | Protocol must be `5` on both machines; a mismatch closes frames `4400 Unsupported protocol version; expected 5, got <n>` |
| `device principal` | `getOrCreateDeviceIdentity()` | This is what peers pin. Compare it against their `/link devices show` |
| `state directory` | `getOmpDir()` | Not the directory you meant → check `OMP_DIR` |
| `paired devices` | `loadPairedDevices().size` | `0` after you expected pairings → look for the reset note |
| `NOTE` | `wasPairedStoreReset()` | `the paired-device store was reset by an upgrade; re-pair your devices` — every device must re-pair. There is deliberately no migration |
| `link state` | `linkState()` | `off`, `starting`, `pairing`, `hosting`, `connected`, `reconnecting`, `blocked`. `blocked` means a pin mismatch and will not auto-retry |
| `listening` | Hub only: `bindHost:port` | `0.0.0.0` in `lan` mode, the `100.x` address in `tailscale` mode. `127.0.0.1` means loopback-only |
| `port 9900` | Live loopback `/status` probe | `no omp-link hub responded` while `link state` is `hosting` → you are bound to a non-loopback interface only, or the listener died |
| `tls to host` | Client only: `socket.getProtocol()` on the live socket | Must be `TLSv1.3`. `not connected` while the card claims connected is a contradiction worth reporting |
| `host identity` | Client only | `<principal>… pinned` is good; `unverified` means no certificate was captured |
| `network` | `networkMode` + `getNetworkInfo()` | `tailscale not detected` while mode is `tailscale` → hosting will fail |
| `config` | `loadConfig()`, re-read at each run | `(defaults in force)` while you expected your edits → the file is missing, unreadable, or contributed no recognised setting. A `config problem` line follows with the reason and the fix ([concepts.md#configuration-linkjson](concepts.md#configuration-linkjson)) |
| `config problem` | `LoadedConfig.warning` | Printed only when the file has a defect: bad JSON, a `rooms` value that is not a list, unusable room records, or rejected timing values |
| `audit events` | `readAuditLogs(50).length` | `0` → nothing has been logged, or the log is unwritable |
| `AUDIT LOG` | `getAuditLogStatus()` | `NOT WRITABLE — security decisions are not being recorded`, with the reason and the directory to fix. Until this is clear, every "no denials recorded" reading is unreliable |

## Close codes

Seen in `ws` close events and in `parseWireMessage` results.

| Code | Meaning | Typical reason string |
|---|---|---|
| `1000` | Normal | `Link shutting down`, `Disconnected` |
| `4400` | Protocol/schema | `Malformed JSON frame: …`, `Unsupported protocol version; expected 5, got 4`, `Unknown message type: "…"`, `Duplicate hello message rejected`, `Handshake frame "…" forbidden after connection is authenticated`, `client_hello displayName is empty after sanitising` |
| `4403` | Authorization / phase / SAS | `Mutual TLS client certificate required`, `Message "…" forbidden in phase "tls-connected" (expected hello)`, `Application traffic strictly prohibited before device pairing approval`, `SAS verification mismatch`, `Device pairing revoked`, `Pairing denied` |
| `4408` | Timeout | `Handshake timeout (<n>s)` (`handshakeTimeoutMs`, 10 s by default), `Pairing request timed out after <n>s` (`pairingWindowMs`, 60 s), `No response for <n>s` (liveness sweep, 30 s) |
| `4409` | Oversized frame, unpairable runtime, or superseded connection | `Frame exceeds maximum permissible size of 2097152 bytes`, `Pairing unsupported on this runtime`, `Superseded by a newer connection from the same agent` |
| `4429` | Rate limit | `Connection rate limit exceeded` (60/min/IP), `Pairing rate limit exceeded` (10/min/IP), `Pairing queue full (maximum 16 requests)` |

A `4403 Mutual TLS client certificate required` at connect time means the client presented
no certificate — check that its `<OMP_DIR>/identity/` exists and is readable.
