# Worked scenarios

Five situations you will actually be in, walked through end to end with the real output.

- [(a) Two codebases on one machine](#a-two-codebases-on-one-machine)
- [(b) Two machines on a LAN](#b-two-machines-on-a-lan)
- [(c) Two machines over Tailscale](#c-two-machines-over-tailscale)
- [(d) The hosting terminal exits](#d-the-hosting-terminal-exits)
- [(e) Nested repositories](#e-nested-repositories)

Related: [getting-started.md](getting-started.md), [concepts.md](concepts.md),
[security.md](security.md).

---

## (a) Two codebases on one machine

Goal: an agent in `~/work/api` and an agent in `~/work/web`, on the same laptop, able to
inspect and message each other. **No pairing prompt appears** — and that is intentional.

### Terminal 1 — `~/work/api`

```
/link create backend
```

```
Hosting room "backend" on 192.168.1.42:9900.
No peer is admitted until you approve it. Share access with /link invite.
```

### Terminal 2 — `~/work/web`

Run the same command. Do not try to invent a second room name.

```
/link create backend
```

```
A terminal on this machine is already hosting on port 9900. Joined it instead of starting a second room.
```

What happened, step by step (`hostRoom` → `findLocalHub` → `joinEndpoint`, `index.ts`):

1. `startHub()` rejected with `EADDRINUSE`. The rejection is delivered by
   `handleServerError`, one idempotent handler attached to **both** `httpsServer` and
   `wss` before `listen()` — `ws` forwards the HTTP server's `error` to the
   `WebSocketServer`, and an unhandled emit there would kill the terminal on a later tick.
   Audited as `hub_start_failed`.
2. `findLocalHub()` did `GET https://127.0.0.1:9900/status` and got an omp-link answer.
3. `joinEndpoint("127.0.0.1:9900", { pinnedFingerprint: node.identity.fingerprint })` —
   pinned to **this device's own** SPKI, so the loopback join is not TOFU.
4. Terminal 1's hub saw a client certificate whose `principalId` equals its own, took the
   sibling branch in `handleHubClientHello`, and admitted it directly.

### Why no pairing prompt

```ts
if (peerCert.principalId === this.identity.principalId) {
  ctx.principalId = peerCert.principalId;
  ctx.permissions = { ...FULL_PERMISSIONS };
  appendAuditLog({ type: "local_sibling_admitted", ... });
```

The peer proved possession of this device's private key. `SECURITY.md` §7 already treats
local compromise of `<OMP_DIR>` as defeating device identity, so asking you to compare a
code against yourself would add nothing. Check the log:

```bash
grep local_sibling_admitted ~/.omp/audit.log
```

```json
{"type":"local_sibling_admitted","timestamp":1757500000000,"roomId":"6f1c...","principalId":"ed25519-sha256:AA:BB:...","agentInstanceId":"9d2e...","remoteAddress":"127.0.0.1"}
```

**Be clear-eyed about the consequence:** local siblings get `FULL_PERMISSIONS`, in both
directions. The hub grants them to the sibling's context; `applyStoredHubPermissions`
grants them symmetrically on the client side when the hub's principal is our own. So the
`web` agent can `read_file` inside `api`, and vice versa. That is the intended trust
boundary — one machine, one user — but do not host a room on a machine where you would not
accept that.

### Separate agent instances

```
/link status --verbose
```

```
Link · Connected
Room          backend
This agent    mac-mini · web (this)
Other agents  1
Network       lan · host 127.0.0.1:9900 · SPKI verified

Agent                Workspace        Identity
mac-mini@a1b2c3      api              ed25519-sha256:AA:BB:C…

[verbose]
  device principal  ed25519-sha256:AA:BB:...:FF
  device SPKI       AA:BB:...:FF
  agent instance    9d2e7c41-...
  room id           6f1c0a5e-...
  config            /Users/you/.omp/link.json
```

Two things to read off that card:

- `Workspace` is `path.basename(msg.cwd)` from `client_hello`, so the two terminals are
  distinguishable as `api` and `web`.
- The display name was disambiguated to `mac-mini@a1b2c3` because both terminals default
  `terminalName` to `os.hostname()`. `uniqueDisplayName`, called from
  `handleHubClientHello`, appends the `@<6 hex>` stub only when the *agent instance*
  differs — i.e. exactly when they are genuinely two terminals — and audits every
  collision as `display_name_collision`. These two are siblings with no paired record, so
  the name they send is used; for a device the hub has already paired, the locally stored
  `deviceName` is authoritative and the name on the wire is ignored.

To avoid the suffix, name them at launch. `--link-name` wins over `link.json`'s
`terminalName`, which wins over `os.hostname()`; there is still no slash command to set it:

```bash
omp --link-name api   # terminal 1
omp --link-name web   # terminal 2
```

`--link` is honoured at the same level: when it is set, `index.ts` registers a
`session_start` hook that calls `resumeRoom`, so the terminal rejoins its remembered room
without you typing `/link on`.

For real isolation rather than a display name, give each terminal its own state root:

```bash
# per-terminal isolation, before launching the agent
OMP_DIR=~/.omp-api  omp   # terminal 1
OMP_DIR=~/.omp-web  omp   # terminal 2
```

Note that separate `OMP_DIR`s give separate **device identities**, so the two terminals
stop being siblings and will pair with a SAS like any two machines.

### Separate exec grants

Exec grants key on `(principalId, agentInstanceId)`:

```ts
const activeExecGrants = new Map<string, ExecGrant>();  // `${principalId}::${agentInstanceId}`
```

so a grant issued to the `api` terminal is never consumed by the `web` terminal even
though both are the same device principal. `/link revoke <device>` with no instance is
device-wide on purpose (it also unpairs).

> **Exec is off unless that terminal was launched with `--unsafe-remote-exec`.** `index.ts`
> registers the flag (`pi.registerFlag("unsafe-remote-exec", …)`) and passes its value to
> the node as `allowRemoteExec`; it is deliberately never written to `link.json`, so every
> terminal has to re-state it at each start. Without it `link_exec action="exec"` answers
> `Remote execution is disabled on this node (requires --unsafe-remote-exec)`, and
> `/link grant` refuses up front with
> `Remote command execution is disabled on this terminal, so a grant would do nothing. Nothing was granted. To enable it, restart this terminal with --unsafe-remote-exec; that peer would then be able to run commands as your local user. Structured inspection (link_exec git_status, git_diff, read_file, list_dir) needs no grant.`
> With the flag on, the other two gates still stand — `execRequest` on the device record
> and a live single-use grant — and a peer that passes all three runs commands as your
> local user. Structured inspection (`git_status`, `read_file`, …) needs none of it.

---

## (b) Two machines on a LAN

Machine A hosts, machine B joins. Full first-run flow with output:
[getting-started.md](getting-started.md). This section covers the invite shortcut and what
to check afterwards.

### Invite instead of reading a code aloud

On the host:

```
/link invite
```

```
One-time invite, expires in 5 minutes. Single use.
  On the other machine run:
  /link join 192.168.1.42:9900 f3a9...c1 AA:BB:...:FF
```

The three positionals are `<endpoint> <invite-secret> <fingerprint>`. The secret is 32
random bytes hex from `createInvite`, held **in memory only** (`activeInvites`), single-use
(`verifyAndConsumeInvite` sets `used` and deletes), 5 minute expiry. It dies with the
hosting process.

An invite trades the SAS comparison for possession of the secret: `handleHubClientHello`
sees `msg.inviteSecret`, validates it, writes a `PairedDevice` with
`DEFAULT_PERMISSIONS`, sends `server_hello{requiresPairing:false}` and moves straight to
`authenticated`. Use it when you can paste over an already-trusted channel; use the SAS
when you cannot.

Rejection reasons, verbatim from `verifyAndConsumeInvite`: `Invitation not found`,
`Invitation already consumed`, `Invitation expired`. An invalid invite does not fail the
connection — it falls through to normal pairing, so you get a SAS prompt instead.

### After joining, verify

```
/link peers          # both sides must show the same two agents
omp-link shared      # the pairing decision, from audit.log
```

Firewall checklist for LAN mode:

| Port | Protocol | Direction | Used by |
|---|---|---|---|
| 9900 | TCP | inbound to the host | `httpsServer.listen`, the wss upgrade and `GET /status` |
| 9901 | UDP | inbound to the host | `startUdpDiscoveryResponder`: answers `OMP_LINK_DISCOVER` with `OMP_LINK_HUB_V5:<port>` |

Only `9900` is required. `9901` is discovery convenience; you can always
`/link join <ip>:9900` by address.

---

## (c) Two machines over Tailscale

### What changes

**1. `networkMode` must be `tailscale`.** There is no command for this — the only reader
is `config.network` in `index.ts`, and the `link-network` verb was removed in 3.4.0 with
no replacement (`REMOVED_COMMANDS["link-network"] = null`). Edit the config directly,
before launching the agent:

```bash
node -e '
const fs=require("fs"),p=process.env.HOME+"/.omp/link.json";
const c=fs.existsSync(p)?JSON.parse(fs.readFileSync(p,"utf8")):{};
c.network="tailscale";
fs.writeFileSync(p,JSON.stringify(c,null,2)+"\n",{mode:0o600});
console.log(c);'
```

Confirm from inside the agent:

```
/link doctor
```

```
  network            tailscale · lan 192.168.1.42 · tailscale 100.94.12.7
```

**2. The hub binds to the Tailscale IP, not `0.0.0.0`.** `startHub()`:

```ts
if (this.networkMode === "tailscale") {
  const net = getNetworkInfo();
  if (!net.tailscaleIp) {
    throw new Error("Tailscale IPv4 address not found. Ensure Tailscale is running or switch to LAN mode.");
  }
  this.bindHost = net.tailscaleIp;
}
```

`getNetworkInfo` recognises a Tailscale address as non-internal IPv4 starting `100.` whose
second octet is 64–127 (the CGNAT range Tailscale uses). If Tailscale is down you get that
error verbatim, rendered as
`Failed to host "backend": Tailscale IPv4 address not found. Ensure Tailscale is running or switch to LAN mode.`

The room's endpoint is then the Tailnet address:

```
Hosting room "backend" on 100.94.12.7:9900.
No peer is admitted until you approve it. Share access with /link invite.
```

**3. LAN UDP discovery is off.** Two independent reasons: `startHub` only starts the
responder when `networkMode === "lan"`, and `startUdpDiscoveryResponder` returns `null`
for any `bindHost` beginning `100.`. Nothing listens on UDP `9901`, and nothing broadcasts
either — `discoverAllHubs` skips the UDP sweep unless the mode is `lan` or `all`.

**4. Discovery uses `tailscale status --json`.** `discoverAllHubs` resolves the binary from
`tailscale`, `/Applications/Tailscale.app/Contents/MacOS/Tailscale`, `/usr/local/bin/tailscale`,
`/opt/homebrew/bin/tailscale`, then walks `Peer[*]`, keeps peers with `Online === true`,
takes the first `TailscaleIPs` entry starting `100.`, and probes
`https://<ip>:9900/status`. Verify the same view by hand:

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

An offline peer is never probed, so a peer that Tailscale reports offline will not appear
in `/link scan` even if it is actually reachable. Join it by address instead.

### What does not change

| Unchanged | Why |
|---|---|
| Pairing and the 4-word SAS | `initiatePairingForSocket` is transport-agnostic; the SAS is bound to the TLS session, not to the network |
| SPKI pinning | `getClientTlsOptions.checkServerIdentity` compares fingerprints regardless of mode |
| Capabilities | `isActionPermitted` never consults `networkMode` |
| Quarantine, path confinement, exec gates | Same code paths |
| Port 9900 | Hardcoded `DEFAULT_PORT`; Tailscale changes the address, not the port |

`SECURITY.md` §10 states it directly: *"Tailscale membership does not automatically imply
omp-link authorization."* Being on the tailnet gets you a TCP connection and nothing else.

### The mixed-mode trap

`networkMode` is one value per terminal, and it selects discovery *and* bind address. A
host in `tailscale` mode binds only to `100.x` and is unreachable from the LAN address; a
host in `lan` mode binds `0.0.0.0` and *is* reachable over Tailscale, but will not answer
Tailnet discovery. If Tailnet peers cannot find a LAN-mode host, join it by its Tailscale
address explicitly:

```
/link join 100.94.12.7:9900
```

---

## (d) The hosting terminal exits

### What actually happens

The hub is a server inside a terminal process. When that process exits, the listener goes
with it. On every client:

1. `ws.on("close")` → `role = "disconnected"`, `clientContext = null`, `hubRoster = []`.
2. `onTerminalsChanged` fires, `updateStatusLine()` runs, and `linkState()` returns `off`
   (a non-null node whose role is `disconnected` is explicitly mapped to `off`).
3. The card is honest about it:

```
/link status
```

```
Link · Off
No room. Nothing on this machine is shared.

  /link scan            see who is reachable
  /link join <ip:port>  join an existing room
  /link create <name>   host a new room
```

That is the state before anything recovers. On a machine that still has another terminal in
the room it lasts about a second — see below.

### Automatic succession, when another terminal on that machine is alive

Terminals on one machine share a device certificate, which is what makes hosting
transferable: a successor presents exactly the identity remote peers already pinned. So the
client's `ws.on("close")` fires `onHubDisconnected`, `index.ts` calls
`attemptLocalSuccession`, and for a room whose endpoint is `127.0.0.1` the survivor

1. waits `SUCCESSION_BASE_DELAY_MS` (400 ms) plus up to 1.2 s of jitter — randomised so two
   survivors do not race in lockstep — and stops if the link became usable meanwhile;
2. re-probes `127.0.0.1:9900` and joins whoever already claimed the port;
3. otherwise calls `startHub()` itself, audits `local_hub_succession`, and announces it:

```
The terminal hosting "backend" exited. This terminal is now hosting the room; peers keep the same pinned identity and reconnect automatically.
```

A hub that does not exit but stops answering reaches the same place by a different route:
the survivor's client-side liveness sweep declares the hub gone after
`clientHubSilenceTimeoutMs` (45 s by default), audits `hub_liveness_timeout`, and that
transition fires the same `onHubDisconnected`. That timeout is deliberately longer than the
hub's own peer deadline, precisely so a busy hub is not taken over by mistake
([concepts.md#liveness-and-ttl](concepts.md#liveness-and-ttl)).

If `startHub()` loses the race for the port it falls back to joining the winner. Confirm it
happened:

```bash
grep local_hub_succession ~/.omp/audit.log
```

Two limits, both deliberate. A `/link off` sets `intentionalDisconnect` in the terminal
that typed it, so releasing the port on purpose never triggers a takeover there. And
succession is **local only**: when the last terminal on the hosting machine exits there is
nobody to claim the port and the room ends. Remote peers are not woken either — there is no
reconnect backoff in v3.5.0, so they rejoin with `/link on`.

### The manual fallback: on the surviving local terminal

If nothing succeeded automatically — you closed the last terminal on that machine, or it
rebooted — recovery is one command. Run `/link on`. Do **not** run `/link create`, which
would mint a new `roomId` and break every remote pin's room binding.

```
/link on
```

`resumeRoom` does exactly the right thing here. The surviving terminal's remembered room
was written by its own `joinEndpoint`, with `hubPrincipalId` = the hub's certificate
principal = **this device's own principal** (siblings share the certificate). So:

```ts
if (currentRoom.hubPrincipalId === node.identity.principalId) {
  await hostRoom(currentRoom.label, currentRoom.roomId, ctx);   // re-host, same roomId
```

and because `LinkNode.roomId` was already overwritten with the hub's room id on
authentication (`this.roomId = sHello.roomId || this.roomId`), the new hub publishes the
**same `roomId`** under the **same device certificate**. Remote peers' pins remain valid;
nobody re-pairs.

```
Hosting room "backend" on 192.168.1.42:9900.
No peer is admitted until you approve it. Share access with /link invite.
```

Before that, `resumeRoom` probes `127.0.0.1:9900` first, so if a different local terminal
already took over you join it instead of racing for the port:

```
Joined room "backend" hosted by another terminal on this machine.
```

### Recovering: on the remote machine

```
/link on
```

`currentRoom.hubPrincipalId` is the *other* device, so this path rejoins
`currentRoom.endpoint` pinned to `currentRoom.hubFingerprint`. The successor presents the
same device certificate, the pin matches, the device is already in
`paired-devices.json`, and `server_hello` comes back with `requiresPairing: false`:

```
Rejoined room "backend".
```

If you get there before the successor is listening:

```
Could not rejoin "backend" at 192.168.1.42:9900: connect ECONNREFUSED 192.168.1.42:9900
```

Just re-run `/link on`.

### Leaving deliberately

| Command | Effect |
|---|---|
| `/link off` (aliases `/leave`, `/link-leave`) | Detaches **this** terminal. `stop()` + `revokeAllGrants("Link deactivated")` |
| `/link end` | Hub only. Names the impact first, requires `--yes` to proceed |

`/link off` while hosting for others warns you:

```
Left the room. You were hosting for 2 peers; another terminal on this machine will take over hosting if one is running.
```

`/link end` refuses to be casual:

```
This will drop 2 connected agents: linux-box, other-mac.
Run /link end --yes to confirm.
```

That warning is literal: the sibling terminals see the hub's socket close and one of them
claims the port on its own. `intentionalDisconnect` only suppresses succession in the
terminal that typed `/link off`.

---

## (e) Nested repositories

### The current limitation, stated plainly

A workspace export is **auto-registered from `process.cwd()`** with the id `default`, and
nothing narrows it to a repository boundary.

```ts
// LinkNode constructor
registerWorkspace({ id: "default", rootDir: this.workspaceRoot });   // workspaceRoot = process.cwd()

// getRegisteredWorkspace, for ids "default" and "*"
return registerWorkspace({ id: "default", rootDir: process.cwd() });
```

So for this layout:

```
~/work/monorepo/          <- agent launched here; this is the export
  .git/
  services/
    payments/
      .git/               <- a nested repository
```

a peer with `readContent` can read `services/payments/src/index.ts` through the parent's
`default` export. `req.params.workspace` is honoured if a *different* id was registered,
but nothing in `index.ts` ever registers a second workspace, and there is no
`/link workspace add` verb. `/link devices workspace <device> <w1,w2>` stores a
`workspaces` list on the paired-device record, but that list is only surfaced in
`system_status` output — it is not consulted by `isActionPermitted` or by the RPC
dispatcher.

The `git` RPCs behave per their `cwd`: `safeGitStatus(cwd)` with `cwd` = the parent root
reports the parent repository, and git itself will not descend into the nested `.git`.
`read_file` and `list_dir` are plain filesystem operations and *will* traverse into the
nested tree, subject only to path confinement.

### What still protects you

| Guard | Effect |
|---|---|
| `resolveConfinedPath` | Rejects `..` traversal, null bytes, `C:` prefixes, and symlinks resolving outside the canonical root |
| `isSensitivePath` | Blocks `.env*`, `id_rsa`/`id_ed25519`/`id_ecdsa`/`id_dsa`, `*.pem`, `*.key`, `*.pfx`, `*.p12`, `.git`, `.ssh`, `credentials`, `secrets*`, `.npmrc`, `.netrc`, `known_hosts`, `authorized_keys`, `.aws`, `kubeconfig`, `.kube`, `*.tfvars`, `.sops` — in the nested repo too |
| `GIT_EXCLUSION_PATHSPECS` | The same list as `:(exclude)` pathspecs on `git diff` and `git grep` |
| Capabilities | `readContent` is off by default; `DEFAULT_PERMISSIONS` grants only `observe` and `message` |
| `safeReadFile` | Caps a read at 256 KiB; `safeListDir` caps at 100 entries |

### Workaround until named exports land

Scope by **launch directory**, because the export *is* the cwd:

```bash
cd ~/work/monorepo/services/payments && omp    # exports only payments
```

and scope by capability on the machine that owns the files:

```
/link devices deny linux-box content,diff
```

```
linux-box can now: send messages, see repo status
```

Verify what you are exporting before granting anything:

```
link_exec to="<self-peer>" action="list_dir" filePath="."
```

Named mandatory exports and `git rev-parse --show-toplevel` canonicalisation are the
Sprint C item that removes this; see `INTERNAL_SPRINT_LOG.md` §3.
