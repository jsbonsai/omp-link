# Getting started

Two machines, one room, one pairing. Every block below is either a copy-pasteable command
or the exact text the source produces.

- [1. Install](#1-install)
- [2. First room (machine A)](#2-first-room-machine-a)
- [3. Second machine joins (machine B)](#3-second-machine-joins-machine-b)
- [4. First pairing](#4-first-pairing)
- [5. Confirm both sides agree](#5-confirm-both-sides-agree)
- [6. Grant something beyond messages](#6-grant-something-beyond-messages)
- [Failures a first-timer hits](#failures-a-first-timer-hits)

Related: [commands.md](commands.md), [concepts.md](concepts.md),
[troubleshooting.md](troubleshooting.md). Using it from Claude Code or Codex CLI instead
of OMP/Pi: [mcp.md](mcp.md).

---

## 1. Install

Node ≥ 18 is a hard requirement (`setup.sh` step 2). There is no build step: OMP/Pi loads
`index.ts` directly and the CLI files are hand-written `.mjs`.

```bash
git clone https://github.com/jsbonsai/omp-link.git
cd omp-link
npm install && ./setup.sh
```

`setup.sh` symlinks the checkout into `~/.omp/agent/extensions/omp-link`,
`~/.omp/extensions/omp-link`, the two matching `~/.pi` paths, the skills into
`~/.omp/agent/skills`, `bin/omp-link.mjs` into `~/.local/bin/omp-link` and
`~/.local/bin/pi-link`, and `bin/omp-link-mcp.mjs` into `~/.local/bin/omp-link-mcp` (the
MCP stdio server, [mcp.md](mcp.md)). It never kills a process holding port `9900` — it
only reports it.

Verify:

```bash
omp-link version
```

```
3.5.0
```

`omp-link --version` and `omp-link -v` are aliases of the same verb
(`command-registry.mjs`, `COMMANDS[version].aliases`).

Then confirm the install is wired up:

```bash
omp-link doctor
```

```
omp-link doctor — measured values only

  version           3.5.0
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

Line-by-line reading of that report: [troubleshooting.md#reading-doctor](troubleshooting.md#reading-doctor).

> Upgrading from an earlier version wipes your pairings on purpose.
> `PAIRED_DEVICES_SCHEMA_VERSION = 3` (`src/identity.ts`); an older store is renamed to
> `paired-devices.v<old>.bak.json` and load returns empty. `doctor` says so:
> `NOTE               the paired-device store was reset by an upgrade; re-pair your devices`.

---

## 2. First room (machine A)

Start the agent normally, then inside it:

```
/link create backend
```

```
Hosting room "backend" on 192.168.1.42:9900.
No peer is admitted until you approve it. Share access with /link invite.
```

The IP comes from `getNetworkInfo().lanIps[0]` (`src/discovery.ts`), which only collects
non-internal IPv4 in `10.`, `192.168.` or `172.` ranges. If none exists the endpoint reads
`127.0.0.1:9900`.

Check the card:

```
/link status
```

```
Link · Hosting, no other agents
Room          backend
This agent    mac-mini · omp-link (this)
Other agents  0
Network       lan · hosting 192.168.1.42:9900 · SPKI verified

  /link peers   /link shared   /link off
```

`create` always creates. It never joins something it discovered
(`command-registry.mjs`: *"Always creates. It never silently joins something it found."*).

---

## 3. Second machine joins (machine B)

```
/link join 192.168.1.42:9900
```

Machine B, still unpaired, reports two messages. From the extension:

```
Waiting to be verified by the host at 192.168.1.42:9900.
Compare this code on BOTH screens: canyon-ember-violet-rapid
Nothing is shared until the host approves.
```

and from the node itself (`LinkNode.handleClientSocketMessage`):

```
Pairing required. Compare this code on BOTH devices: canyon-ember-violet-rapid
The host approves with: /link accept <id> canyon-ember-violet-rapid
```

The four words are a 4-word SAS taken from `SAS_WORD_LIST` (256 frozen words) — the
example above is illustrative; your words will differ. B's card is explicit that nothing
has moved yet:

```
Link · Pairing — not connected yet
Host        192.168.1.42:9900 · identity not yet trusted
Compare on BOTH devices:   canyon-ember-violet-rapid

Shared now  nothing — no file, diff or command has been sent
  Waiting for the host to approve this device.
  /link off   cancel
```

Don't know A's address? `/link scan` lists candidates and never picks one for you:

```
/link scan
```

```
Reachable hubs (1). Unverified — joining still requires a code or a pin:
  192.168.1.42:9900 [lan] room 6f1c0a5e-...
    join: /link join 192.168.1.42:9900
```

---

## 4. First pairing

Machine A sees the request:

```
Pairing request #1
  Device       "linux-box" from 192.168.1.183
  Compare this code on BOTH screens:  canyon-ember-violet-rapid
  Approve      /link accept 1 canyon-ember-violet-rapid
  Refuse       /link deny 1
  Granting     messages and status only. Add access later with /link devices allow.
```

**Compare the four words out of band** — look at B's screen, or read them over a call. The
code is never transmitted: both ends derive it independently from the live TLS session
(`deriveLocalSas`, exporter label `EXPORTER-omp-link-pairing-v5`). Matching words prove
you are both on the same TLS channel, so an active man-in-the-middle cannot make them
agree.

Approve on A:

```
/link accept 1 canyon-ember-violet-rapid
```

```
Approved "linux-box".
  They can: send messages
```

B is told:

```
Device pairing approved by host
```

The code is a required argument, compared with `crypto.timingSafeEqual` after stripping
non-alphanumerics and upper-casing (`LinkNode.approvePairing`). There is no
approve-without-code path.

You have `pairingWindowMs` — 60 seconds unless you changed it
([concepts.md#configuration-linkjson](concepts.md#configuration-linkjson)): the pending
request carries a `setTimeout` that closes the socket with code `4408` and reason
`Pairing request timed out after <n>s`.

---

## 5. Confirm both sides agree

The rosters must match. Run on **both** machines:

```
/link peers
```

Machine A:

```
Agents in "backend":
  mac-mini (this agent) · omp-link
  linux-box · api · can: send messages
```

Machine B:

```
Agents in "backend":
  linux-box (this agent) · api
  mac-mini · omp-link · can: send messages
```

A client's roster is whatever the hub last published — `LinkNode.absorbRoster` replaces it
from `server_hello.terminals` and from `status_update` frames. If B lists only itself, the
`status_update` never arrived; see
[troubleshooting.md](troubleshooting.md#roster-mismatch).

Send a message across:

```
link_send to="linux-box" message="ping"
```

```
Message sent to "linux-box".
```

---

## 6. Grant something beyond messages

A fresh pairing stores `DEFAULT_PERMISSIONS` — `observe` and `message`, nothing else
(`src/identity.ts`). So this fails, by design:

```
link_exec to="linux-box" action="git_status"
```

```
RPC execution error on "linux-box": Permission denied: action requires "inspectMetadata" capability, which is not granted to this device
```

The consent step happens on the machine that owns the files. On **B**:

```
/link devices allow mac-mini metadata
```

```
mac-mini can now: send messages, see repo status
```

Now re-run `link_exec` from A. Full capability table:
[security.md#capabilities](security.md#capabilities).

---

## Failures a first-timer hits

### Port 9900 already in use

Two cases, and the code distinguishes them (`hostRoom`, `index.ts`). If the holder is an
omp-link hub reachable on loopback, you join it instead:

```
A terminal on this machine is already hosting on port 9900. Joined it instead of starting a second room.
```

If it is anything else:

```
Port 9900 is in use by something that is not an omp-link hub. Free the port or run /link doctor to see what is holding it.
```

Find the holder:

```bash
omp-link doctor
```

```
  tcp 9900:
    pid 54120 user you cmd node (this user)
    /status did not answer (ECONNREFUSED)
```

`omp-link cleanup` will only stop a listener whose ownership it can prove **and** that
answers `/status` as an omp-link hub; otherwise it refuses:

```
      REFUSING to stop it: the listener did not answer /status as an omp-link hub
      This CLI never signals a process it cannot prove is an omp-link hub owned by you.
```

### No hubs found

`/link join` with no argument:

```
No hubs responded. Give an address: /link join <ip:port>
```

`/link scan`:

```
No hubs responded on lan.
```

The `lan` in that sentence is the active `networkMode`. In `lan` mode
`discoverAllHubs` probes loopback and does a UDP broadcast sweep but **skips Tailscale**;
in `tailscale` mode it probes loopback and Tailnet peers but **skips the LAN sweep**
(`src/discovery.ts`, step 2 and step 3 guards). Mode comes from `network` in
`<OMP_DIR>/link.json`. From a shell, `omp-link scan` always probes all three:

```
No omp-link hub answered /status (1 endpoint(s) probed).
Start one from inside the agent: /link create <name>
```

Discovery is not trust. Even with exactly one result, nothing joins or pins automatically
(`SECURITY.md` §9).

### Wrong verification code

On the host:

```
Request #1 was not approved: unknown id, expired, or the code did not match. The device was told and disconnected.
```

The joiner is told immediately rather than waiting out the pairing window:

```
Pairing rejected: Verification code did not match
```

Audited as `pairing_rejected_invalid_sas`. A missing code is caught before it reaches the
node at all:

```
/link accept 1
```

```
"accept" needs 2 argument(s).
Usage: /link accept <id> <code>
```

and an approval attempted without a code is audited `pairing_rejected_missing_sas` and
refused with `Verification code required`.

After a refusal, re-run `/link join <ip:port>` on the joining machine to get a new
request id and a new code.

### Pin mismatch

Rejoining a remembered room checks the stored SPKI fingerprint. If the host's key changed
(reinstall, new machine, or an impostor at the same address), the TLS handshake fails in
`checkServerIdentity` (`src/tls.ts`):

```
Could not rejoin "backend" at 192.168.1.42:9900: Server certificate pinning mismatch! Expected AA:BB:...:FF, received 11:22:...:99
```

Nothing was sent. No invite, diff or file leaves the machine on this path. Compare the
fingerprints before doing anything else:

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

If the change is legitimate, drop the old record and pair again:

```
/link revoke mac-mini
/link join 192.168.1.42:9900
```

Details and the second, differently-worded mismatch path:
[troubleshooting.md#pin-mismatch](troubleshooting.md#pin-mismatch).

### The Pi version guard

```
omp-link requires Pi >=0.84.2 (detected 0.83.1); upgrade Pi or OMP.
```

`MIN_PI_VERSION = [0, 84, 2]` in `index.ts`. Bypass only if you know why:
`PI_LINK_IGNORE_VERSION_CHECK=1`.
