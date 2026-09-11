# omp-link v3.5.0 — documentation

`omp-link` lets two or more OMP/Pi agent terminals talk to each other over your own
network, with no server you have to run and nothing hosted by anyone else. One terminal
anchors a hub on TCP `9900`; the others join it. Traffic is mutually authenticated
TLS 1.3 with SPKI pinning (`src/tls.ts`), and every inbound frame passes a capability
check (`LinkNode.gateInboundApplicationMessage`, `src/link-node.ts`).

What it is good for: asking a peer agent to do work in *its* repository (`link_send`),
reading a peer's git state without spending tokens (`link_exec`), moving a file into a
peer's quarantine inbox (`link_send_file`), and forcing a peer to compact
(`link_compact`). It is not OMP/Pi-only: `omp-link-mcp` exposes six of the seven tools —
all but `link_compact` — to any MCP host, Claude Code and Codex CLI included
([mcp.md](mcp.md)).

What it is not: it is not peer-to-peer and not end-to-end encrypted. The hub decrypts
and routes everything (`SECURITY.md` §1). It is not a daemon — hosting lives inside a
terminal process. Another terminal on the same machine takes the hub over automatically if
one is running ([scenarios.md](scenarios.md#d-the-hosting-terminal-exits)); when the last
one exits, the room goes with it. It does not sandbox
anything: an exec grant is local-user access (`MUTATION_GUARD_ADVISORY`,
`src/authorization.ts`).

## Read in this order

| Document | For |
|---|---|
| [getting-started.md](getting-started.md) | Install, host a room, join from a second machine, first pairing, the four failures you will actually hit |
| [concepts.md](concepts.md) | The four identities, what a room really is, where state lives on disk, the star topology stated honestly |
| [scenarios.md](scenarios.md) | Worked walkthroughs: two repos on one machine, LAN, Tailscale, host exit, nested repositories |
| [commands.md](commands.md) | Every verb, both surfaces, arity, flags, refusals, the removed-verb table |
| [tools.md](tools.md) | The seven agent tools, parameters, `details` payloads, when to prefer `link_exec` over `link_send` |
| [mcp.md](mcp.md) | The MCP stdio server: the six tools it exposes, wiring for Claude Code and Codex CLI, what happens with no room, the loader tiers |
| [security.md](security.md) | Operator companion: capability table, pairing, `audit.log`, `/link shared`, revocation |
| [troubleshooting.md](troubleshooting.md) | Real error strings → cause → fix, and how to read `doctor` line by line |

## Related files outside `docs/`

| File | Role |
|---|---|
| [../SECURITY.md](../SECURITY.md) | Authoritative threat model. Anything here that disagrees with it is wrong |
| [../AGENTS.md](../AGENTS.md) | Architecture map and the invariants a contributor must not break |
| [../README.md](../README.md) | Public overview |
| [../CHANGELOG.md](../CHANGELOG.md) | Release history |
| [../src/command-registry.mjs](../src/command-registry.mjs) | Single source of truth for the command surface. `commands.md` is derived from it |

## Conventions used in these docs

- Commands prefixed `/link` run **inside** the agent (OMP/Pi). Commands prefixed
  `omp-link` run in a **shell**. A few work on both; [commands.md](commands.md) says which.
- Output in fenced blocks is copied from the source strings that produce it, or captured
  from a real run. Where a value is machine-specific it is shown as `<...>`.
- `<OMP_DIR>` means the state root resolved by `getOmpDir()` (`src/identity.ts`):
  `$OMP_DIR` if set, else `~/.omp` if it exists, else `~/.pi` if it exists, else `~/.omp`.

## The website

[`index.html`](index.html) is a self-contained landing page and documentation site: one file, no
build step, no dependencies, no network requests. Open it locally with `open docs/index.html`, or
publish `docs/` as-is.

| Host | Setup |
|---|---|
| GitHub Pages | Settings → Pages → source `main` / `/docs`. Served at `<user>.github.io/omp-link/` |
| Cloudflare Pages | Connect the repo, build command empty, output directory `docs` |
| Netlify, Vercel, S3, any static host | Upload `docs/`; `index.html` is the entry point |

It carries its own favicon, Open Graph tags and `theme-color` for both schemes, follows
`prefers-color-scheme` with a manual toggle remembered in `localStorage`, and degrades to readable
prose with JavaScript disabled (only the copy buttons, mobile menu and scroll-spy need it).

It is a summary, not a substitute: it links back to these files for anything detailed. When a
behaviour changes, update the Markdown here first, then reconcile the page — the site quoting a
string the code no longer prints is the failure mode to guard against.
