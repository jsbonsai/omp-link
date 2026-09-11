---
name: Feature request
about: Propose a change to what omp-link does
labels: enhancement
---

## What you want to do that you cannot do today

## Why the current surface does not cover it

Check [docs/commands.md](../../docs/commands.md) and [docs/tools.md](../../docs/tools.md) first —
and the removed-verb table, in case the thing you want was deliberately dropped in 3.4.0.

## Which non-goal in SECURITY.md does this collide with?

Answer this even if the answer is "none" — it is the question that saves the most time. The
boundaries most requests run into:

- **§1** — the hub reads and routes everything. There is no client-to-client end-to-end
  encryption, and the topology is a star, not P2P.
- **§4** — structured inspection discloses non-sensitive repository source to any peer holding
  `inspect`; sensitive paths are refused for everyone.
- **§5** — a shell grant is local-user access. The Mutation Guard is advisory and provides no
  OS-level isolation.
- **§7** — local compromise of the state directory defeats device identity; a peer presenting this
  device's own certificate is admitted without pairing.
- **§8** — SAS comparison is mandatory and has no fallback. There is no approve-without-code path.
- **§9** — discovery is never trust: nothing joins, pins or auto-approves because a candidate was
  the only one found. `join` never creates a room.
- **§10** — being on the same tailnet grants connectivity, not authorization.

Also note that there is no daemon: hosting lives inside a terminal process, and when the last
local terminal exits, the room is gone.
