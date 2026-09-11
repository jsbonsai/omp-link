# Contributing to omp-link

Read [AGENTS.md](AGENTS.md) first: it is the architecture map — data flow, identity model, and the
numbered invariants a change must not break. [SECURITY.md](SECURITY.md) is the authoritative threat
model; [docs/](docs/README.md) covers the user-facing surface. This file only lists the house rules
you would otherwise violate.

## Toolchain

- **Node, not Bun.** Shebangs are `#!/usr/bin/env node`; `setup.sh` hard-fails below Node 18. CI
  runs Node 20 and 22 on Linux and macOS.
- **npm**, `package-lock.json` (lockfileVersion 3). Bump `package.json` and both lockfile version
  fields together.
- **No build step.** `npm run typecheck` (`tsc --noEmit`) is the only compile: Pi loads `index.ts`
  directly, tests run under `node --import tsx`, and shipped CLI files (`bin/*.mjs`,
  `src/command-registry.mjs`) are hand-written ESM needing no loader.
- **There is no eslint, prettier or biome, and none is wanted.** No bundler either. Match the
  style of the file you are editing.
- One runtime dependency, `ws`, exact-pinned. Another needs discussion first.

## Code conventions

- ESM + NodeNext: **relative imports carry a `.js` extension** even though the file is `.ts` —
  `import { getOmpDir } from "./identity.js";`. Builtins always take the `node:` prefix.
- **Result objects, not exceptions**, at every boundary: `{ ok, error, closeCode }`,
  `{ allowed, reason }`, `{ permitted, required, reason }`. Throwing is for programmer errors.
- `strict: true` plus `noUnusedLocals`/`noUnusedParameters`; only `src/**/*` and `index.ts` are
  typechecked. Existing `any` is confined to untyped `ws` sockets, caught errors and open
  wire-payload bags — use a real type in new code.
- Security decisions are recorded with `appendAuditLog({ type, timestamp, ... })`; `audit.log` is
  what `/link shared`, `doctor` and the tests read.
- Identity, paired devices and `link.json` are written with `atomicWriteSecureFile` (tmp + `0600` +
  rename), never `fs.writeFileSync`.

## Tests

```bash
npm test                 # tests/security.test.mjs
npm run test:integration # one ordered loopback mesh suite
npm run test:fuzz        # protocol fuzzing
npm run test:regression  # REGRESSION R<n>: each named after the finding it pins
npm run ci               # typecheck + all four suites; run before every commit
```

- **Runner is built-in `node:test` with `node:assert`.** No jest, vitest, mocks or snapshots. **Do
  not add a test framework**, and no coverage tooling is configured — do not claim thresholds.
- Tests are `*.test.mjs`: plain JS importing TypeScript through `.js` specifiers
  (`import { LinkNode } from "../src/link-node.js"`), resolved by `tsx`. Nodes are real
  mutual-TLS `LinkNode` instances, not doubles.
- **A new test must fail before your fix and pass after it.** If it passes unfixed it pins nothing.
  Denial paths matter more than happy paths: a suite that only pairs with `FULL_PERMISSIONS` cannot
  detect an authorization bypass.

Hygiene that bites:

- Pass `customOmpDir: fs.mkdtempSync(...)` to every node and call
  `setCustomAuditLogPath(path.join(tempDir, "audit.log"))` in `before()`, or identity, paired
  devices and audit records land in the developer's real `~/.omp`. Use a scratch `workspaceRoot`
  too — no test writes into the repository tree.
- Clients use `port: 0`; hubs bind `port: 0` and read back `hub.port`. Only `security.test.mjs`
  hardcodes ports, for its `/status` cases; add no new ones.
- Exec-grant state is process-global: call `revokeAllGrants()` in `before()`/`after()` and use
  unique principal strings.
- `tests/integration/node-mesh.test.mjs` is **ordered** — one hub/client pair, paired in the first
  test and revoked in the last. Append at the end; never insert.
- Crash and lifecycle faults need a child process (`runFixture`, `tests/helpers/child.mjs`) and are
  asserted on its exit code. Never give a fixture an `uncaughtException` handler.

## Pull requests

`npm run ci` green, a test that failed before and passes after, docs updated when behaviour
changed. Command-surface changes go in `src/command-registry.mjs` — the single source of truth —
not in `bin/` or `index.ts`.

## Security

Do not open a public issue for a vulnerability; follow the private process in
[SECURITY.md](SECURITY.md).
