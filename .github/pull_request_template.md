## What this changes

## Why

<!-- For a bug fix: what the defect was, and which invariant in AGENTS.md it violated. -->

## Checklist

- [ ] `npm run ci` is green locally (typecheck + security + integration + fuzz + regression)
- [ ] There is a test that **failed before this change and passes after it**
- [ ] Behaviour change → docs updated (`docs/`, plus `README.md` / `AGENT.md` / `SECURITY.md` if
      the claim lives there); command surface change → made in `src/command-registry.mjs`
- [ ] No new dependency. The project has exactly one runtime dependency (`ws`); adding another
      needs discussion in an issue first
- [ ] No new tooling: no eslint/prettier/biome, no test framework, no bundler, no coverage runner
- [ ] Security-relevant decisions are recorded with `appendAuditLog`, and secrets are written with
      `atomicWriteSecureFile`

<!-- Conventions and the invariants a change must not break: CONTRIBUTING.md and AGENTS.md. -->
