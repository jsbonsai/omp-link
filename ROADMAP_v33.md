# ROADMAP v3.3.0 Security Preview

Progress tracker for addressing audit feedback and implementing the 16 ship plan items.

## Status Overview

- [ ] **Item 1: Correct Architecture Claims & Documentation**
  - Replace P2P, host migration, and E2EE claims with honest peer-hosted star topology model.
  - Update README, SECURITY.md, and command documentation.
- [ ] **Item 2: Real SPKI Principals & Database Migration**
  - Compute fingerprint & principal from public key SPKI DER (not certificate DER).
  - Add database schema versioning and migration for `paired-devices.json`.
- [ ] **Item 3: Enforce SPKI Pinning Immediately Post-Handshake**
  - Implement `verifyPeerSpki` check on `ws.open` before sending `client_hello` or secrets.
  - Reject socket immediately on SPKI mismatch.
- [ ] **Item 4: Channel-Bound, Independently Computed SAS Confirmation**
  - Exchange 32-byte nonces.
  - Bind SAS using `TLSSocket.exportKeyingMaterial()` with SHA-256 context.
  - Expand SAS entropy (4 words from 256-word dictionary).
  - Remove SAS transmission over the wire; enforce verification in `/link accept <id> <code>`.
- [ ] **Item 5: Wire Invitations End-to-End**
  - Complete CLI wiring for `/link invite` and `/link join <endpoint> <secret>`.
  - Pin hub SPKI prior to transmitting invite secret.
- [ ] **Item 6: Real Network Mode Confinement (Tailscale / LAN / Loopback)**
  - Tailscale mode: bind to Tailscale IP only, disable UDP discovery, probe tailnet only.
  - LAN mode: explicit opt-in with visible warning.
  - Minimal public `/status` endpoint returning only protocol & SPKI info.
- [ ] **Item 7: Eliminate `FULL_PERMISSIONS` Fallbacks**
  - Introduce `NO_PERMISSIONS` default.
  - Remove role-based permission escalation for clients in local RPC handling.
- [ ] **Item 8: Protocol Addressing & Response Correlation by Immutable Principal**
  - Address messages using `toPrincipalId`.
  - Bind pending RPC/file/compact requests to `expectedPrincipalId`.
  - Use `crypto.randomUUID()` for all message/request IDs.
- [ ] **Item 9: Local Workspace Policies & Registered Canonical Roots**
  - Implement `WorkspacePolicy` registry with canonical realpaths.
  - Split inspection capabilities into metadata, content read, diff read, and exec.
- [ ] **Item 10: Outbound File Transfer Confinement & Confirmation**
  - Confine outbound file reads to registered workspace root with symlink resolution.
  - Enforce sensitive file denylist on sender side.
- [ ] **Item 11: Shell Execution Isolation / Safe Defaults**
  - Disable remote shell execution by default; require explicit opt-in flag `--unsafe-remote-exec`.
  - Bind execution grants to command digest and enforce execution safety.
- [ ] **Item 12: Upgrade `ws` to 8.21.3 & Transport Limits / Backpressure**
  - Update `ws` to 8.21.3.
  - Configure `maxPayload: 2MB`, `maxFragments: 128`, `perMessageDeflate: false`.
  - Implement streaming backpressure with `sendBounded()`.
- [ ] **Item 13: Installer & CLI Version Alignment**
  - Align all versions to 3.3.0.
  - Fix `setup.sh` (no arbitrary SIGKILL, no unauthorized rc edits, non-destructive).
  - Fix `omp-link find` to use HTTPS.
- [ ] **Item 14: GitHub Actions CI Workflow & Governance**
  - Add `.github/workflows/ci.yml` for Linux & macOS.
  - Establish `main` as primary branch.
- [ ] **Item 15: Adversarial Test Suite**
  - Add comprehensive tests covering identity, TLS, SAS, MITM resistance, authorization, path confinement, and limits.
- [ ] **Item 16: End-to-End Verification & Remote Sync**
  - Verify local `npm run typecheck && npm run ci`.
  - Verify remote node `js@192.168.1.183`.
  - Commit and push to repository.
