# Security Policy & Threat Model

## Reporting a Vulnerability

We take the security of `omp-link` seriously. If you discover a security vulnerability, please do not disclose it publicly via GitHub issues or discussions.

Instead, please report security vulnerabilities responsibly:
- **Email**: `security@omp-link.internal` (or reach out to the maintainers via private channels)
- **Response Time**: Maintainers will acknowledge receipt within 48 hours and provide an assessment and timeline for a fix.
- **Coordination**: Please give us reasonable time to release a patch before disclosing details publicly.

---

## Threat Model (Protocol v5)

`omp-link` is designed for secure, mutually authenticated inter-terminal communication across local area networks (LAN) and Tailscale overlay networks. The security model is built upon **TLS 1.3 Mutual Authentication**, **Certificate Pinning**, **SPKI Device Principals**, and **Strict Capability Authorization**.

### Core Assumptions & Security Boundaries

1. **Hub Mediation & Wire Inspection**:
   - The hub mediates message routing and structured RPCs between terminals.
   - **The hub can read and route all traffic passing through it**. It is not a blind transport relay.
   - End-to-end security between client agents and the hub is enforced via TLS 1.3 mutual certificate pinning.

2. **Untrusted Peers & Prompt Injection**:
   - Paired peer terminals may deliver adversarial prompt injection via chat or direct messages.
   - User interfaces must visually label peer-originating messages with their authoritative origin display name and authenticated device principal.
   - Agents receiving messages must treat peer input as untrusted data rather than system-level instructions.

3. **Structured Inspection Scope**:
   - Structured inspection (`git_status`, `git_diff`, `git_log`, `search_text`, `read_file`, `list_dir`) is restricted to the confined workspace root.
   - Path traversal (`../`), null bytes, Windows drive escapes, and symlink escapes are strictly blocked.
   - Tracked or untracked sensitive files (e.g., `.env*`, `.git/*`, private keys `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, credentials) are denied across all operations, including `git diff` path filtering and `git grep` exclusion pathspecs.
   - **Structured inspection will disclose non-sensitive repository source code** to any peer granted the `inspect` capability.

4. **Shell Execution & Local-User Access**:
   - Shell command execution (`exec` RPC) grants arbitrary process execution on the host running the command.
   - **Full shell elevation equals local-user access**.
   - The regex-based Mutation Guard is an advisory warning layer against accidental modifications and **does NOT provide OS-level containerization or isolation**.
   - Shell execution requires **both** base `execRequest` permission **and** an explicit, single-use, time-bounded in-memory `ExecGrant` keyed to the device principal.

5. **Untrusted File Quarantine**:
   - Files transferred via `file_offer` and `file_chunk` are received into an isolated quarantine directory outside the workspace (`~/.omp/inbox/<workspace>/<receiver-id>/`).
   - Files in the quarantine inbox are untrusted until explicitly audited and copied into a working directory by the user.
   - Transfers enforce streaming SHA-256 verification, sequential chunk numbering, sender binding, and quarantine size quotas.

6. **Local Host Compromise**:
   - Persistent device credentials are saved in `~/.omp/identity/` (permissions `0600` / `0700`).
   - **Local compromise of `~/.omp` defeats device identity**, as an attacker with local user access can read the private key.

7. **Trust On First Use (TOFU) & MITM Resistance**:
   - On first connection, TOFU requires mutual verification of a 4-word Short Authentication String (SAS) derived from both peer certificates and random nonces:
     `SHA256("omp-link/pairing/v5" || hubCertDer || clientCertDer || hubNonce || clientNonce)`
   - After initial approval, the peer's SubjectPublicKeyInfo (SPKI) fingerprint is permanently pinned.
   - Subsequent connections reject any hub or client certificate changes (`rejectUnauthorized: true`).

8. **Network Segmentation & Tailscale**:
   - Tailscale membership provides network connectivity, but **Tailscale membership does not automatically imply omp-link authorization**.
   - Devices on the same tailnet must still perform mutual TLS 1.3 certificate validation and explicit pairing approval before exchanging application messages.
