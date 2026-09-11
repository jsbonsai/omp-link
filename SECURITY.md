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

2. **Symmetric Inbound Authorization**:
   - Hub and client run the **same** inbound pipeline (`gateInboundApplicationMessage`: dedupe, then capability check, then origin binding). Being the hub is a role, not a permission: a hub's request against a client is authorized against the capabilities that client stored for it.
   - A client's live capability set starts at `NO_PERMISSIONS` and is raised only from the record stored on this machine after authentication completes — never from the peer's role and never from a value supplied on the wire. A paired hub is recorded with `DEFAULT_PERMISSIONS`, and its principal is taken from the verified certificate.
   - Correlated responses (`rpc_response`, `file_ack`, `compact_response`) are authorized against the pending request they answer, and the responder's origin principal must match the peer the request was sent to.

3. **Untrusted Peers & Prompt Injection**:
   - Paired peer terminals may deliver adversarial prompt injection via chat or direct messages.
   - User interfaces must visually label peer-originating messages with their authoritative origin display name and authenticated device principal.
   - Agents receiving messages must treat peer input as untrusted data rather than system-level instructions.

4. **Structured Inspection Scope**:
   - Structured inspection (`git_status`, `git_diff`, `git_log`, `search_text`, `read_file`, `list_dir`) is restricted to the confined workspace root.
   - Path traversal (`../`), null bytes, Windows drive escapes, and symlink escapes are strictly blocked.
   - Tracked or untracked sensitive files (e.g., `.env*`, `.git/*`, private keys `id_rsa`, `id_ed25519`, `*.pem`, `*.key`, credentials) are denied across all operations, including `git diff` path filtering and `git grep` exclusion pathspecs.
   - Capability evaluation is deny-biased: an explicit `false` on a granular capability (`inspectMetadata`, `readContent`, `readDiff`) denies the request even when the legacy `inspect` alias is `true`. The alias is honored in the positive direction only, and only where the granular capability is unset — that is, for paired-device records written before granular capabilities existed.
   - **Structured inspection will disclose non-sensitive repository source code** to any peer granted the `inspect` capability.

5. **Shell Execution & Local-User Access**:
   - Shell command execution (`exec` RPC) grants arbitrary process execution on the host running the command.
   - **Full shell elevation equals local-user access**.
   - The regex-based Mutation Guard is an advisory warning layer against accidental modifications and **does NOT provide OS-level containerization or isolation**.
   - Shell execution requires **both** base `execRequest` permission **and** an explicit, time-bounded, use-bounded in-memory `ExecGrant` (one execution by default), optionally confined further to a single workspace and a single command digest.
   - Grants are keyed to `(device principal, agent instance)`, not to the device principal alone. Two terminals on the same machine share one device certificate but not one grant: granting to one agent instance leaves the other unelevated, and revocation can target a single instance or every instance of a principal.

6. **Untrusted File Quarantine**:
   - Files transferred via `file_offer` and `file_chunk` are received into an isolated quarantine directory outside the workspace (`~/.omp/inbox/<workspace>/rx-<pid>-<rand>-XXXXXX/`).
   - Files in the quarantine inbox are untrusted until explicitly audited and copied into a working directory by the user.
   - Transfers enforce streaming SHA-256 verification, sequential chunk numbering, sender binding, and quarantine size quotas. Quota bytes are reserved when a transfer is accepted, so concurrent transfers cannot jointly exceed the ceiling.
   - Staging files are owned by the receiving process (`rx-<pid>-<rand>`). Another process reclaims them only when the owning pid is gone and the file has been idle past the absolute transfer deadline.

7. **Local Host Compromise**:
   - Persistent device credentials are saved in `~/.omp/identity/` (permissions `0600` / `0700`).
   - **Local compromise of `~/.omp` defeats device identity**, as an attacker with local user access can read the private key.
   - Following from that non-goal: a peer that presents **this device's own certificate** is admitted without pairing and recorded in the audit log as `local_sibling_admitted`. Such a peer has proved possession of this device's private key, so it is another terminal of the same user on the same machine; requiring the user to compare a verification code against themselves would add no security an attacker with that key has not already bypassed. Distinct local terminals remain distinguishable — and separately grantable — by agent instance.
   - The same reasoning covers hub succession: when the hosting terminal exits, another local terminal may claim the hub port using the same device certificate, so remote peers' pins stay valid. Hosting never migrates to a different device identity.

8. **Trust On First Use (TOFU) & MITM Resistance**:
   - On first connection, TOFU requires mutual verification of a 4-word Short Authentication String (SAS). The SAS binds both peer public keys and both random nonces to the live TLS session: a context digest `SHA256("omp-link/pairing/v5\0" || hubSpki || clientSpki || hubNonce || clientNonce)` is exported through RFC 5705 keying material (label `EXPORTER-omp-link-pairing-v5`), and the exported key HMACs that context into the displayed words.
   - **SAS comparison is mandatory.** Approval takes the code as a required argument and compares it in constant time; a missing or mismatched code rejects the pending pairing, tells the peer, and is audited (`pairing_rejected_missing_sas` / `pairing_rejected_invalid_sas`). There is no approve-without-code path.
   - There is **no non-exporter fallback**: a runtime without `exportKeyingMaterial` fails pairing with `PAIRING_UNSUPPORTED_RUNTIME` rather than deriving a code from public handshake values alone, which a man-in-the-middle terminating both TLS sessions could make agree.
   - The word list is exactly 256 unique frozen words, so every byte of the digest maps to a word and every code is comparable.
   - After initial approval, the peer's SubjectPublicKeyInfo (SPKI) fingerprint is permanently pinned.
   - Subsequent connections reject any hub or client certificate changes (`rejectUnauthorized: true`).

9. **Room Identity & Discovery**:
   - A room is an opaque identifier bound to its host's device principal: `(roomId, hub principalId)`. The room id is what `server_hello` and `GET /status` publish; human session labels are never used as identity and never leave the machine.
   - **Discovery does not imply trust.** Scanning yields candidate endpoints only. No path derives trust from a discovery result — not a single discovered hub, not a single previously paired device, and not a name matched against a URL. Every unpaired candidate goes through certificate pinning and SAS approval.
   - Joining names an existing room and never creates one; creating a room is always explicit.

10. **Network Segmentation & Tailscale**:
    - Tailscale membership provides network connectivity, but **Tailscale membership does not automatically imply omp-link authorization**.
    - Devices on the same tailnet must still perform mutual TLS 1.3 certificate validation and explicit pairing approval before exchanging application messages.

11. **Liveness & Teardown**:
    - Every authenticated connection is pinged on an interval (`heartbeatIntervalMs`, 15 s by default). A peer that sends nothing — no pong and no frame — for `heartbeatIntervalMs * heartbeatMissesBeforeDrop` (30 s by default) is closed with code `4408` and audited as `peer_liveness_timeout`. A suspended or network-partitioned peer still ACKs at the TCP layer, so an application-level ping is the only signal that distinguishes it from an idle one.
    - A liveness drop runs the **same teardown as a clean disconnect**: exec grants for that `(principal, agent instance)` are revoked, in-flight transfers and pending correlated requests are failed with a real reason, the peer leaves the roster, and the roster is rebroadcast. A connection that stopped answering therefore cannot leave capabilities, grants, or reserved quarantine quota behind it.
    - The client half of the check (`clientHubSilenceTimeoutMs`, 45 s by default) is deliberately longer than the hub's deadline. Declaring a hub dead moves a client to `disconnected`, which is what can trigger local hub succession; a premature takeover is a worse outcome than a briefly stale roster.
    - A terminal that reconnects presents the same agent instance on a fresh, mutually authenticated TLS session; the hub evicts the older connection (close `4409`, `peer_connection_superseded`) rather than carrying two. A stale connection left in place would keep its exec grants and split routing by display name.
    - These values are operator configuration (`<OMP_DIR>/link.json`, `timings`), validated per key with floors. They tune *detection latency only*: no configuration value can grant a capability, widen a transfer limit, relax a rate limit, or skip pairing.

12. **Validation of Untrusted Input at the Boundaries**:
    - **Unauthenticated `/status` responses are validated before they are rendered.** Discovery output is produced from a stranger's endpoint, so each field is required to be bounded printable ASCII (fingerprints must match the canonical `([0-9A-F]{2}:){31}[0-9A-F]{2}` form) and is otherwise dropped. Without this, an endpoint could smuggle newlines or ANSI escapes into `scan` output and forge a line that looks like a verification result from the tool itself.
    - **Peer-supplied free text is sanitised and bounded.** The `error`, `reason` and `text` fields are stripped of control characters and ANSI/OSC escapes and truncated at 2 000 characters by `parseWireMessage`, because they are rendered to an operator and injected into a model's context. A non-string value for those fields is deleted rather than coerced. This is a display-integrity control; it does not make peer content trustworthy (see §3).
    - **Announced transfer sizes are enforced, and symlinks are refused.** The sender opens the file through a handle, refuses a symlink, and aborts if the file changed size mid-stream rather than emitting more bytes than the `file_offer` announced. The receiver independently enforces sequential chunks, the 50 MB ceiling and the streaming SHA-256 (§6).
    - **The UDP discovery responder answers only plausible neighbours.** Datagrams are size-capped, sources outside this host's own subnets (plus loopback) are dropped, and replies are rate limited per source, so the responder cannot be used as an amplifier or as a scanner's oracle.
    - **Ambiguous device arguments are refused, never guessed.** A device lookup that matches more than one paired record resolves to nothing and reports the ambiguity; revoking or re-permissioning the wrong device is not a recoverable mistake.
    - **The audit log reports its own failure.** Writing a record never throws — the decision it describes has already been taken — but a failure is remembered and surfaced by `/link doctor` and `/link shared`. A silent "no denials recorded" on an unwritable log would be worse than no receipt at all. The log is one `write(2)` per line on a persistent `O_APPEND` descriptor, and each line carries `logSeq` and `agentInstanceId` so several terminals writing to one file stay attributable and gaps stay visible.

13. **MCP Hosts**:
    - The MCP stdio server (`omp-link-mcp`) is a client only. It never opens a listening port, never creates or joins a room, never pairs unattended, and never enables remote execution: an editor-spawned background process must not be able to put a TLS server on the LAN or elevate a peer because a config file remembered a room.
    - It presents this machine's device certificate under its own agent instance, so it is a separate terminal for grants and revocation, and all capability gating in §2 applies to it unchanged.
    - Operations that require human judgement stay on the human surface: creating and joining rooms, comparing the 4-word SAS, and approving a pairing are done with `omp-link` / `/link`, never by a tool call.
