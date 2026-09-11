---
name: Bug report
about: omp-link did something it should not, or refused something it should have allowed
labels: bug
---

## What happened

Include the exact error string if there was one — the strings are catalogued in
[docs/troubleshooting.md](../../docs/troubleshooting.md), which may already name the cause.

## What you expected

## Reproduction

Numbered steps, including the `/link` or `omp-link` commands you ran, in order.

## Version

```
omp-link version
```

## `omp-link doctor` output

```
omp-link doctor
```

<!--
Paste the output above. It is safe to paste: it reports measured values only — version, Node
version, platform, the file *modes* of the identity cert and key (never the key material), the
state of the four install symlinks, and whatever is listening on TCP 9900 (pid, user, command).
If loopback answered it also prints the room id, which is an opaque uuid, never your room label.
It contains no private keys, no pairing codes, no peer list and no message content.

It does contain absolute paths, so it reveals your username, and the pid/user/command of the
listener on 9900. Edit those out if you mind.

`/link doctor` inside the agent prints a different, larger card: it additionally shows this
device's principal (a public SPKI fingerprint), the paired-device count, and your LAN and
Tailscale addresses. If you paste that one, redact the addresses if you consider them sensitive.
-->

## Environment

- OS and version:
- Node version:
- One machine or several:
- If several: LAN or Tailscale, and which side hosts the room:
- Role of the terminal that failed (hub / client / not connected):

## Relevant `audit.log` lines

The log is JSONL at `<OMP_DIR>/audit.log` — `$OMP_DIR` if set, else `~/.omp`, else `~/.pi`. For a
refusal, the deny record is usually the whole diagnosis. `/link shared` renders the same data more
readably.

```
```

<!--
Audit records can carry device principals, terminal names, workspace paths and file names. Redact
anything you consider sensitive; a redacted line is still useful, since the `type` field is what
identifies the decision.
-->
