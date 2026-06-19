# Security Policy

qeli is censorship-circumvention software. People may rely on it in settings
where a failure has real consequences, so we take security reports seriously.

## Supported versions

qeli is pre-1.0 and ships a single, unified version across all components
(the Rust daemon and the Windows / macOS / Android clients). Only the **latest
released version** receives security fixes. There are no long-term support
branches yet. See [`CHANGELOG.md`](CHANGELOG.md) for the current version.

## Reporting a vulnerability

**Please do not open a public issue for security problems.**

Report privately through **GitHub Private Vulnerability Reporting**:
the *Security* tab of the repository → *Report a vulnerability*. This opens a
private advisory visible only to the maintainers and to you.

If that is unavailable to you, open a regular issue titled
"security contact request" with **no technical detail** and we will arrange a
private channel.

When reporting, please include:

- affected component(s) and version (`qeli --version`, client build);
- the wire mode in play (`plain` / `fake-tls` / `obfs` / `reality` / `reality-tls` / UDP);
- a description of the issue and its impact, ideally with a reproduction or PoC;
- whether the issue is already public anywhere.

### What to expect

- **Acknowledgement:** within 7 days.
- **Initial assessment:** within 14 days (severity + whether we can reproduce).
- **Fix / disclosure:** coordinated. We aim to ship a fix and publish an advisory
  within 90 days of acknowledgement; for an actively-exploited issue we move
  faster. We will credit you in the advisory unless you prefer to stay anonymous.

This is a small, volunteer-maintained project — timelines are best-effort, not
contractual.

## Scope

In scope (please report):

- Cryptographic flaws in the handshake, key derivation, AEAD framing, or replay
  protection (`qeli/src/crypto/*`, `qeli/src/protocol/packet.rs`).
- Memory-safety or panic-on-untrusted-input bugs in the parsers that face a
  hostile network: the fake-TLS / realtls ClientHello parsing
  (`qeli/src/protocol/realtls/*`, `qeli/src/protocol/tls.rs`) and the packet
  codec.
- Authentication bypasses (tunnel auth, server-identity proof, or the web panel).
- Traffic-confirmation / fingerprinting weaknesses that let a network observer
  *positively identify* a qeli flow (distinct from the documented residual
  metadata leaks — see the threat model).
- Local privilege-escalation via qeli's privileged components (TUN setup,
  nftables kill-switch, `resolv.conf` handling, the control socket).

Out of scope:

- The documented residual leaks and non-goals in the
  [threat model](docs/eng/THREAT-MODEL.md) (e.g. DNS metadata on the physical
  link while the kill-switch allows port 53, or traffic-volume/timing
  correlation by a global passive adversary).
- Findings that require an already-root local attacker, or physical access.
- Denial of service that requires an on-path attacker who could simply drop the
  connection anyway.
- Reports from automated scanners without a demonstrated, qeli-specific impact.

## A note on the custom TLS stack

qeli intentionally implements a hand-rolled TLS 1.3 record/handshake layer
(`qeli/src/protocol/realtls/*`) so it can control its wire fingerprint (JA3/JA4)
byte-for-byte and cross-compile without `ring`/`aws-lc-rs`. This is the largest
single attack surface and has **not yet had an independent external audit**.
Reports against this code are especially welcome. See the threat model for the
current assurance status.
