# qeli — Threat Model

This document states **what qeli defends against, what it deliberately does
not, and the current assurance status.** It is written so a user can decide
whether qeli fits their risk, and so a reviewer knows where to look. It
describes design intent; it is not a guarantee.

Русская версия: [`../ru/THREAT-MODEL.md`](../ru/THREAT-MODEL.md).

## 1. What qeli is for

qeli is a censorship-circumvention VPN. Its primary job is to carry a user's
traffic to a server **without a network adversary being able to (a) read it,
(b) tamper with it undetected, or (c) positively identify the flow as a VPN/qeli
flow and block it.** Privacy from the *server operator* is explicitly a non-goal
(you trust your own server, as with any VPN).

## 2. Adversaries we design against

| Adversary | Capability | qeli's answer |
|-----------|-----------|---------------|
| **On-path passive DPI** (GFW / TSPU style) | Reads every byte, classifies by signature/entropy/fingerprint | Wire modes mimic real protocols: `reality-tls` presents a byte-grade Chrome TLS 1.3 ClientHello (JA3/JA4 parity) and a JA3S mirrored from a real site; `obfs` rides a WebSocket-fronted channel; nonce PRP removes the per-packet counter tell. |
| **On-path active prober** | Replays/initiates connections to the server to test if it is a proxy | REALITY: a connection without a valid crypto token in the ClientHello `session_id` is transparently bridged to the real decoy site. Replayed ClientHellos are detected and also bridged. This reduces the obvious active-probe oracle; it does not prove universal equivalence to the target under timing or correlation analysis. |
| **On-path active MITM** | Intercepts and rewrites handshake records | Server-identity proof bound to the handshake transcript (channel binding): any swap of ServerHello/Certificate/Finished breaks the proof. Optional `bind_static_to_session` (on by default) binds session keys to the server's long-lived identity (Noise-IK style). |
| **Store-now-decrypt-later / future quantum** | Records traffic today, breaks X25519 with a future quantum computer | All non-`plain` modes run a hybrid X25519 + ML-KEM-768 key exchange; the data keys depend on **both** secrets. The server refuses a non-PQ handshake (no silent downgrade). |
| **Online credential guesser** | Tries to brute-force a user password or the panel admin | Argon2id password hashing; per-IP lockout + per-username adaptive tarpit on the tunnel; the same on the web panel API; constant-time proof comparison; dummy-hash work on unknown users to avoid username enumeration by timing. |
| **Replay attacker** | Re-sends captured ciphertext | 2048-bit sliding replay window per session; AEAD with unique per-packet nonces. |
| **Local unprivileged user on the client** | Tries to read secrets or hijack qeli's privileged file writes | Secrets/config/keys written atomically with `O_EXCL` + `O_NOFOLLOW` and preserved `0600` mode; control socket gated by a `0700` directory. |

## 3. Non-goals and residual leaks (READ THIS)

qeli does **not** claim to defend against the following. Some are fundamental;
some are explicit engineering trade-offs.

1. **Global passive traffic-correlation.** An adversary who can observe both
   ends of the path can correlate a flow by **packet timing and volume**.
   Padding and traffic normalization raise the cost but do not defeat a true
   global passive adversary. qeli is not a high-latency mix network.

2. **DNS metadata while the kill-switch is engaged.** The Linux kill-switch
   allows UDP/TCP port 53 so a *hostname* server can be re-resolved during a
   reconnect. While the tunnel is down, DNS queries (metadata only — not your
   data plane) can transit the physical link. Use an **IP** server address to
   close even this. The data plane and your real IP to arbitrary sites stay
   blocked. (See `qeli/src/client/killswitch.rs`.)

3. **Kill-switch coverage.** Each desktop platform ships a native, fail-safe
   kill-switch: Linux **iptables** (Rust core, `qeli/src/client/killswitch.rs`),
   Windows **WFP** (`New-NetFirewallRule` + default-block outbound,
   `qeli-win/QeliWin/Vpn/KillSwitch.cs`), macOS **pf** (`qeli-mac/QeliMac/Vpn/KillSwitch.cs`).
   All allow only the tun device, the server IP(s), DNS, and DHCP, and stay
   engaged across a crash (the host stays locked — no leak — until qeli runs
   again). The residual DNS-metadata trade-off (point 2) applies to all of them.
   On **Android**, use the OS-level *Always-on VPN + Block connections without VPN*.

4. **Endpoint compromise.** Malware, a hostile OS, a compromised client device,
   or a coerced/backdoored server are out of scope. qeli protects bytes on the
   wire, not a compromised endpoint.

5. **Server-operator trust.** Your server sees your decrypted traffic's
   destination (it is the exit). Run your own.

6. **The `plain` wire mode is not anti-DPI.** It is a bare encrypted tunnel
   (high-entropy from byte 0) intended for already-trusted networks or
   benchmarking — it is a red flag to an entropy detector. Use `obfs` /
   `reality-tls` against active censorship.

7. **Anonymity.** qeli is not Tor. It encrypts content and aims to obscure the VPN
   fingerprint from the DPI models described above; it does not guarantee that a censor
   cannot classify the flow, and it does not anonymize you from a determined global
   observer or from your server.

8. **Optional update check — OFF by default, disclosed here so it is never
   "covert".** qeli ships **no telemetry**. Its only built-in request to the qeli project
   or a developer-controlled service is the *opt-in* "check for updates" feature (Settings on the clients,
   `[web] update_check` on the panel, or `qeli version --check`). When you enable it,
   the client makes a **single unauthenticated GET** of public GitHub release metadata
   (`/repos/litvinovtd/qeli/releases`) — with a **generic User-Agent**, sending nothing
   that identifies you or your device; the version comparison is done locally. On the GUI
   clients it only fires **while the tunnel is up**, and it follows the OS route table.
   **Careful: "the tunnel is up" is not the same as "the request went through it."** In
   full-tunnel it does, and GitHub sees your server's IP. In **split-tunnel** — the default
   on the CLI and the desktop clients — or if GitHub falls under an `exclude`, the request
   goes out directly and GitHub sees your real IP. If you need the guarantee, enable the
   update check only on a full-tunnel profile. The CLI's `qeli version --check` has no
   tunnel gate at all: it performs the request whenever you run it. The panel check runs in
   the operator's browser, not the server process. It is **notification-only** — it never
   downloads or installs anything. Left OFF (the default), qeli opens no update-check socket.
   The residual, when enabled, is a "this host asked GitHub for the qeli repo" signal
   to whatever sees the request (inside the tunnel, that is your own exit's upstream).

9. **Profile reachability polling — ON by default, opt-out.** Windows, macOS and Android
   periodically contact every configured VPN endpoint to paint the status dot and latency.
   The default interval is 30 seconds (configurable from 10 to 3600 seconds); automatic
   sweeps stop while a tunnel is connecting/connected, and Android additionally limits them
   to a visible app. TCP profiles get a bounded TCP connect; UDP profiles get a
   credential-free protocol first flight. These diagnostics send no data to the qeli project,
   but the configured servers and an on-path observer can see their timing. Disable automatic
   profile checks in Settings when that signal is undesirable; manual checks remain available.

10. **Configured server-side egress.** A `reality-tls` handrolled profile probes its configured
    target at startup and every 12 hours to refresh the borrowed certificate/shape. DNS
    forwarding and optional notification/webhook destinations also make the network requests
    their configuration explicitly requests. None of these is telemetry, but an operator's
    egress policy must allow and account for them.

## 4. Assurance status

- **Independent external audit: NOT yet done.** The largest single attack
  surface is the **hand-rolled TLS 1.3 stack** (`qeli/src/protocol/realtls/*`,
  ~3k lines), written so the wire fingerprint can be controlled byte-for-byte
  and to cross-compile without `ring`. It has had internal review and is
  covered by unit tests, but no third-party cryptographic audit. Treat it
  accordingly.
- **Fuzzing:** harnesses for the untrusted-input parsers (ClientHello, packet
  codec, realtls records) live under [`qeli/fuzz/`](../../qeli/fuzz/). Continuous
  fuzzing coverage is being built out.
- **Tests:** the crate has an extensive in-tree unit-test suite (crypto vectors,
  replay window, handshake transcript binding, config round-trips) enforced as a
  CI merge gate alongside `clippy -D warnings` and `rustfmt`.
- **Reproducibility:** prebuilt native cores are currently committed to the repo
  for client convenience; migrating to published, checksummed, reproducible
  build artifacts is tracked in [`ROADMAP.md`](ROADMAP.md).
- **Memory hygiene (accepted limitation):** long-lived secrets are zeroized on
  drop (X25519 static/ephemeral keys, the HKDF input keying material). The
  *transient* per-session AEAD keys held inside the realtls TLS-record objects
  (`aes-gcm`'s expanded key schedule) are NOT zeroized — the upstream `aes-gcm`
  crate does not implement `Zeroize`, and the expanded round keys live inside its
  cipher object, out of qeli's reach. This is accepted defence-in-depth debt: an
  attacker who can read the process's freed heap can already read the *live* keys
  during a session, so it does not change the threat model. Revisit on a
  dedicated memory-hygiene pass or a cipher-crate change.

## 5. If your life depends on this

Then: pin the server identity key (`require_client_key_proof`), use an **IP**
(not hostname) server address with the kill-switch on, use `reality-tls`, keep
all components on the same released version, and understand points 1 and 4
above. And prefer tools that have completed an independent audit until qeli has.
