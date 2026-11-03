# Q29: authenticated Private DNS / DoT

<!-- normative-sync: q29-android-trusted-dot-v1 -->

Four strict Private DNS scenarios passed over TCP, UDP and QUIC on the isolated
.11 API34 x86_64 AVD with production Release R8. Android's system resolver validates
trust and hostname; product code and its TLS settings are unchanged. Q29 remains
IN_PROGRESS, overall plan 28/37 (75.7%); this qualifies the bounded DoT block.

| Transport | Seconds | DNS operations | A/AAAA/raw answers | Burst samples | Result |
|---|---:|---:|---:|---:|---|
| TCP | 245.27 | 13 | 13 | 192 | PASS |
| UDP | 241.21 | 13 | 13 | 192 | PASS |
| QUIC | 234.18 | 13 | 13 | 192 | PASS |

## Qualified behavior

- Untrusted test CA: TLS rejection, system lookup fails.
- CA temporarily added only to the readonly AVD: an app's unique name returns
  A/AAAA over strict DoT, with correct SNI and TUN source in TLS receipts.
- Trusted CA with mismatched SAN: TLS rejection and no system plaintext fallback.
  A separate successful raw UDP probe demonstrates that the network path is usable.
- Correct provider restored: another uncached lookup succeeds over DoT.

39 DNS operations, 39 A/AAAA/raw answers, including 12 authenticated A/AAAA answers
in trusted/recovered. Unique names correlate plaintext capture, TLS receipts and
app journal. Provider bootstrap is accounted separately from app nonce requests.
Invalid CA/SAN produces no app DNS receipt or plaintext fallback.

36 full IPv4/IPv6 TCP/UDP payload probes (12 bootstrap, 12 during DoT, 12 manual
recovery), verified SHA; 576 burst samples, 144 blocked after stop. Three independent
PCAPs: no new physical requests in the observed protected window, zero kernel drops.
No universal immediate first-packet delivery claim after state changes.

## Harness fixes and retained failures

`StartupDns.diagnose` uses the Package Manager UID instead of hardcoded 10148.
A UID10149 regression fails on the old implementation and passes on the fix;
foreign UIDs remain rejected. UDP/DoT share a DNS response builder. Fresh 12 helper
tests and three CLI guards PASS; 172 JVM/lint checks are reused against unchanged
product inputs, with no unnecessary rebuild.

Two initial FAIL attempts remain preserved and excluded from PASS totals. The first
observed no new strict TLS validation for the unchanged provider after installing
CA. Positive validation now uses a distinct SAN-covered name; the suspected cache
root cause is not independently qualified. The second interpreted an unnecessary
`nsenter` error as missing CA directories. Shell/netd share a mount namespace;
root commands run directly there and other command failures are not hidden.

## Reproduction and limits

`--suite private-dns --variant release --leak-bursts --transport tcp|udp|quic`
requires apps_mode=all, pinned fixed APK/manifest, OpenSSL, root and a dedicated
`/var/tmp/qeli-q29-data-*`. It uses private NET/MNT/PID namespaces and a readonly AVD.
Certificates are short lived; private keys are not included in evidence. Original
CA hashes/mounts, Private DNS settings, host/service/firewall/routes and persistent
userdata were restored for all five attempts; .10 remained untouched.

Exact earlier production R8 pair and matching mapping from CONNECTED gate,
non-debuggable app with lab signature. Product APK SHA
`786e8954762b63a4c2cf8ad873376aeecd594bb5c98999df03d3f58710a8eaf2`.
299 source inputs (README only changed), 22 auxiliary inputs (two changed,
three new), 14 native / 7 managed artifacts unchanged; one prior regression input
changed for dynamic UID. The opt-in instrumented ABI APK was not substituted.

Raw: `audit-debt-20260924/q29-android-trusted-dot-20261005`.
Evidence: `release/certification/evidence/q29-android-trusted-dot-20261005.json`.

[Prior SIGKILL FAIL](AUDIT-Q29-ANDROID-SYSTEM.md) and
[auto/null DnsResolver ENONET](AUDIT-Q29-ANDROID-RESOLVER-DIAGNOSTIC.md) remain open.
Other API/OEM/arm64, physical sleep and multi-hour soak are not qualified here.
Mac/iOS/router/Windows VM USER_SKIPPED; D06 without BPF is unchanged.
