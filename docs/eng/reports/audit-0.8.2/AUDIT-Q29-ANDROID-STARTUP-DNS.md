# Q29: system DNS and cold Android Release enable

<!-- normative-sync: q29-android-startup-dns-v1 -->

**5 October 2026. Partial DNS/blocking packet; immediate delivery after NetworkPlan is assessed separately. Q29 IN_PROGRESS, plan 28/37 (75.7%).**

## Method

Release/R8 with real INI file-picker import and Settings Always-on/lockdown; readonly API 34 x86_64 AVD on .11 in separate NET/MNT/PID namespaces. Product APK/JNI/Linux CLI and seven managed artifacts are byte-identical; only the test Java receiver changed among 296 source inputs. Production rules unchanged. Initial test build 24 s, ordinary-resolver rebuild 15 s and journal rebuild 15 s, same lab signing certificate; no publication. Instrumentation runner not executed.

The profile sets `dns = tunnel`, `dns_servers = 198.19.0.53`, full dual-stack and kill-switch. This exercises VPN DNS; previous `dns = off` deliberately retains system resolver settings and does not qualify this mode. Receiver UID 10148 differs from Qeli UID 10149; no bind/protect/root/JNI or private preferences injection.

Ordinary system resolution calls `InetAddress.getAllByName` for a fresh `q29-<nonce>.test`. Unique names and authority TTL 0 prevent cache results replacing wire evidence. Fixture A/AAAA addresses are compared. A separate UDP DNS request tests an explicit DNS socket and calibrates physical outbound access before lockdown. Receiver waits at most 7 s; the blocking native resolver itself is not cancelled by this wait. This is a harness bound, not an Android resolver termination guarantee.

Four streams of fresh IPv4/IPv6 TCP/UDP sockets already run before tapping TURN ON. Android-clock APPLIED and each sample start are recorded. Physical delivery before OS lockdown is permitted and not classified as a leak. Every delivered marked post-plan request is checked for TUN source; a follow-up burst starts without source preflight or UI waiting. Private `any` capture includes ports 53/26000, full framed TCP reassembly, UDP/DNS questions/answers and SHA.

## Observations that remain unsuccessful

The first strict startup run FAIL: fresh sockets 67–78 ms after APPLIED received EACCES/pending-connect instead of immediate delivery. Capture/logs retained. QeliService establishes TUN, transfers fd and ACKs before publishing CONNECTED; this does not prove synchronous Android UID routing readiness. Exact delay cause and the required CONNECTED contract remain unqualified; no product fix claimed. Follow-up success does not change the first result to PASS.

Second run FAIL on a short physical DNS reply timeout. Authority received the question and answered, but Android did not receive the reply within 1.5 s. Actual sink/capture requests qualify outbound calibration; a reply timeout remains a timeout, neither successful blocking nor client DNS PASS.

Third run FAIL: automatic-family `DnsResolver.query(null, ...)` returned ENONET before the fixture question was sent. The [Android API](https://developer.android.com/reference/android/net/DnsResolver) selects address families from network availability; reviewed Android 14 source first calls `haveIpv4`/`haveIpv6` using network-bound sockets. Full ENONET cause is not established. This API failure is retained separately; ordinary `getAllByName` results do not close it.

Fourth QUIC run FAIL on incomplete logcat: one of 48 records missing (later dump still had 47). A private append journal was added only in the test APK; root reads evidence, sockets still belong to the ordinary UID. Only QUIC repeats; successful TCP/UDP retain their original APK/source pair. The failed run is not renamed PASS.

Fifth QUIC run FAIL before network probes: uiautomator reported a successful dump, but shell-read could not find the /sdcard XML on three attempts. This is missing required UI evidence, not a network FAIL. Diagnostics/cleanup retained; one more bounded repeat uses unchanged product and conditions.

## Results

| Transport | Socket samples | First fresh sockets after APPLIED | Follow-up burst | Answered DNS questions | Post force-stop | Total echo receipts |
| --- | --- | --- | --- | --- | --- | --- |
| TCP | 288 | FAIL: 28–247 ms | 48/48 | 7 | 0/48 | 166 |
| UDP | 288 | FAIL: 27–36 ms | 48/48 | 7 | 0/48 | 170 |
| QUIC | 288 | FAIL: 85–146 ms | 48/48 | 7 | 0/48 | 202 |

All three ordinary system lookups after connection and three after manual recovery returned exact A/AAAA. Raw DNS also uses TUN. Six unique DNS operations without VPN produced no captured question/answer/authority receipt; 144 new socket samples with retained OS lockdown and no PID/TUN were blocked. Manual re-enable passed 12 full IPv4/IPv6 TCP 16 KiB/UDP 257 payload probes with SHA and TUN source. The 538 total echo receipts include calibration and ordinary control probes, not only burst success.

The next TCP burst began 1,919 ms after APPLIED, including evidence-read/dispatch overhead; this does not assert Android was unavailable throughout that interval. All exact sample timings are in raw. Some later QUIC cold samples received replies; first fresh post-marker sockets still failed. Neither availability FAIL nor retained generic DnsResolver ENONET is closed by follow-up PASS.

Physical socket baselines got only 8/48 replies per transport, but capture/sink received 46/48/44 complete outgoing requests; all four outgoing path types calibrated. Physical cold-phase requests before OS policy are retained. Every delivered fresh marked post-plan request has TUN source; negative samples sent no payload. No new physical SYN/data/UDP in steady/force-stop/blocked window; parser distinguishes late pre-VPN calibration flows. DNS question/answer bytes, RDATA/TTL 0, peer, nonce and raw reply SHA independently checked, zero kernel capture drops. These are bounded windows, not full leak PASS.

Revoke/desired=false/consent ignore/no service/TUN, server exit 0, namespace addresses restored, host/service and persistent userdata SHA/size/mtime preserved across all eight attempts. .10 untouched. Python parse/four CLI guards, nine docs checks, panel, generated bindings and certification PASS. Unchanged product JVM/.NET/native suites not repeated. TCP/UDP qualified with the pre-journal test APK; QUIC with the new journal test APK. Target Release APK is identical in both generations. Full QUIC runtime validates the journal; old missing-log run remains FAIL.


## Scope and remaining work

Specific names/ports and bounded bursts are tested, not arbitrary traffic or every startup millisecond. APPLIED is not the exact time another app receives CONNECTED. Cold-start availability and generic DnsResolver failure remain separate observations. Split/per-app DNS, Private DNS/DoT, an IPv6 resolver, long power/flapping, other API/OEM/arm64 and remaining lifecycle are unqualified. SIGKILL redelivery FAIL and prior matching instrumentation Trace FAIL were not repeated or closed. USER_SKIPPED and D06 without BPF unchanged.

Raw: `audit-debt-20260924/q29-android-startup-dns-20261005`; evidence: `release/certification/evidence/q29-android-startup-dns-20261005.json`. Failed runs and their harness/APK versions and cleanup remain sealed. Overall plan 28/37; Q29 stays open.
