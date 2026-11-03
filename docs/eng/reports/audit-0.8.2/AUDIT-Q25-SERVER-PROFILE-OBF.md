# D07: server profile obf.* fields

1 October 2026. Traced 59 unique `obf.*` keys from the TCP/UDP [fixture](../../../../scripts/gen_roundtrip_fixture.py) through the [INI codec](../../../../qeli/src/config/server_ini.rs), [profile validation](../../../../qeli/src/server/mod.rs), [TCP](../../../../qeli/src/server/handler.rs), [UDP](../../../../qeli/src/server/udp_handler.rs) and [share-link generator](../../../../qeli/src/config/share.rs). This is static consumer tracing; Q25-F152 already covers parse/serialize round-trip.

| Family and key count | Application and boundary |
|---|---|
| `mode`, `obfs_key`, `obfs_fronting` — 3 | Wire handshake; obfs requires a key. WebSocket fronting applies to TCP obfs; UDP has no TCP nonce exchange. Plain and reality-tls are rejected on UDP. |
| `tls.server_name` and `tls.reality_proxy.*` — 8 | `server_name` does not control the server listener; it supplies non-REALITY share links. The REALITY decoy target, port, short IDs, real TLS, handrolled mode and peek timeout feed the TCP proxy/terminator. With REALITY active, links now derive SNI from `reality_proxy.target` even if `server_name` differs. |
| `padding.*` — 5 | Conditional range/probability checks, outgoing TCP/UDP record encryption and client policy in AuthOK. |
| `fragmentation.*` — 4 | TCP wire-output fragmentation; this is separate from UDP PMTU/DATA_FRAG. Values stay dormant on UDP. |
| `heartbeat.*` — 4 | Interval/jitter/size checks, TCP/UDP timers and AuthOK. Active traffic shaping replaces periodic heartbeat. |
| `traffic_normalization.*` — 2 | Size-list checks; shared TCP/UDP encryption adds padding to the chosen size and pushes policy to clients. |
| `traffic_shaping.*` — 9 | Bounds, Poisson idle cover on TCP/UDP and the client. `stealth` and its rate apply only on TCP; both UDP peers disable it after measured throughput loss. |
| `recordizer.*` — 14 | Policy/batch/record/fragment checks, client capability negotiation and TCP/UDP record assembly/reassembly. With policy=off, tuning stays in INI but is not applied. |
| `anti_fingerprinting.*` — 2 | TCP handshake jitter; values remain stored on UDP, which lacks that TCP handshake. |
| `awg.*` — 4 | TCP obfs junk and UDP junk before handshake. It is inactive on TCP fake-tls/reality-tls; validation warns and links do not advertise it there. |
| `multipath.*` — 3 | TCP bonding, cap/adaptive settings in AuthOK. UDP uses one stream and validation warns about the inactive setting. |
| `quic.enabled` — 1 | UDP QUIC-shaped envelope only; compatibility masking, not a full QUIC/HTTP/3 implementation. Incoming UDP QUIC is detected even with the profile's outgoing flag off; validation warns about its no-op on TCP. |

Finding: with different `tls.server_name` and `reality_proxy.target`, the generator wrote the former into a REALITY link while the proxy contacted the latter. The shared `ClientLink::for_profile` used by CLI and panel now takes REALITY SNI from the target. Manually configured clients still need matching SNI. `server_name` remains effective for non-REALITY links. On isolated lab `.11`, the regression for fake-tls+REALITY, real TLS, no REALITY and URI round-trip, all 12 share-codec tests, `cargo fmt --check` and strict Clippy passed; services were untouched.

Mixed D07 save/reload/import scenarios and the race with an external editor that skips the advisory lock remain. This static matrix does not prove every obfuscation mode on a live server.

Continuation on 2 October: [Q25-F209 in the register](../../plans/AUDIT-DEBT.md) closes mixed API save/INI/history/Quick Start/archive/restart checks for D07 and specifies the mandatory external-writer sidecar lock. Historical counts above are not a new execution. Network combinations and final certification remain D10/D15.
