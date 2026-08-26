# Client config: current contract and the 0.7.14 → 0.7.15 migration

This table records the **current 80-key `[qeli]` contract** for all five clients while
retaining the refactor history. “Before” is released 0.7.14 behaviour; “after” began as
the 0.7.15 shared-core contract and is extended here with current code, including
NetworkPlan v2 and complete IPv6.

Legend:

- **A** — read and applied by this client;
- **C** — accepted and preserved unchanged, but not applied on this platform;
- **R** — recognized as valid, but neither applied nor re-saved by this client (the headless
  CLI has no profile editor);
- **D** — accepted but lost when a GUI saved the profile; this was a 0.7.14 defect;
- `X→Y` — historical state in 0.7.14 and the current state on the right.

`C` and `R` do not mean “misspelled”. A name unknown to every qeli client is still rejected
fail-closed. Current GUI clients preserve every known key even when only another platform
can apply it; separately exposed controls are identified in the notes.
> **Reality/H2 contract:** there is no client H2 key. `mode = reality-tls` selects the
> genuine H2 carrier in the shared Rust core automatically, and that path ignores a requested
> qeli heartbeat. Installed apps receive this behaviour only after their native core is rebuilt,
> packaged and installed; updating the server cannot rewrite an existing client binary.

| Keys | CLI | Windows | macOS | Android | iOS | Current contract / change |
|---|:-:|:-:|:-:|:-:|:-:|---|
| `server` `proto` `user` `pass` `key` `bind_static` `mode` `sni` `obfs_key` `front` `reality_sid` `quic` `awg` `jc` `jmin` `jmax` `mtu` `mtu_probe` `gateway` `route_local` `include` `exclude` `dns` `ipv6` `allow_ipv6_leak` `allow_ipv4_leak` | A→A | A→A | A→A | A→A | A→A | IPv6 is negotiated inside authenticated capabilities/NetworkPlan v2. The `auto`, `required`, and `off` modes and symmetric leak controls are shared across all adapters. GUI→Rust boundaries make platform `gateway` defaults explicit. |
| `reality_compact` `reality_split` `reality_split_delay` | R→A | C→A | C→A | C→A | C→A | The shared Rust core now owns REALITY ClientHello sizing and split-write evasion for every app. Editors that do not expose controls preserve the exact values. |
| `reconnect` `reconnect_retries` `reconnect_base_delay` `reconnect_max_delay` | R→R | A→A | A→A | A→A | A→A | Reconnect remains a platform lifecycle concern. Rust owns one connection attempt, not the GUI's decision to start the next one. The 0.7.15 iOS adapter now actually creates the next generation; before the audit these keys round-tripped but every native/pump failure was terminal. |
| `timeout` | R→A | A→A | A→A | A→A | A→A | The connect timeout moved into Rust and now reaches the shared core. |
| `padding` `padding_min` `padding_max` `heartbeat` `heartbeat_interval` `heartbeat_size` `heartbeat_jitter` `shaping` `shaping_gap_mean` `shaping_gap_min` `shaping_gap_max` `shaping_budget` `shaping_min_size` `shaping_max_size` `shaping_stealth` `shaping_stealth_mbps` | R→A | A→A | A→A | A→A | A→A | The shared core parses local values; an authenticated server push, when present, still takes precedence. |
| `keepalive` `tcp_nodelay` `recv_buffer_size` `send_buffer_size` | A→A | C→A | C→A | C→A | C→A | Rust applies socket settings for every native client while TCP keeps OS autotuning. An absent `recv_buffer_size` enables bounded UDP auto-grow 4→8→16 MiB; an explicit value is fixed and `0` leaves the OS alone. New stats expose kernel/internal drops, grow events and granted bytes. |
| `dns_servers` | A→A | A→A | C→A | C→A | C→A | Every client uses canonical dual-family `dns_servers`. Mobile still imports legacy `dns = IP, IP`, but saves the canonical form. Resolvers are filtered against the negotiated inner families; no public fallback resolver is injected. |
| `allow_unpinned_tofu` | A→A | C→A | C→A | C→A | C→A | The default is `false` everywhere. `true` permits continuation only after a proven first-seen-key persistence failure; a mismatch against a known pin is always fatal. |
| `password_file` `password_command` | A→A | C→C | C→C | C→C | C→C | Password sources remain headless-only; GUIs never execute commands or read arbitrary files. |
| `local` `lport` | R→A | A→A | A→A | D→C | D→C | Linux and Windows/macOS apply the primary TCP/UDP carrier bind. Secondary bonded TCP sockets retain `local` with an ephemeral port and intentionally do not claim the same fixed `lport`. A bind failure blocks the connection instead of silently using another source address/port. Phones preserve the desktop keys. |
| `dev` | A→A | A→A | C→C | D→C | D→C | The interface name applies on Linux/Windows; macOS receives `utunN` from the kernel and phones use their system TUN. |
| `device_type` | R→A | C→C | C→C | C→C | C→C | Linux can select `tun` or `tap`; other clients preserve the portable key and reject TAP at connect time because their system VPN devices are L3-only. |
| `dev_attach` | A→A | C→C | C→C | C→C | C→C | Attaching an existing TUN remains CLI-only; every editor preserves the key. |
| `dev_node` `metric` | R→R | A→A | C→C | D→C | D→C | Only Windows applies the Wintun fields; other GUIs preserve them. |
| `persist_tun` `route_file` | R→R | A→A | A→A | D→C | D→C | Desktop lifecycle/routes do not apply to phones, but no longer vanish after a mobile round trip. |
| `kill_switch` | A→A | A→A | A→A | C→A | D→C | Android implements fail-closed behavior through verified system Always-on VPN + lockdown and refuses to connect without it. iOS preserves the key but uses the separate system VPN On Demand policy. |
| `gateway_nat` `exit_node` `lan_subnet` `lan_subnet_ipv6` `post_up` `post_down` | A→A | C→C | C→C | C→C | C→C | Linux/router-only dual-family policy survives every editor; GUIs never execute the commands. |
| `forward` | A→A | A→A | A→A | D→C | D→C | Site-to-site forwarding remains CLI/desktop-only; a mobile round trip no longer deletes it. |
| `allow_lan` | R→R | C→C | C→C | A→A | A→A | The mobile home-LAN carve-out keeps its semantics; desktop preserves it for phones. |
| `apps` `apps_mode` | R→R | C→A | C→A | A→A | C→C | Windows uses executable paths with WinDivert; macOS uses signing identifiers with a transparent+DNS Network Extension; Android uses package names. iOS preserves the choice but cannot apply it without MDM `NEAppRule`. |
| `autostart` | A→A | C→C | C→C | C→C | C→C | On headless systems this is supervisor/panel policy; GUIs use OS lifecycle and preserve the portable field. |
| `name` | R→R | A→A | A→A | D→C | D→C | Desktop stores the label in `[qeli]`; mobile uses separate profile metadata and now preserves the desktop key. |

## Refactor gaps found and closed

In an intermediate 0.7.15 state the adapters kept serializing several settings that the new
core did not read. All of these gaps were closed before release:

- `timeout`, every padding/heartbeat/shaping setting and `local`/`lport` were added to Rust
  parsing, validation and round-trip serialization;
- `keepalive`, `tcp_nodelay` and socket buffers are no longer replaced by hidden GUI constants;
- `gateway` and every transport-owned value are explicit at the core boundary, so different UI
  defaults do not depend on Rust defaults;
- `dns_servers` is the canonical representation and silent `1.1.1.1`/`8.8.8.8` fallback was removed;
- Android/iOS no longer delete known foreign-platform keys;
- `allow_unpinned_tofu` is uniform and can never bypass a mismatch with an existing pin;
- Android `kill_switch` now means verified system lockdown instead of an ineffective profile flag.

The `[logging]` section is outside these shared `[qeli]` keys: the CLI applies it; Android/iOS
carry it through edits; Windows/macOS use their own log settings and do not parse the section.
