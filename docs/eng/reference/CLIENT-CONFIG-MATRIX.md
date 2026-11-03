# Client config: current contract and the 0.7.14 → 0.7.15 migration

This table records the **current 84-key `[qeli]` contract** for all five clients while
retaining the refactor history. “Before” is released 0.7.14 behaviour; “after” began as
the 0.7.15 shared-core contract and is extended here with current code, including
NetworkPlan v2 and complete IPv6.

Legend:

- **A** — read and applied by this client;
- **C** — accepted and its value preserved, but not applied on this platform;
- **R** — recognized as valid, but neither applied nor re-saved by this client (the headless
  CLI has no profile editor);
- **D** — accepted but lost when a GUI saved the profile; this was a 0.7.14 defect;
- **N** — not yet part of the 0.7.14 contract; that release treated the key as unknown;
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
| `server` `proto` `user` `pass` `key` `bind_static` `mode` `sni` `obfs_key` `front` `reality_sid` `quic` `awg` `jc` `jmin` `jmax` `mtu` `mtu_probe` `gateway` `route_local` `include` `exclude` `dns` `ipv6` `allow_ipv6_leak` `allow_ipv4_leak` | A→A | A→A | A→A | A→A | A→A | IPv6 is negotiated inside authenticated capabilities/NetworkPlan v2. The `auto`, `required`, and `off` modes and symmetric leak controls are shared across all adapters. The shared `gateway` default is `true`; explicit `false` enables split tunnel. |
| `pull_routes` | N→A | N→A | N→A | N→A | N→A | 0.8.3: default `true`; `false` ignores only server routes, preserving local routes, independent full tunnel and protected DNS. INI/URI/model parity. |
| `windows_disable_sharing` | N→R | N→A | N→C | N→C | N→C | 0.8.3: default `false`; opt-in only for the created Windows Wintun. GUID/LUID/CIM ownership and binding readback; no effect on WinDivert or other platforms. |
| `roaming` | N→A | N→A | N→A | N→A | N→A | New shared 0.8 key: `off` forbids roam, `auto` uses safely negotiated TCP/UDP roam with reconnect fallback, and `required` refuses an incomplete contract. Explicit `local`/non-zero `lport` are incompatible with `required`. Linux `dev_attach=true` does not supply `ROAMING_PATH`: `auto` → reconnect; `required` is unavailable. |
| `reality_compact` `reality_split` `reality_split_delay` | R→A | C→A | C→A | C→A | C→A | The shared Rust core now owns REALITY ClientHello sizing and split-write evasion for every app. Editors that do not expose controls preserve the exact values. |
| `reconnect` `reconnect_retries` `reconnect_base_delay` `reconnect_max_delay` | R→A | A→A | A→A | A→A | A→A | The CLI now reads these keys and passes them to its built-in loop too. The core owns the failure counter, retry-limit decision, backoff/jitter and 1.5 s start-to-start floor. Adapters supply monotonic connected time and OS events; offline waiting does not reset the budget. `reconnect_retries=-1` means unlimited retries. |
| `timeout` | R→A | A→A | A→A | A→A | A→A | The connect timeout moved into Rust and now reaches the shared core. |
| `padding` `padding_min` `padding_max` `heartbeat` `heartbeat_interval` `heartbeat_size` `heartbeat_jitter` `shaping` `shaping_gap_mean` `shaping_gap_min` `shaping_gap_max` `shaping_budget` `shaping_min_size` `shaping_max_size` `shaping_stealth` `shaping_stealth_mbps` | R→A | A→A | A→A | A→A | A→A | The shared core parses local values; an authenticated server push, when present, still takes precedence. |
| `keepalive` `tcp_nodelay` `recv_buffer_size` `send_buffer_size` | A→A | C→A | C→A | C→A | C→A | Rust applies socket settings for every native client while TCP keeps OS autotuning. An absent `recv_buffer_size` enables bounded UDP auto-grow 4→8→16 MiB; an explicit value is fixed and `0` leaves the OS alone. New stats expose kernel/internal drops, grow events and granted bytes. |
| `dns_servers` | A→A | A→A | C→A | C→A | C→A | All clients use one DNS plan for legacy IPv4 and v2: explicit resolvers override the push, at most 8 active-family addresses, malformed selected push fails. DNS gets a protected host route even in split mode; no public fallback is invented. |
| `allow_unpinned_tofu` | A→A | C→A | C→A | C→A | C→A | The default is `false` everywhere. `true` permits continuation only after a proven first-seen-key persistence failure; a mismatch against a known pin is always fatal. |
| `password_file` `password_command` | A→A | C→C | C→C | C→C | C→C | Password sources remain headless-only; GUIs never execute commands or read arbitrary files. Linux `password_command` uses `/bin/sh`, a 30-second deadline and a 16 KiB stdout cap; stderr is discarded. Both sources share the 16 KiB raw-secret limit; password_file accepts regular files/symlinks, with one blocking read job and a 30-second cooperative I/O budget. |
| `local` `lport` | R→A | A→A | A→A | D→C | D→C | Linux and Windows/macOS apply the primary TCP/UDP carrier bind. Secondary bonded TCP sockets retain `local` with an ephemeral port and intentionally do not claim the same fixed `lport`. A bind failure blocks the connection instead of silently using another source address/port. Phones preserve the desktop keys. |
| `dev` | A→A | A→A | C→C | D→C | D→C | Linux applies `dev` to its TUN/TAP name. Windows uses an explicit `dev`, with `dev_node` taking precedence; omitting both retains the unique per-profile name. macOS receives kernel-assigned `utunN`; phones use system TUN devices. |
| `device_type` | R→A | C→C | C→C | C→C | C→C | Linux can select `tun` or `tap`; other clients preserve the portable key and reject TAP at connect time because their system VPN devices are L3-only. |
| `dev_attach` | A→A | C→C | C→C | C→C | C→C | Attaching an existing TUN remains CLI-only; every editor preserves the key. Requires NO_PI without VNET_HDR and guarded attachment; see [CONFIG](../manuals/CONFIG.md). |
| `tun.tx_queue_len` | N→A | N→C | N→C | N→C | N→C | Development 0.8.2: Linux sets its owned TUN/TAP TX queue, default `1000` packets, explicit range `1..32767`, no auto mode. Local INI only, not push/link/QR; requires an updated client. Omit with `dev_attach=true`; an explicit value fails on Linux. Other OSes preserve without applying it. [Full contract](../manuals/CONFIG.md#client-tun-tx-queue). |
| `dev_node` `metric` | R→R | A→A | C→C | D→C | D→C | Only Windows applies the Wintun fields; other GUIs preserve them. |
| `persist_tun` `route_file` | R→R | A→A | A→A | D→C | D→C | Desktop lifecycle/routes do not apply to phones, but no longer vanish after a mobile round trip. |
| `kill_switch` | A→A | A→A | A→A | C→A | D→C | Android implements fail-closed behavior through verified system Always-on VPN + lockdown and refuses to connect without it. iOS preserves the key but uses the separate system VPN On Demand policy. |
| `gateway_nat` `exit_node` `lan_subnet` `lan_subnet_ipv6` `post_up` `post_down` | A→A | C→C | C→C | C→C | C→C | Linux/router-only dual-family policy survives every editor; GUIs never execute commands. CLI hooks receive `$1=ifname`, `$2=gateway`, versioned `QELI_*`, a stop reason and temporary full-NetworkPlan JSON. |
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
- form and runtime defaults come from the shared Rust schema; absence of `recv_buffer_size`
  remains significant because it enables automatic UDP-buffer growth;
- `dns_servers` is the canonical representation and silent `1.1.1.1`/`8.8.8.8` fallback was removed;
- Android/iOS no longer delete known foreign-platform keys;
- `allow_unpinned_tofu` is uniform and can never bypass a mismatch with an existing pin;
- Android `kill_switch` now means verified system lockdown instead of an ineffective profile flag.

The `[logging]` section adds **3 fields** to the 84 `[qeli]` keys and survives every GUI.
The CLI applies `level`, `file`, and `time_format`. Windows/macOS use `level` in service/
daemon profiles; the GUI can supply it from application settings. Desktop preserves
`file` and `time_format` in the document without applying them. Android/iOS preserve
all three fields while their own application settings control logging.

Editor grammar and defaults now share [ABI 1.16 configuration core](../plans/CLIENT-CONFIG-CORE.md). The table describes platform application of fields, not separate parser implementations.

## Source cross-check — 22 September 2026

Fixed missing CLI `reconnect*` reads and explicit Windows `dev` application.
C# export no longer drops empty/repeated `route_file` entries; case-distinct paths
remain separate. Unchanged bool/int entries in `carriedKeys` are compared by type,
so saving a form no longer erases duplicate declarations. Android `qeli://` label
decoding also delegates to the core. At that cross-check, model tests covered 84 fields,
including `[logging]`; current coverage with `tun.tx_queue_len` is listed below.

This matrix describes the updated source. Installed applications require rebuilt
ABI 1.16 native libraries; local C#/JVM checks do not replace Apple/device or release
A/B verification. See the [migration status](../plans/CLIENT-CONFIG-CORE.md).

<!-- generated-model-coverage -->
## Model coverage: all 87 fields

This block is generated from `editor/schema.rs`: M is a typed model property;
S is preserved in the core source document and/or `carriedKeys`.
This is not a form-control inventory: fields without a dedicated UI remain available through INI.
All 84 `[qeli]` keys and 3 `[logging]` keys are recognized by the shared parser.

Keys mapped to typed properties: C# 64, Kotlin 59, Swift 58; remaining fields are preserved as S.

| Schema keys | C# (Windows/macOS) | Kotlin | Swift |
|---|:-:|:-:|:-:|
| `server` `proto` `user` `pass` `key` `bind_static` `allow_unpinned_tofu` `mode` `obfs_key` `front` `sni` `reality_sid` `quic` `awg` `jc` `jmin` `jmax` `mtu` `mtu_probe` `gateway` `pull_routes` `ipv6` `roaming` `route_local` `allow_ipv4_leak` `allow_ipv6_leak` `include` `exclude` `dns` `dns_servers` `apps_mode` `apps` `route_file` `reconnect` `reconnect_retries` `reconnect_base_delay` `reconnect_max_delay` `timeout` `padding` `padding_min` `padding_max` `heartbeat` `heartbeat_interval` `heartbeat_size` `heartbeat_jitter` `shaping` `shaping_gap_mean` `shaping_gap_min` `shaping_gap_max` `shaping_budget` `shaping_min_size` `shaping_max_size` `shaping_stealth` `shaping_stealth_mbps` `logging.level` | M | M | M |
| `name` `persist_tun` `windows_disable_sharing` `forward` `local` `lport` `metric` `dev_node` | M | S | S |
| `kill_switch` | M | M | S |
| `allow_lan` `logging.file` `logging.time_format` | S | M | M |
| `dev` `device_type` `dev_attach` `tun.tx_queue_len` `autostart` `exit_node` `gateway_nat` `lan_subnet` `lan_subnet_ipv6` `post_up` `post_down` `password_file` `password_command` `keepalive` `tcp_nodelay` `recv_buffer_size` `send_buffer_size` `reality_compact` `reality_split` `reality_split_delay` | S | S | S |
<!-- /generated-model-coverage -->
