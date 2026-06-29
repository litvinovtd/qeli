# Porting the qeli client to Keenetic (dual-arch: mipsel + aarch64)

Status: **Code complete** — the dual-arch client (mipsel + aarch64) builds and is caught
up to the current release (PR #34/#43 merged, lab-verified); pending only a check on real
Keenetic hardware. This doc is kept as the design/build reference.
The goal is to run the existing Linux `qeli` client on Keenetic routers under Entware,
**for both arches at once** of the model range: MIPS (mipsel) and ARM (aarch64). Without
writing a new native client — we reuse the daemon.

## 1. The feasibility conclusion

Keenetic is Linux. The full `qeli client` is already Linux-only (TUN via `/dev/net/tun` +
`ioctl(TUNSETIFF)`), so the same daemon is installed on the router, cross-built for the
router's CPU.

The only hard blocker is **`ring`** (via `rustls`): it has no MIPS backend. But
`ring`/`rustls`/`rcgen` are used **only on the server side** (`protocol/realtls/server.rs`,
`server/mod.rs`, `server/reality.rs`) plus in tests/docs. The client path, including
`reality-tls`, is **hand-written on RustCrypto**
(`realtls/{client,stream,sansio,keyschedule,record,clienthello}.rs`) — pure Rust,
portable to any arch. So a **client-only build without `ring` compiles** after the
feature refactor (below), the same on mipsel and aarch64.

## 2. The target matrix

| Target | Covers | Rust class | Crypto on hardware |
|---|---|---|---|
| `aarch64-unknown-linux-musl` | new WiFi6 (Cortex-A53: Hopper, Peak/Filogic MT7981) | tier-1/2, std from rustup | ARMv8 crypto-ext → AES-GCM fast, `reality-tls` ok |
| `mipsel-unknown-linux-musl` | the main fleet (MT7621/MT7628: Giga/Ultra/Viva/...) | **tier-3**, needs `-Zbuild-std` | software ChaCha20 → `obfs`/`fake-tls`/`plain` |
| *(opt.)* `mips-unknown-linux-musl` (BE) | rare models on Realtek | tier-3 | like mipsel |

Both main targets — **static musl** (a single binary in `/opt/bin`). Big-endian by
default is NOT built.

> Before fixing the toolchains, take from the devices `opkg print-architecture` (the
> exact ABI string, especially mipsel: o32/float) and `cat /proc/cpuinfo`
> (FPU/crypto-ext).

## 3. A single codebase for both arches (Phase 1)

The principle: **zero arch-specific Rust code**. The difference goes into (a) Cargo
features and (b) the toolchain/runtime. A behaviorally identical binary for any target.

### 3.1 Feature flags (Cargo.toml)

`rustls/tokio-rustls/rcgen/axum/tower/qrcode` → `optional = true`, enabled only by the
`server` feature. Introduced:

```toml
[features]
default    = ["server", "client"]   # the usual server build — as before
server     = ["dep:rustls", "dep:tokio-rustls", "dep:rcgen", "dep:axum", "dep:tower", "dep:qrcode"]
client     = []
# A separate standalone client binary (routers/Keenetic). OFF by default,
# so the server/CI/FFI builds stay byte-identical to the previous ones.
client-bin = ["client"]
```

`default` keeps `server`+`client` → `cargo build` without flags compiles exactly the same
as before the edits (server + web + realtls::server + the FFI cdylib for Android/Win/Mac
unaffected).

### 3.2 Module gating

- `lib.rs`: `client`/`tun` → `feature="client"`; `server`/`web`/`transport` →
  `feature="server"` (plus the existing `target_os="linux"`).
- `protocol/realtls/mod.rs`: `pub mod server` → `#[cfg(feature="server")]`. The client
  submodules (`client/stream/sansio/keyschedule/record/clienthello/ffi`) always stay
  (needed by both the Linux client and the win/mac FFI). References to `realtls::server`
  outside the server modules exist only in `#[cfg(test)]` — a client-only build doesn't
  compile them, and `cargo test` runs with the default features (server on).

### 3.3 portable-atomic (needed only for 32-bit mipsel)

On 32-bit mipsel there are no 64-bit atomics (`target_has_atomic="64"` = false) →
`std::sync::atomic::AtomicU64` is absent, and the code without edits **doesn't compile**.
`AtomicU64` in production is used only in `client/mod.rs` (the stats counters/`last_rx`;
in `server/{handler,udp_handler}.rs` — but that's server-only, not in the client build).

The solution: the dependency `portable-atomic = "1"` and in `client/mod.rs`
`use portable_atomic::AtomicU64;` instead of std. On aarch64/x86_64 it maps to a native
instruction (zero cost), on mipsel — a lock fallback. One code path for both arches.
`tokio` already shims its own internal `AtomicU64` (`loom/std/atomic_u64.rs`).

### 3.4 The entry point

A new binary `src/client_main.rs` (only the client subcommand), `required-features
= ["client-bin"]`. The existing `main.rs` is **untouched**: the binary `qeli` is marked
`required-features = ["server","client"]`, so a client-only build skips it. This way the
default build never compiles the new file — zero risk for the working builds.

The Keenetic build command:
```sh
cargo build --release --bin qeli-client \
  --no-default-features --features client-bin --target <TARGET>
```
`--no-default-features` silences `server` → `rustls/ring/axum/...` aren't compiled.

## 4. Toolchains (on lab .10) — both arches via zig ✅

The linker/cc for both arches — **zig 0.13** (already on .10) via `cargo-zigbuild`. The
OpenWrt SDK was NOT needed. The canonical script — `scripts/build_keenetic.py`
(an idempotent setup of nightly+rust-src+aarch64-target+cargo-zigbuild, a build of both
arches, strip, a pull into `release/keenetic/`). Toolchain reconnaissance —
`scripts/keenetic_toolchain_probe.py`.

### aarch64 (stable, std from rustup) → ~2.3 MB, static ARM aarch64
```sh
rustup target add aarch64-unknown-linux-musl
cargo zigbuild --release --bin qeli-client \
  --no-default-features --features client-bin --target aarch64-unknown-linux-musl
```

### mipsel (tier-3: nightly + build-std) → ~3.3 MB, static-pie MIPS32r2 LE
```sh
rustup toolchain install nightly -c rust-src
# Rust compiles mipsel as soft-float, but zig links mips as fpxx → a float-ABI conflict.
# Force linking to soft-float (the binary doesn't touch the FPU — runs on any mips):
RUSTFLAGS='-C link-arg=-msoft-float' cargo +nightly zigbuild \
  -Z build-std=std,panic_abort --release --bin qeli-client \
  --no-default-features --features client-bin --target mipsel-unknown-linux-musl
```

### Gotchas that surfaced in the cross-build (both arch-specific — visible ONLY here, not on x86)
- **TUNSETIFF** (`tun/iface.rs`): the `ioctl` request type — `c_ulong` on glibc, but
  `c_int` on musl (we cast `as _`); on MIPS a different `_IOW` encoding → the value
  `0x800454ca`, not `0x400454ca` (the choice via `cfg(target_arch="mips")`). Otherwise the
  ioctl would fail at runtime on a live Keenetic, although on x86 everything is "green".
- **mipsel float-ABI**: `-msoft-float` on linking (see above).

### CI
- In `ci.yml` add both targets to the client build matrix (a gate, so that the cross-build
  for both arches doesn't break silently).

## 5. Runtime on the router (the same for both arches)

📖 **Step-by-step deployment with commands and a tunnel check — [KEENETIC-DEPLOY.md](KEENETIC-DEPLOY.md).**
Below — an overview, the full guide is there.

1. **Entware** installed (opkg, `/opt`). The binary → `/opt/bin/qeli-client`.
2. `opkg install ip-full iptables` — the client shells out to `ip addr/route/link/tuntap`
   (`tun/iface.rs`, `client/route.rs`); Keenetic's busybox `ip` is stripped (no `tuntap`).
3. **`/dev/net/tun`**: it must exist (enable the KeeneticOS VPN component — WireGuard/
   OpenVPN — it pulls the tun module). Check: `ls -l /dev/net/tun`.
4. The config `/opt/etc/qeli/client.conf` (the `[qeli]` section), imported from a
   `qeli://` link.
5. **The device-id on a persistent path**: by default `/var/lib/qeli/device-id`, on a
   router `/var` is often tmpfs (lost on reboot → the server sees a "new device" each time,
   spends a slot). In the init script set `QELI_DEVICE_ID_FILE=/opt/etc/qeli/device-id` (the
   env override is already in the code).
6. **DNS — don't touch the router's resolv.conf**: `dns.mode = off`/`manual` in the config
   (`client/dns.rs::setup_dns_for_interface` does an early-return when `mode != tunnel`).
   The DNS of LAN clients — via the router's stock dnsmasq/ndnsproxy.
7. Autostart: `/opt/etc/init.d/S99qeli` (start/stop), as root. Auto-reconnect and
   resilience to an IP/link change are already in the client.

## 6. Gateway mode — the router as a VPN for the whole LAN

The client is designed as an endpoint and **doesn't set up NAT itself**. To route the
LAN:

```sh
echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o vpn0 -j MASQUERADE
iptables -A FORWARD -i br0 -o vpn0 -j ACCEPT
iptables -A FORWARD -i vpn0 -o br0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

Two routing sub-modes:
- **Full-tunnel**: all LAN traffic into the tunnel. The client already knows how to set a
  default route via tun + a bypass route to the server (`client/route.rs`,
  `add_default_gateway`/`full-tunnel`). Enabled in `[routing]`.
- **Selective (by domains/IPs)**: `ipset` + `iptables` + the router's dnsmasq (a pattern
  like kvas/antizapret on Keenetic). More flexible and friendlier to speed.

> ⚠️ The most finicky part: the interaction with KeeneticOS's own firewall/NAT depends on
> the model and firmware version — check on a live device.

## 7. Performance and the wire-mode choice

| | mipsel (MT7621 ~880 MHz, no AES-NI) | aarch64 (A53 + crypto-ext) |
|---|---|---|
| Recommended mode | `obfs`/`fake-tls`/`plain` (ChaCha20) | `reality-tls` is possible |
| Expected ceiling | tens of Mbps | hundreds of Mbps |
| `reality-tls` | very slow (double AEAD, <~20 Mbps) | acceptable |

The mode choice is a config on the device, **not a different binary**.

## 8. Risks

- **The mipsel build** — the main tech risk (tier-3 + `-Zbuild-std` + ABI-match +
  atomics). On aarch64 there's none of this.
- **Perf on MIPS** — a ceiling of tens of Mbps (software crypto). For a channel up to
  ~50–100 Mbps it's ok, for gigabit no.
- **Integration with KeeneticOS's NAT/firewall** — unpredictable, depends on the
  model/firmware.
- **No native integration into the KeeneticOS web UI** — it's a third-party Entware daemon
  (an SSH/init script). A full KeeneticOS component requires the Keenetic SDK — out of the
  realm of realism.

## 9. Checklist

**Phase 1 — the code skeleton + lab verification ✅ PASS (2026-06-11):**
- [x] Cargo.toml: the server deps → optional; the features `server`/`client`/`client-bin`
- [x] lib.rs: modules under features
- [x] protocol/realtls/mod.rs: `server` under `feature="server"`
- [x] client/mod.rs: `AtomicU64` → `portable_atomic`
- [x] src/client_main.rs: the standalone client
- [x] **verification on .10** (`scripts/keenetic_verify.py`): the default `cargo build --release`
  = OK (not broken); `cargo build --bin qeli-client --no-default-features --features
  client-bin` = OK (without rustls/axum/rcgen in the graph); the client-bin `clippy -D warnings`
  = OK; `cargo tree -i ring` → "did not match any packages" (**ring absent**); the binary = ELF x86-64.

**Phase 1.5 — config keys for the router ✅ (2026-06-11):**
- [x] The `[qeli]` parser: `gateway=true` (→ full-tunnel) and `dns=off` (→ don't touch the
  router's resolver) + emit in `to_ini_string` + a test (`config/client.rs`); they do NOT go into the qeli:// link.

**Phase 2 — toolchains and cross-build ✅ PASS (2026-06-11):**
- [x] aarch64-musl: `rustup target add` + `cargo zigbuild` → static ARM aarch64, 2.3 MB
- [x] mipsel-musl: nightly + `-Zbuild-std` + zig + `-msoft-float` → static-pie MIPS32r2, 3.3 MB
- [x] `scripts/build_keenetic.py` (both arches, an idempotent setup, a pull into `release/keenetic/`)
- [x] arch bugs fixed: TUNSETIFF (type+value per-arch), float-ABI (soft-float)
- [ ] CI matrix (both targets in `ci.yml`)

**Phase 3 — runtime/deploy ✅ templates ready (2026-06-11), a device check is needed:**
- [x] `release/keenetic/install-keenetic.sh` (arch detect → the binary, `ip-full`/`iptables`, a tun probe)
- [x] `release/keenetic/S99qeli` (the Entware init + NAT/forward for a gateway + `QELI_DEVICE_ID_FILE`)
- [x] `release/keenetic/client.conf.example` (`gateway`/`dns`) + `README.md`
- [ ] **a check on a live Keenetic** (no device): the arch, `/dev/net/tun`, the interface names,
  the interaction with KeeneticOS's firewall/NAT

**Phase 4 — e2e and measurements (a device is needed):**
- [ ] a tunnel against the production server, ping/speedtest from a LAN client (mips + arm)
- [ ] tuning the wire mode to the hardware
