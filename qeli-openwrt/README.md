# qeli for OpenWrt (client)

> **0.8.3 router state fix (issue #205).** Update the binary and init script together.
> Init resolves only the firmware `/var` alias and passes `STATE_DIRECTORY` (normally
> `/tmp/lib/qeli`); the core safely opens/creates the same physical journal directory
> without following child symlinks or changing unsafe permissions. Identity and TOFU
> pins remain persistent in `/etc/qeli`. For manual launch and recovery, see
> [state storage](../docs/eng/manuals/OPERATIONS.md#client-physical-route-recovery).
> The firmware kernel must support `SO_NETNS_COOKIE` for managed route recovery,
> including `dns=off`; a successful cross-build or license export does not prove this.

> **0.8.2 audit scope.** Physical router tests were excluded from the agreed audit.
> Source/SDK and isolated lifecycle checks do not certify the package on your hardware;
> earlier hardware results do not qualify this revision. Use artifacts from an exact
> published release tag and verify target architecture, TUN and firewall/interface names.
> [Current audit evidence and limits](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

A native **OpenWrt** package for the qeli **client**, so an OpenWrt router can dial
out to a qeli server and route its LAN through the tunnel — managed the OpenWrt way
(procd + UCI + firewall + LuCI), not by hand-editing files.

## Design — what's new and what's reused

The client logic is **not reimplemented**. OpenWrt runs the exact same
`qeli client` logic the Linux/Keenetic clients use, so it **inherits core-side
fixes after rebuilding/updating the client binary**, not from a server upgrade alone:

| Fix (release) | Why it matters on a router |
|---|---|
| Dual-family kill-switch on **iptables**+ip6tables, verified with `-C` | In full-tunnel gateway mode the rendered config also guards FORWARD, so LAN traffic cannot fall back to WAN during reconnect; both TUN directions remain allowed. |
| **UDP handshake + encrypted data-record fragmentation** | Routers on an **LTE / 4G / CGNAT WAN** may drop IP fragments — the PQ handshake and oversized encrypted records are fragmented below the outer budget in the application layer. |
| Native inner IPv4/IPv6/dual NetworkPlan | UCI/LuCI expose `ipv6=auto|required|off` and symmetric `allow_ipv4_leak` / `allow_ipv6_leak`; the firewall zone applies NAT44/NAT66. |
| UDP idle/download **liveness** (0.7.4) | No false reconnects on an idle or download-only router tunnel. |
| `gateway` / `dns` INI keys, `bind_static`/H-1, persistent **device-id** + TOFU `known_hosts` | Router runs headless; these are exactly the keys the init script writes. |

So this package = **integration only**: packaging, a procd service, a UCI schema, a
firewall zone, and a LuCI page. The GUI-only fixes (Android IPv4-fallback at
`establish()`, the C# INI parity, low-res layout) are desktop/phone concerns and do
not apply to the headless router client.

## Layout

```
qeli-openwrt/
├── Makefile                         # OpenWrt feed package "qeli" (binary + service + UCI + fw)
├── files/
│   ├── qeli.init                    # /etc/init.d/qeli — procd service (UCI → INI → qeli client)
│   ├── qeli.config                  # /etc/config/qeli — UCI defaults
│   └── qeli.firewall.uci-defaults   # first-install: create the `qeli` firewall zone (fw4-native)
├── luci-app-qeli/                   # LuCI web UI (modern client-side JS)
│   ├── Makefile
│   ├── root/usr/share/luci/menu.d/luci-app-qeli.json
│   ├── root/usr/share/rpcd/acl.d/luci-app-qeli.json
│   └── htdocs/luci-static/resources/view/qeli/config.js
└── build/build_openwrt.py           # cross-compile the client-only binary per arch (zig), for the .ipk
```

## How it runs

1. **Binary**: the client-only target `qeli-client` (`--no-default-features --features
   client-bin`, no `ring` → works on mips), installed to `/usr/bin/qeli-client` and run
   directly as `qeli-client --config <file>` (no subcommand; the default `qeli` bin with
   subcommands needs the server+client features).
2. **Config and secrets**: non-secret settings live in **UCI** (`/etc/config/qeli`) or LuCI.
   Password and `obfs_key` are never UCI options: they are 0600 files below
   `/var/run/qeli/` (tmpfs). On start, `qeli.init` renders a 0600 flat-INI in the same
   tmpfs and passes the password through `password_file`. Secrets therefore must be
   provisioned again after every reboot, either in LuCI or from a trusted boot-time secret
   provider. On first upgrade, legacy UCI secrets are moved to tmpfs and deleted from the
   live UCI config; rotate them because flash wear levelling may retain older blocks.
3. **Persistence**: `QELI_DEVICE_ID_FILE` + `QELI_KNOWN_HOSTS` live in `/etc/qeli/`
   (persistent overlay; `/tmp` and `/var` are tmpfs and reset on reboot) so the server
   doesn't see a "new device" every boot and the TOFU pin survives.
4. **Gateway (full-tunnel for the LAN)**: handled by an **OpenWrt firewall zone**
   (`config zone … name 'qeli' … masq '1'` + a `lan → qeli` forwarding), created once by
   `qeli.firewall.uci-defaults`. This is fw4-native and survives `/etc/init.d/firewall reload`
   — unlike raw iptables, which fw4 would flush. The qeli kill-switch is a separate layer;
   when both `gateway=1` and `kill_switch=1`, the renderer enables no-NAT core forwarding
   ownership so the switch protects forwarded LAN traffic as well as router-local OUTPUT.

## Quick start (on the router)

```sh
opkg install qeli luci-app-qeli      # from the feed, or `opkg install ./qeli_*.ipk`
uci set qeli.main.server='vpn.example.com:443'
uci set qeli.main.user='router1'
# Read from stdin: the secret does not enter UCI, process argv or persistent flash.
printf '%s\n' 'PASSWORD' | /etc/init.d/qeli set_secret pass
uci set qeli.main.key='<server identity hex from: qeli show-identity>'
# H-1 MUST match the server, and the server default is ON. The shipped UCI default is
# '0' because the shipped key is the all-zero TOFU placeholder — the moment you set a
# real key above, flip this too, or the handshake completes and then every record fails
# to decrypt ("Connection error: decryption failed"), because the two sides derive keys
# from different salts. Nothing is negotiated on the wire.
uci set qeli.main.bind_static='1'
uci set qeli.main.mode='fake-tls'; uci set qeli.main.sni='www.cloudflare.com'
uci set qeli.main.gateway='1'       # route the whole LAN through the tunnel
uci set qeli.main.enabled='1'; uci commit qeli
/etc/init.d/qeli enable; /etc/init.d/qeli start
logread -e qeli                      # look for "Auth OK"
```

Or use **LuCI → Services → qeli VPN**. The password fields are write-only and show only
whether a volatile secret exists; an empty field leaves the current value unchanged.

## Notes / compatibility

### Client TUN TX queue (development 0.8.2)

A client binary containing the queue-setting change uses `1000` packets for its
owned Linux TUN/TAP even when the INI omits `tun.tx_queue_len`. This is a core
default, not a server push, and an old installed binary does not acquire it from
a server upgrade. Current UCI/LuCI has **no queue-size option**, and the init
renderer does not emit this key: editing its tmpfs-generated INI is not a persistent
override and is lost on the next render. Do not invent a UCI setting for it.

When running a standalone client with an administrator-owned INI, put
`tun.tx_queue_len = 1000` (explicit `1..32767`, no auto mode) under `[qeli]`, then
stop/start that client. Omit it with `dev_attach=true`; the external owner controls
that queue. A larger queue may increase latency. Linux amd64 functional checks
do not qualify a new MIPS/ARM package on real OpenWrt hardware.
[Full contract](../docs/eng/manuals/CONFIG.md#client-tun-tx-queue).

### Other compatibility notes

- Wire mode by CPU: on low-end **mipsel** prefer `fake-tls` / `obfs` / `plain` (ChaCha20);
  `reality-tls` (double AEAD) is sane only on ARM (aarch64) routers.
- `dns`: resolver **mode**, default `off` (leave the router's dnsmasq/resolver alone).
  Set it to `tunnel` to use the server-pushed resolver, and optionally add IPv4/IPv6
  literals through the repeatable `dns_servers` UCI/LuCI field. Older installations that
  stored a comma list directly in `dns` are migrated by the init renderer at startup.
- The `.ipk` ships per-arch; `build/build_openwrt.py` cross-builds the binary (zig), the
  OpenWrt `Makefile` also builds it from source via the SDK rust feed.
- Real-device validation has passed. OpenWrt models and releases can still differ in
  interface naming, flash layout and fw4 integration, so verify those platform details
  when deploying to a new router model or firmware line.

## Configuration and service failure handling (development0.8.2)

Save & Apply edited fields before using the status controls. Connect/Disconnect
await UCI commit/confirmation before changing service state; Restart joins the same
queue in this page. Apply can include other staged UCI packages. A service error
is reported; it does not undo already committed autostart intent.

The init renderer publishes a complete0600 tmpfs INI by atomic rename. A normal
render failure keeps the previous file; MTU must be0(auto) or576..16602. A failed
firewall mutation/commit/reload stops startup and leaves a root-only tmpfs pending
marker so the next start retries; a successful no-op does not reload firewall.
Partial UCI changes are not rolled back automatically. After correcting the error,
restart qeli. This behavior is covered by shell/JavaScript fixtures; the historical
public0.8.0 hardware result above does not qualify these development changes on a
real router. See [Q31 audit evidence](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

Development status polling reads init-visible UCI through the scoped service_status
RPC; it preserves staged form edits and displays unknown when the read fails.
Maintainer cross-build helpers reject target typos and setup/transfer failures;
Every run uploads this checkout into a fresh private directory. SHA256/ELF-checked
atomic artifact transfer does not qualify full ABI or real router runtime. Development tests execute pinned OpenWrt24.10/25.12 ucode/fs on a Linux host;
The native24.10 rpcd/ubus/UCI/session ACL path is tested in a private Linux chroot;
The actual non-PID1 procd API is qualified below. SDK package installation is qualified in isolated OpenWrt userspace below; firmware
runtime remains unqualified and USER_EXCLUDED.


The first-install firewall defaults use named package-owned sections. An existing
qeli zone is preserved. Failed UCI creation/commit or live firewall reload returns
failure and keeps /var/run/qeli/firewall-install-pending. Qeli start is blocked
while it exists: fix the reported error, rerun
`sh /etc/uci-defaults/99-qeli-firewall` successfully, then start qeli. Do not remove
the marker as a substitute for repair. Retry completes those sections without
duplicating devices/forwarding; this does not roll back partial UCI changes.
The marker is tmpfs state, not a persistent reboot recovery guarantee.

Each helper run allocates a private0700 directory under
/var/tmp/qeli-router-keenetic-XXXXXX or /var/tmp/qeli-router-openwrt-XXXXXX, uploads
the current checkout and uses its own target directory. --sync remains a
compatibility option; upload also happens without it. The old /opt/qeli-src and
shared Cargo.toml backup are no longer used. Manifest restriction to rlib affects
only that private copy. Upload/close failure leaves .router-sync-incomplete and
stops the run; retry creates a new checkout. Runs retain their directories for
diagnosis; after the run finishes, review and remove only its printed owned path.
They are not automatically removed. Qeli compilation uses --locked, --jobs1 and no incremental
cache. Separate runs may still share installed toolchains and Cargo download cache.

Before atomic publication, the same SHA256-bound snapshot must be a little-endian
ELF executable of the requested class/machine, with a file-backed executable entry,
no PT_INTERP or DT_NEEDED; ARMv7 must declare EABI5 hard-float. Failure preserves
the previous local binary, including when its hash would match the remote cache.
These checks do not prove musl identity, CPU ISA, full MIPS float ABI, reproducible
builds or firmware runtime. The shared router policy now selects Rust1.97.0, nightly-2026-06-10 for MIPS,
Zig0.13.0 and cargo-zigbuild0.23.0. Wrong identities fail; missing named components
are installed without changing the default Rust. Encoded/ambient Rust flags cannot
override the Qeli recipe; explicit MIPS soft-float is retained, compiler overrides
cleared and wrappers disabled. Global Cargo config/PATH/shared installations and
upload races remain outside a hermetic/reproducible-build guarantee. This policy
applies to maintainer helpers; the SDK retains its own Rust feed/toolchain. See [Q31](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

The SDK package requires Cargo.lock before compilation and checks the client-only
graph with cargo metadata --locked before cargo install --locked --jobs1.
Missing/outdated lockfiles fail before installation. Keep the source SHA and
PKG_MIRROR_HASH release-cut steps; this check does not validate a real SDK package.

Secret deletion reports filesystem failure through both CLI and LuCI; an absent
file is a successful no-op. Removing the stored file does not stop the current
VPN or erase credentials already loaded by it; restart applies changes.
Legacy UCI migration retains /var/run/qeli/secret-migration-pending through failed
commit and retries on the next start even if staged options are already absent.
After fixing the storage/UCI error, retry start; this does not guarantee reboot
transactions or erase old flash blocks. Rotate migrated credentials.
Failed UCI loads or multiple qeli firewall zones reject start preparation. Standard
rc.common hooks return preparation/cleanup and actual ubus service submission
failures to the caller. Failed stop cleanup or service deletion submission blocks
the next start within that restart/reload call. An unavailable procd/service socket
is a command failure; fix the supervisor and retry. Successful submission still
does not confirm client initialization, completed cleanup or VPN connectivity.

Repeated `start` now compares the rendered INI and volatile password contents
through procd. Changed data replaces the process; identical data keeps its PID.
A secret write alone does not apply it. Failed start preparation refuses the
service replacement instead of removing a running instance; a render failure
keeps the previous INI. This does not roll back firewall/UCI changes or confirm
VPN readiness. Use `restart`/`reload` to request an explicit restart.

The development init renderer quotes string values and escapes double quotes
according to the shared INI parser. Literal quotes, backslashes and significant
edge whitespace in usernames or volatile obfs keys survive rendering. Enter raw
values through UCI/LuCI or the stdin secret command; do not add INI escaping there.
ASCII control characters remain rejected for secrets and stripped from ordinary
UCI values. This formatting rule does not make an invalid endpoint, logging mode
or other setting valid; the client still validates the resulting configuration.

The development secret RPC uses fixed init commands and passes credentials only
through stdin, compatible with the tested OpenWrt24.10/25.12 ucode revisions.
Secrets must contain 1..4096 UTF-8 bytes and no ASCII C0/DEL controls; the limit
counts bytes, not characters. Enter literal values without shell/INI escaping
into LuCI. A secret status of configured requires a readable regular file of
that size in the real runtime directory. Empty/oversize files, directories,
FIFOs and symlinks do not count. Linked runtime directories and non-regular or
linked secret destinations reject writes. Clearing secrets also rejects a linked
runtime directory to avoid deleting outside files; an absent directory is a no-op. Correct the unexpected filesystem
object before retrying; do not treat a failed write as an applied credential.
Host tests cover real ucode/fs and native24.10 rpcd/ubus/UCI/session ACL in a
private chroot. Separate tests exercise the actual official24.10.4 x86 procd
supervision API and rc.common with an inert client process: start/stop/reload,
respawn, autostart links and transport errors. Procd runs as a non-PID1 daemon;
these tests do not confirm VPN cleanup/connectivity, SDK installation, HTTP
serving, OpenWrt boot or router firmware behavior. Administrator path replacement
between checks and publication is outside this guarantee.

The LuCI package explicitly requires luci-base, rpcd-mod-ucode and ucode-mod-fs
along with qeli. An installation missing fs cannot register the Qeli RPC object.
Both secret fields validate ASCII controls, the UTF-8 byte limit and Unicode
before sending RPC. NUL is unsupported by ubus C-string transport: external RPC
producers must reject it before serialization, as it may otherwise truncate a
value before the Qeli handler receives it. Use valid text without control bytes.
LuCI session staging remains separate from init-visible configuration until
commit; administrative global CLI UCI staging is a different context and can be
init-visible before commit. Save & Apply the form before service controls.

### SDK package verification

Use the SDK matching your firmware version and target, with its pinned feeds.
The 7 October audit used official x86/64 SDK24.10.4: actual Qeli package metadata,
IPv6 Kconfig and LuCI IPK compilation/minification passed. A private default-n
Kconfig fixture covered the IPv4-only dependency branch; stock SDK fixes IPV6=y.
The package keeps virtual iptables providers and requests ip6tables only with IPV6.
LuCI IPK owner/URL use LUCI_MAINTAINER/LUCI_URL as required by luci.mk.

The pinned SDK Rust feed uses1.89.0; Cargo.toml declares no global rust-version.
The F358 client-bin source snapshot passed a GNU check and musl compile/link using stock Rust1.89.0,
SDK GCC13.3 and the exported SDK Build/Compile macro/profile. The fresh ELF passed
CLI/INI inspection in the official24.10.4 rootfs. This uses upstream prebuilt Rust
standard libraries; it does not certify SDK Rust bootstrap, the source-download/
release-cut pipeline, other SDK targets, VPN connectivity or router firmware.
Standalone maintainer builds retain Rust1.97.0 and their separate qualification.

The recipe projects only its private SDK Cargo.toml to rlib before metadata/install.
The canonical three-type declaration and an existing rlib declaration are accepted;
unknown declarations stop before Cargo. Unused cdylib/staticlib outputs are not
built or installed; the repository manifest/native ABI declarations remain unchanged.
Source tag/commit, PKG_SOURCE_DATE and source/mirror hashes must be verified at
release-cut. Use the Source filename from actual package metadata; do not assume
.tar.xz (SDK24.10.4 generates .tar.zst). See package/qeli/check FIXUP=1 guidance
in the recipe. Reject recursive-dependency diagnostics even if make returns0.

Three SDK checks and three actual IPK checks live in scripts/test_openwrt_sdk.py.
Run SdkTests only in a prepared owned SDK with .qeli-audit-sdk marker; it temporarily
changes/restores .config and Config-build.in. QELI_OPENWRT_LUCI_IPK selects the built
IPK for IpkTests, including the14 existing LuCI fixtures on its minified JS.
No installed router package is read. Offline opkg was subsequently qualified with
actual signed release dependencies in an official rootfs: nft/legacy providers,
install/upgrade/remove, modified UCI retention and0600 modes, and early refusals.
The initial empty-root failure is retained; live postinst/fw4/procd is unqualified.
Use a proper offline /target inside an owned chroot rather than offline-root /.
Six real-Cargo SDK macro tests live in scripts/test_openwrt_compile.py and require
explicit owned compiler/template fixtures. These do not run against a router. See [Q31 audit](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### HTTP/session audit scope

The actual OpenWrt24.10.4 uhttpd JSON-RPC bridge was tested on private Linux
namespace loopback against native rpcd/ucode/UCI, using the SDK-built LuCI IPK.
Six integration methods cover login, reader/writer permissions, unauthorized
requests, secrets, closed service verbs, session UCI apply/confirm, session-ID
impersonation rejection, revocation/idle expiry, static JS and malformed requests.
Restricted rpcd users need the corresponding read/write luci-base ACL in addition
to luci-app-qeli: the framework supplies UCI RPC methods, Qeli grants only qeli
config/object scope. Accessing a session refreshes idle expiry. Qeli ACL is unchanged.

Tests require root inside private mount AND network namespaces, loopback up,
QELI_OPENWRT_ROOTFS_TEMPLATE, QELI_OPENWRT_RPCD_TEMPLATE and QELI_OPENWRT_LUCI_IPK;
run scripts/test_openwrt_http.py only in an owned lab. No authentication bypass.
Service verbs use an inert adapter; no live VPN, browser login/DOM, TLS or whole-LuCI
cookie/CORS/CSRF policy is qualified by these API checks. Firmware remains excluded.
See [Q31 audit](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Compiler and intermediate build directory (development0.8.2)

The shared router build helper now resolves the selected pin's rustc with
`rustup which --toolchain ... rustc`, verifies the executable and passes it explicitly
to Cargo. Both `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR` point into the owned
run's target directory, so ordinary Cargo build.rustc/build.build-dir settings or
ambient build-dir cannot silently redirect these two inputs. Router CI follows
the same policy. The Linux `keenetic_verify.py` gate now uses Rust1.97.0 with its
installed Clippy component instead of the host default; missing compiler resolution
fails before Cargo. Wrapper/encoded Rust flags follow the shared policy.

This is scoped environment isolation, not a fully hermetic build. Cargo home/ancestor
configuration, forced environment, profile/source/linker overrides, PATH/shared
registry/tool caches and clean independent Qeli A/B still require qualification.
7 real-Cargo methods use dependency-free Linux fixtures; they do not certify a fresh
Qeli cross build, Zig invocation, SDK Rust toolchain or router ABI/runtime. See [Q31](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

The subsequent F361 runtime generation change has fresh GNU Rust1.97 unit/check/
production Clippy/fmt coverage. The preceding SDK1.89/musl qualification covers
the F358 source snapshot, not this subsequent source change. See [Q31](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Standalone helper release profile (development0.8.2)

Shared `scripts/router_toolchain.py` supplies child Cargo with the five explicit
canonical Cargo.toml release fields: lto=fat,codegen-units=1,opt-level=3,
strip=true,panic=abort. OpenWrt/Keenetic standalone helpers and the Linux host gate
override ambient profile values for these fields (including FFI panic=unwind),
Cargo home and ancestor config. Router CI gets the same set by running
`python3 scripts/router_toolchain.py --print-release-profile` from repository root.
FFI libraries retain their separate unwind policy; SDK feed profiles are unchanged.

Actual GNU Cargo mini-crates and a pinned Zig x86_64-musl mini-probe were tested,
not a new whole Qeli/cross/firmware build. Other profile keys, forced child env,
source/linker/PATH/caches and clean Qeli A/B are not fully isolated yet.

The shared standalone/host helper also remaps its private source root to
`/usr/src/qeli` in compiled source locations (`file!()`/panic diagnostics); actual
configuration paths stay unchanged. F365 verified two independent full x86_64-musl
Qeli builds with fresh target/Zig caches and identical offline registry copies:
byte-identical ELF, help/version and INI metadata PASS. This supersedes the earlier
A/B NOT_RUN statement only for this target/recipe; other targets, SDK/CI path policy
and arbitrary build environments remain separate. See the Q31 audit report.

### Audit update: standalone A/B and release preflight (7 October 2026)

Q31-V006 completes independent full A/B for aarch64, armv7 and mipsel; each pair
is byte-identical. Combined with the sealed, input-matched F365 x86_64 pair,
all four standalone targets have scoped A/B evidence. The six new ELF files also
pass static target admission and QEMU help/version/INI metadata checks. This
supersedes earlier other-target A/B NOT_RUN wording. QEMU parser checks do not
qualify firmware, router networking or the full SDK build/release pipeline.

For maintainers, `python scripts/release_preflight.py <branch>` runs optional
32-bit lab gate 2 when `QELI_LAB_PASS` is set. It rejects dirty source/participating
recipe inputs before SSH, freezes exact bytes from one committed `qeli/` Git
archive and builds a private checkout through the common pinned, locked one-job
router recipe. It checks fetched SHA256 and static target ELF and closes SSH on
success/error. `QELI_LAB_SRC` is obsolete. No artifacts are published; the private
checkout remains for inspection. Missing named tools may be installed by the
existing toolchain helper. Full live preflight/CI dispatch and SDK bootstrap/
source-pin/mirror release-cut remain separate release checks.

## Stable source during release preflight

Run `python scripts/release_preflight.py <release-branch>` from a clean committed
working tree, including non-ignored untracked inputs. Preflight prints the admitted
commit and checks it between gates and after certification. Do not commit, edit or
switch branches while it runs; source drift returns FAIL and stops later gates.
The optional lab snapshot/report must carry that same commit. Ordinary gate failures
still accumulate; certification process timeout120 seconds also refuses release.
Ignored caches and a change reverted entirely inside one gate are outside this
boundary guard. Preflight does not lock Git or authorize publishing after later
changes. The lab gate remains optional; this does not replace actual SDK build,
release source pin/archive generation or a successful CI run for the exact commit.

## Actual SDK client package integration (8 October 2026)

The x86/64 OpenWrt24.10.4 SDK now has scoped source-to-IPK evidence: a private Git
fixture with the exact current qeli source tree, SDK-generated/admitted source archive,
prepare, real client-only Cargo build, GCC13.3 musl link, package install/dependency
check/strip and IPK generation. Nested GNU make exposed a broken sed anchor; Compile
now checks the exact accepted crate declaration before projection and uses a command
that survives SDK expansion. Six real-Cargo boundary cases passed.

The fresh IPK passed seven offline opkg install/upgrade/removal/corruption cases
with genuine OpenWrt rootfs/dependency packages and nine executions of its client
in isolated OpenWrt userspace. Both nft and legacy dependency providers passed.
No forced dependencies or invented installed records were used. The r2 artifact is
an upgrade test fixture. Firmware and VPN connectivity were not exercised.

This run used private official prebuilt Rust/std1.89.0 and a copied registry through
the direct SDK package entry; upstream Rust bootstrap, cold/hermetic compilation,
other SDK targets and a successful current Actions/preflight remain unqualified.
The 8 October run did not update production source pin/hash; the subsequent
9 October source-cut qualification below updates those inputs locally. Use the
full SDK dependency graph for a release build; the audit's toolchain bootstrap shortcut
is not release certification. See [Q31](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Current standalone 32-bit verification (8 October)

After the publication-lock change, the current committed source was rebuilt through
Gate2 for ARMv7/MIPS. Both static ELF/SHA checks and32 QEMU CLI/INI cases pass on
cortex-a7/24Kc under uid65534. Fourteen additional executions check the exact
production publication-lock/budget modules in the same standalone release policy.
No new regression was found in this scope. This is neither the full cfg(test) suite
nor firmware/VPN networking, SDK Rust bootstrap or a new independent clean A/B.
Previous four-target A/B retains its original source/date. See
[Q31](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md) for artifacts and limits.


### Release source Git flags

The shared `scripts/openwrt_source_gate.py` used by release preflight requires
committed inputs and refuses `assume-unchanged`/`skip-worktree` flags on `qeli/`,
the package Makefile, `verify-source.sh`, the gate and `release_preflight.py`.
These flags can hide edits from `git status`. Inspect them before source admission:

```sh
git ls-files -v -- qeli qeli-openwrt/Makefile qeli-openwrt/verify-source.sh scripts/openwrt_source_gate.py scripts/release_preflight.py
```

A lowercase status indicates assume-unchanged; `S` indicates skip-worktree.
Review the affected files, clear the applicable flags explicitly and commit the
intended inputs before retrying. Flags on unrelated documentation do not change
this gate's input scope. Clean-source admission still requires the matching
immutable source pin and actual SDK mirror archive; removing flags does not
qualify a stale source cut. [Audit](../docs/eng/reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-FLAGS.md).


### Historical local OpenWrt source cut (9 October 2026)

That qualification pinned the exact full local dev commit `f4b80a9a3052e9ec12c640036928d543f931dafa` and
its actual SDK-generated `qeli-0.8.2.tar.zst` SHA256 `d6c112641de77b446d3a32a702221b247556b873c11f648087aebb57d3b209c5`.
Two real SDK24.10.4 downloads from different private Git URLs and empty download
caches produced identical archive bytes. SDK prepare verified the archive and
all 3131 tracked files matched the pinned Git commit, including licenses
and common native notices. This is a full original commit/tree; its private
shallow mirror did not synthesize or rewrite a commit.

The public `PKG_SOURCE_URL` is unchanged. GitHub returned HTTP422 for the pinned
commit during qualification: publish that exact commit before using this recipe
against GitHub. Local matching pin/hash is not proof of public availability or
successful Actions, Rust bootstrap, package compilation or router networking.
The release preflight source gate passes only with the matching SDK archive;
missing or modified bytes still refuse admission. Every later qeli tree change
requires a new immutable cut and fresh SDK archive hash. See the
[qualification](../docs/eng/reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-CUT.md).


### Historical local OpenWrt source cut (12 October 2026)

That recipe pinned `c71e4803cd086add92c066dd48a64af1fdb9dec0` and the actual SDK-generated source archive
SHA256 `2843576ae0eac173c95bb1f222d9459ef402ea992a0c43ff496e1e1f52ed8137` (28029607 bytes). Two SDK24.10.4 downloads from empty caches
and distinct private Git URLs matched; prepare verified the hash and all
3272 tracked files matched the original commit. Build/Compile and Install
are unchanged; no new Rust bootstrap, full package build or router runtime
is claimed. The committed production gate accepts that archive and refuses
modified/missing inputs.

The pinned commit is still local: read-only GitHub returned HTTP422 and no
push CI for that SHA. Publish the exact pin before using the public URL; final
release CI and whole release preflight remain separate requirements. Later
recipe/docs changes do not change `qeli/` source admission or the archive
identity. See the [current qualification](../docs/eng/reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-CUT.md).


### Historical local OpenWrt source cut (14 October 2026)

The recipe then pinned `ee2b74aafb2a57a2613541223c5522908cb71f71`, which includes the qualified bonded-slot core fix.
The actual SDK24.10.4 source archive has SHA256 `6c82f2162ba9b4939c8d40393a157d5483ccdc6796e41706f0ec2672ee95fb16`
(28375941 bytes). Two downloads from empty caches and distinct private Git URLs
produced identical bytes. SDK prepare verified the archive; all 3348 tracked files
match the pinned original commit. Build/Compile, Install, public URL and package version are unchanged.
The source gate accepts the committed cut and rejects missing or modified archives.

This is a local source-cut qualification. The exact pin has not been published by this audit;
public availability and current push CI remain unqualified. Rust bootstrap, a fresh full package
build and physical-router networking are separate checks. The 12 October package/runtime results
retain their original source and do not qualify the later core delta. See the
[source-cut report](../docs/eng/reports/audit-0.8.2/AUDIT-Q34-OPENWRT-SOURCE-CUT.md).

### Current standalone 32-bit verification (14 October 2026)

ARMv7/MIPS clients including the bonded-slot fix were freshly compiled from
`d26c78df4cf1556046332b5a7744208a15c00e06` using the common pinned recipe and private offline registry/target.
Both static ELF/SHA admissions and32 QEMU10.0.13 CLI/INI cases pass on cortex-a7/24Kc
under uid65534. This qualifies current standalone compilation and CLI behavior;
it does not qualify a new SDK1.89/IPK build, full VPN networking, cold compiler
bootstrap or physical firmware. The12October package keeps its original source.
All owned build/QEMU/cache resources were archived and removed; production preserved.
See the [current32-bit scope](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Current SDK package verification (14 October 2026)

The source at `2061407d12983a61ba958e2b88adcf660e94d3bc` was built through stock
SDK 24.10.4 x86/64 Download/Prepare/Cargo/Install/dependency-check/strip/BuildPackage,
using private official prebuilt Rust/std 1.89 and GCC 13.3 musl linking.
IPK SHA256: `eb3886d8c449f425726e5ee4cc232af1e4a45e2194dc2970ee6c4741c04120fc` (2711950 bytes).
Seven offline opkg cases and nine actual OpenWrt-userspace CLI/INI cases passed.
All 533 Rust notices match by bytes, modes and root ownership.
The opkg test helper now terminates owned namespace children and preserves partial
output on timeout, verified by both the suite and an actual timeout test.
Owned build/toolchain/cache/rootfs resources were archived and removed.

The private Git fixture preserves the exact qeli tree, but is not the full original
release commit. The production source cut remains separately qualified.
A14October cold feed Host/Compile attempt compiled bootstrap but failed on four
HTTP404 responses for its pinned LLVM CI artifact. That earlier attempt did not
qualify stage2/dist/Host/Install or the cold graph; the later Clang-host result
below provides a separately qualified source-toolchain campaign. This package test does
not certify physical firmware, a public source pin, hosted CI or a release.
See [current SDK scope](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Earlier bounded source-LLVM attempt (14 October 2026)

The private pinned feed's single `download-ci-llvm=false` change has now passed
actual prepare/configure and bootstrap compilation, then entered bundled LLVM
C++ compilation. Last recorded Ninja indicator: 548/3710. The owned time
guard stopped the bounded attempt; full LLVM/rustc/dist/Host/Install and final
cold SDK/IPK still need qualification. Original CI404 failure remains separate.
This confirms the configured download bypass, not a completed toolchain. The
production feed was not modified. See the [actual result and cleanup](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Later Clang source attempt: disk capacity limit (14 October 2026)

A private Clang19 GNU host variant reached LLVM operation 3340/3710,
then stopped at 1003.2 MiB free, below the 1024 MiB safety floor.
Rust stage2/dist and Host/Install did not complete. No subsequent cold SDK
package/opkg campaign started. The pinned Rust source/feed and musl target
compiler/linker were preserved; host cc/cxx and jobs=1 were explicit overrides.
The source compiler fallback remains unqualified on this lab.

The owned build root and unit were removed after archive verification;
only a 142834-byte evidence archive was retained locally. Before
retrying, provide a materially larger disk reserve. The Rust compiler guide
[recommends 30GB+ free disk](https://rustc-dev-guide.rust-lang.org/building/prerequisites.html);
that is general guidance, not a measured minimum for this pinned dist build.
See the [actual Clang disk failure](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

The exact GNU-host Clang TOML entries and the unchanged musl-target boundary
are described in [the source-bootstrap configuration instructions](INSTALL.md#exact-gnu-host-clang-configuration-for-the-qualified-variant).

The 15 October source-bootstrap campaign completed LLVM/Rust Host/Compile and Host/Install. This qualifies the compiler configuration above, not a completed Qeli SDK package. The following SDK consumer failed at `defconfig`: its external PATH incorrectly prepended `staging_dir/host/bin`, causing OpenWrt prerequisite checks to resolve their own canonical symlinks. Enter the top-level SDK with external host tools in PATH (for example, private `deps/usr/bin:/usr/bin:/bin`), clear inherited `ORIG_PATH`, and let OpenWrt add its generated tools itself. Do not use `FORCE=1` to bypass these checks. The old consumer cleanup also deleted the installed compiler; logs remain, binaries are not reusable. See the dated Q31 report and source/compiler failure evidence.

### Qualified Clang-host source bootstrap (2026-10-15)

The later private SDK campaign completed LLVM source compilation, Rust1.89
stage2/dist and Host/Install, followed by the normal package/qeli/compile graph,
7 actual opkg and9 userspace/CLI/INI cases. It kept the pinned Rust source/feed
and musl target compiler/linker. In addition to download-ci-llvm=false, it
selected installed Clang19 as GNU host cc/cxx and jobs=1 in the generated
bootstrap configuration after Host/Configure. Edit the existing build/host
sections; a later Host/Configure can regenerate them. These are results from one controlled host, not a general minimum-resource promise.

The direct host-* goals and the root graph use different Rust installation stamp
locations (host versus hostpkg). R8 produced an IPK but exposed a masked
upstream Host/Install failure after dist autoremove and a post-check refusal.
The continuation verified the entire installed prefix against the qualified source-built
backup, explicitly imported only cache metadata into the root graph namespace,
and qualified normal graph reuse plus the same IPK runtime. The R9 refusal
on the SDK .built_check timestamp update remains historical; R10 recognizes
that normal metadata change while verifying contents and tool identity. This is an
explicit cache handoff, not a clean first bootstrap-to-root-graph run. Original
failures are retained. Future bootstrap/consumer runs must use a consistent
SDK graph namespace; do not infer installation success from make exit alone.

OpenWrt chroot checks require PATH=/usr/sbin:/usr/bin:/sbin:/bin. The lab
systemd manager uses a merged-/usr PATH without /bin; under that environment
opkg falsely reported malformed IPKs and timed out. A same-IPK negative and
positive probe isolated the cause. R13 normalized only the child environment
and passed all7 opkg and9 CLI cases; no host PATH, devices or procfs changed.

Both owned compiler/runtime roots and their large caches were archived and
removed after evidence verification. Original CI404, GCC OOM and bounded
partial outcomes retain their dates. Public source pin/hosted release
qualification remain open; physical router USER_EXCLUDED.
See the [qualified source compiler and SDK result](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

### Historical dependency integration source cut (16 October 2026)

The recipe then pinned `084682e5f3efc05efaf4154b4d5a3eff2750a21d`, containing the updated
Cargo lock, canonical isolated fuzz lock and the matching dependency notices. This immutable commit is available
from the repository through the dependency integration PR; this does not publish a release.
Stock SDK 24.10.4 download/prepare produced SHA256
`df98f489de92b6738048973cc74e84dbf3ee829ef0f1b66badc0a7c091aab671`
(27207208 bytes). A second empty download cache with a distinct private Git URL
produced the same archive. All 3442 prepared tracked files match the exact pinned
commit, including modes and contents; the SDK Git export script is unchanged.

This check qualifies the source export and prepare phase. It does not rerun the
Rust compiler bootstrap, the full SDK/IPK build, opkg runtime or physical-router
networking. Earlier package results retain their original source and scope.
The strict source gate still requires the actual SDK archive and rejects a changed
`qeli/` tree. Build/Compile and Install are unchanged. Temporary SDK files were
removed after saving the proof and verifying that the lab service was preserved.

### Historical documentation and DNS-comment source cut (16 October 2026)

The recipe then pinned `81269a0fd31b74e73174c5aa8fef4d675a1420b6`. This snapshot contains the
audit-report relocation, corrected documentation and three DNS comment corrections;
executable Rust lines and their line numbers are unchanged. Independent native A/B
builds of the corrected source match the previously qualified four native artifacts.

Unmodified stock SDK 24.10.4 download/prepare produced SHA256
`afcd57ea32c6743198c7f51e92baadbaf686c54a7886fe2d4f1ca5ba0def1a08` (27231668 bytes). Two empty download
caches with distinct private Git URLs produced the same bytes; all 3447 prepared
files and modes match the exact Git commit. The actual SDK archive is retained for
the strict source gate. This is an export/prepare check, not a fresh full SDK/IPK,
compiler-bootstrap or physical-router run. Earlier runtime evidence retains its
original source and scope.

### Current 0.8.2 integrated source cut (17 October 2026)

The recipe now pins `b8a5cbd1417b0d3da9dad645d4942c202ba46977`, included in the
`dev` preparation history, with the Linux client `tun.tx_queue_len` change merged,
original legal resources embedded in the CLI and the `licenses` read/export command. One fresh
stock SDK 24.10.4 `download`/`prepare` produced SHA-256
`74f2afbc968904133404825024d1479184b89d5a9cece09a2aefae85eb147bf1`
(27358709 bytes). All 3484 prepared tracked file contents match that exact commit.
The actual SDK archive is retained locally for the strict release source gate.
This qualifies source export/prepare, not a repeated compiler bootstrap, full SDK/IPK
build or physical router test. It does not publish a tag or GitHub Release.

Текущий пакет закреплён на `b8a5cbd1417b0d3da9dad645d4942c202ba46977` из истории подготовки `dev`:
включена клиентская настройка Linux `tun.tx_queue_len`, в CLI встроены оригинальные
лицензионные ресурсы и команда `licenses` для чтения/экспорта.
Свежие `download`/`prepare` в штатном SDK 24.10.4 дали указанный выше SHA-256;
содержимое всех 3484 подготовленных
отслеживаемых файлов сверено с этим commit. Сам SDK-архив сохранён локально для строгой
проверки источника релиза. Это не повторная сборка компилятора, полного SDK/IPK и не
проверка физического роутера. Тег и GitHub Release этим действием не публикуются.

### 0.8.3 source cut — 25 October 2026

The current recipe pins `421fc5cde5dd56a139e658391e3fbabd1e3c743b`.
Two stock SDK 24.10.4 downloads with empty, independent caches and distinct private
Git URLs produced identical `qeli-0.8.3.tar.zst` archives: SHA-256
`0dabf6838fa905d402af1dbf3e49d6c34aced49383d03040a50bf50bb7b2de9b`
(27,886,248 bytes). SDK prepare verified all 3,572 tracked file contents against
that commit. This qualifies source export/prepare, not a full SDK/IPK build or a
physical router test. The public Git URL remains unchanged; no release is published.

Текущий рецепт 0.8.3 закреплён на указанном выше commit. Два независимых экспорта
штатным SDK 24.10.4 дали одинаковый архив и SHA-256; после prepare проверено
содержимое всех 3 572 отслеживаемых файлов. Это проверка экспорта/подготовки
исходников, не полная SDK/IPK-сборка и не тест физического роутера. Публичный Git URL
не изменён; релиз не публикуется.
