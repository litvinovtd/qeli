# Installing the qeli client on OpenWrt

> **0.8.3 / issue #205:** install the updated binary **and** init script. The service
> passes the real `/var` target plus `/lib/qeli` as `STATE_DIRECTORY`; on standard
> OpenWrt this is `/tmp/lib/qeli`, not a new location. No unsafe directory is chmodded
> or adopted by init. Direct launches need the same environment; see
> [state storage and recovery](../docs/eng/manuals/OPERATIONS.md#client-physical-route-recovery).
> Managed routing requires kernel `SO_NETNS_COOKIE` support even with `dns=off`.

> **0.8.2 audit scope.** Physical router tests were excluded from the agreed audit.
> SDK and isolated lifecycle evidence does not replace testing on your firmware.
> Install an artifact from an exact published release tag and verify architecture,
> TUN support and firewall/interface names. [Audit scope](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

Two ways to install: **A) prebuilt binary** (fastest — hand-install + opkg deps) or
**B) from source** (proper feed package + `.ipk`). Both end with the same UCI/LuCI
config and a procd service.

---

## 0. Prerequisites (on the router)

```sh
opkg update
opkg install kmod-tun ip-full iptables ip6tables ca-bundle
ls -l /dev/net/tun        # must exist (kmod-tun provides it)
```

- **Disk space:** the 0.8.2 client ELF is 8.93 MiB (aarch64), 9.07 MiB (armv7),
  9.66 MiB (x86_64) or 10.87 MiB (mipsel). Also reserve space for dependencies,
  the previous binary and staging the replacement; the binary size alone is not
  an installation-space budget. On small-flash devices use **extroot** or a USB/`/opt` overlay.
- **Wire mode by CPU:** low-end **mipsel** (MT7621/7628) → `fake-tls` / `obfs` / `plain`
  (ChaCha20). `reality-tls` (double AEAD) is sane only on **aarch64** routers.

---

## A. Prebuilt binary (quick)

1. Pick your arch (`opkg print-architecture` / `uname -m`) and download the matching
   prebuilt `qeli-client-openwrt-<arch>` binary from **GitHub Releases** (aarch64 /
   x86_64 / mipsel / armv7, static musl), then copy it to the router:

   > `build/build_openwrt.py` is a **maintainer-internal** helper (it cross-builds on a
   > private lab host over SSH) — don't run it yourself; use the release binary here, or
   > build from source via the SDK (section B).
   >
   > This step used to `scp` out of `qeli-openwrt/dist/`, which is a **local build output
   > directory and is gitignored** — so it does not exist in a fresh checkout at all, and in
   > a maintainer's tree it holds whatever was built last (it was still carrying 0.7.13
   > binaries during 0.7.14). Take the binary from the Release you downloaded. Maintainers:
   > the published set for a version lives in `release/dist/v<version>/`, and that path is
   > version-explicit precisely so it cannot go quietly stale. (Audit 2026-08-01, §7.)

   ```sh
   # from your PC, from wherever you saved the download:
   scp qeli-client-openwrt-aarch64 root@192.168.1.1:/usr/bin/qeli-client
   # and the integration files, from a checkout of this repo:
   scp qeli-openwrt/files/qeli.init   root@192.168.1.1:/etc/init.d/qeli
   scp qeli-openwrt/files/qeli.config root@192.168.1.1:/etc/config/qeli
   scp qeli-openwrt/files/qeli.firewall.uci-defaults root@192.168.1.1:/etc/uci-defaults/99-qeli-firewall
   ```

2. On the router, fix perms and run the firewall-zone defaults once:

   ```sh
   chmod 755 /usr/bin/qeli-client /etc/init.d/qeli /etc/uci-defaults/99-qeli-firewall
   chmod 600 /etc/config/qeli
   sh /etc/uci-defaults/99-qeli-firewall      # creates the `qeli` fw zone (or runs on next boot)
   ```

3. Go to **§3 Configure**.

---

## B. From source (feed package + .ipk)

On a build host with the **OpenWrt SDK matching your firmware version and target**
and its pinned feeds (see the SDK verification scope below):

```sh
# 1. Add the rust + luci feeds (rust is needed to compile the client).
./scripts/feeds update -a && ./scripts/feeds install -a

# 2. Drop the package into the tree (symlink or copy this dir).
mkdir -p package/qeli
cp /path/to/qeli-openwrt/Makefile /path/to/qeli-openwrt/verify-source.sh package/qeli/
cp -r /path/to/qeli-openwrt/files package/qeli/files
cp -r /path/to/qeli-openwrt/luci-app-qeli package/luci-app-qeli

# 3. Select and build.
make menuconfig        # Network → VPN → <*> qeli ;  LuCI → Applications → luci-app-qeli
make package/qeli/compile V=s -j1
make package/luci-app-qeli/compile V=s -j1

# 4. The .ipk lands in bin/packages/<arch>/…  — install on the router:
# Use the actual output names; SDK24.10.4 uses <ver>-r<release>.
opkg install ./qeli_<ver>-r1_<arch>.ipk ./luci-app-qeli_<ver>-r1_all.ipk
```

> **Where's the Rust crate / Cargo.toml?** You don't place it — the package fetches it.
> `package/qeli/Makefile` clones the whole repo (`PKG_SOURCE_PROTO:=git`) and the Cargo
> project lives in the repo's `qeli/` subdir (`qeli/Cargo.toml`); the build cd's into it
> automatically. So `package/qeli/` only needs the `Makefile`, build-time `verify-source.sh` and `files/` — the crate comes
> from the git source, not from your local copy. (To build a LOCAL/modified crate instead,
> point `PKG_SOURCE_URL`/`PKG_SOURCE_VERSION` at your fork, or use `PKG_SOURCE_PROTO` with a
> local mirror.)

`opkg install` pulls `kmod-tun`/`ip-full`/`iptables` automatically and runs the
firewall-zone uci-default.

---

## 3. Configure

Get the connection bits from the server's link and the key from the server:

```sh
# on the SERVER:
qeli add-client router1 --link --host vpn.example.com   # prints a qeli:// link
qeli show-identity                                       # prints the public key to pin
```

Set non-secret options via **UCI** (or LuCI → Services → qeli VPN). Credentials are
write-only per-boot tmpfs secrets and are deliberately never committed to UCI/flash:

```sh
uci set qeli.main.server='vpn.example.com:443'
uci set qeli.main.user='router1'
printf '%s\n' '<password>' | /etc/init.d/qeli set_secret pass
uci set qeli.main.key='<64-hex server identity>'   # zero/empty = TOFU
uci set qeli.main.bind_static='1'                  # keep on with a real key (drop to 0 for TOFU)
uci set qeli.main.mode='fake-tls'
uci set qeli.main.sni='www.cloudflare.com'
uci set qeli.main.gateway='1'                      # 1 = route the WHOLE LAN through the tunnel
uci set qeli.main.dns='off'                        # leave the router's resolver alone
uci set qeli.main.enabled='1'
uci commit qeli
```

`gateway = 1` turns the router into a **full-tunnel gateway**: the firewall zone `qeli`
NATs the LAN out the tunnel. `gateway = 0` is split-tunnel (only the tunnel subnet +
pushed routes).

---

## 4. Run

```sh
/etc/init.d/qeli enable        # start on boot
/etc/init.d/qeli start
/etc/init.d/qeli status

logread -e qeli                # watch for "Auth OK"
ip addr show qeli0             # the tun should have an address
ip route                       # full-tunnel: 0.0.0.0/1 + 128.0.0.0/1 via qeli0
```

Verify egress from a LAN client (full-tunnel): its public IP should now be the server's.

```sh
# from a LAN PC:
curl -s https://api.ipify.org ; echo      # == server IP when gateway=1
```

---

## 5. Troubleshooting

| Symptom | Check |
|---|---|
| `/dev/net/tun missing` | `opkg install kmod-tun` |
| Stuck handshake on **LTE/4G WAN** | already mitigated (0.7.4 UDP fragmentation); confirm `proto`/`mode` match the server |
| `Auth` fails | `user`/`pass`/`key` mismatch; check `qeli show-identity` on the server |
| LAN has tunnel but no internet | firewall zone — `uci show firewall | grep qeli` should show `name 'qeli'`, `masq '1'`, and a `lan → qeli` forwarding; `fw4 reload` |
| Reconnect loops | check time sync (`ntpd`); the server log for the disconnect reason |
| Router DNS broken | set `dns='off'` so the client doesn't touch `resolv.conf` (dnsmasq owns it) |

Logs: `logread -e qeli`. Raise detail with `uci set qeli.main.log_level='debug'; /etc/init.d/qeli restart`.

`log_time_format` controls the timestamp the client itself prints (`none` |
`datetime` | `rfc3339` | `time` | `epoch`). It ships as `none` on purpose: procd
sends stderr to syslog, which already stamps each line, so any other value gives
you two timestamps per line in `logread`. Set `rfc3339` only if you forward these
logs off the router and need UTC that lines up with the server's.

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


## OpenWrt release source admission (development 0.8.2)

Gate 3 in `scripts/release_preflight.py` now requires committed participating
inputs, one literal `:=` declaration per source/version/hash variable, a full
immutable commit SHA and the same committed `qeli/` tree as the candidate.
Branches, tags, abbreviated IDs, repeated/qualified/eval/define/undefine metadata,
missing or invalid Cargo `[package].version`, dirty inputs and Git errors refuse
release. Git commands use the repository root and a 30-second timeout.
An older commit with the same crate tree remains valid; matching HEAD exactly
is not required because writing the pin creates another commit.

Set `QELI_OPENWRT_SOURCE_ARCHIVE` to the local **SDK-generated Source archive**
before running preflight. Obtain its actual filename from package metadata,
produce/check it through the SDK download/check steps in the recipe, and commit
the matching source pin/hash. Gate 3 hashes the file and compares its SHA256 to
`PKG_MIRROR_HASH`; absent, empty, nonregular, linked, mismatched or observably
changing files refuse admission. No downloads, extraction or release publication
are performed. A syntactically valid hash alone no longer passes.
The gate checks mirror integrity; it does not reconstruct SDK archive generation,
compile the SDK Rust bootstrap, evaluate arbitrary Make/environment policy or
protect against privileged concurrent replacement after its final observation.
The development source pin/hash are unchanged; source/release-cut qualification
remains separate. Python 3.11 or newer is required for the TOML parser.

25 actual temporary-Git/local-file methods pass on Linux as uid/gid65534,
including four old fail-open reproductions and FIFO/link refusal. The normal CI
command runs 24 methods and explicitly skips only the opt-in historical-baseline
method; the baseline-enabled lab run executes all 25. Related18 CI and15 router
release methods pass. These checksum fixtures are not newly SDK-generated release
archives, and no actual release or GitHub Actions run is claimed.

## SDK archive checks before prepare and compile (development 0.8.2)

The actual 24.10.4 SDK Git fallback can return0 and unpack source despite an
incorrect PKG_MIRROR_HASH. Normal download need not even emit the CHECK warning.
Qeli now calls its build-only verify-source.sh in Hooks/Prepare/Pre and again at
Build/Compile entry, before any Cargo call or manifest projection. Copy this file
alongside the package Makefile as shown above; it is never installed on a router.
Missing/empty/nonregular/linked archive, malformed/nonmatching hash and hash-tool
failure refuse the build. Explicit SDK developer source overlays still work and
are not mirror-qualified release builds. A privileged change after the check or
arbitrary Make overrides is outside this protection.

For a release, pin the desired immutable source, run download, run the SDK check
with FIXUP=1, then independently verify the Source archive/hash and use
QELI_OPENWRT_SOURCE_ARCHIVE for release preflight. The direct package equivalent
used in the audit is `make -C package/qeli TOPDIR=/absolute/sdk download CHECK=1
FIXUP=1 -j1`; it exercises the SDK check/fixup machinery without a host build.
Development source pin/hash remain unchanged until an actual release cut.

The actual SDK generated the same archive twice from a private fixture commit
whose qeli/ tree matches the current candidate exactly. Prepare rejects a bad hash
before unpacking; valid prepare preserves that tree. GNU make exports the real
Compile macro, and an inert Cargo seam proves zero calls on bad hash and two on
valid hash. Actual SDK-generated archive passes the source gate.9 shell methods
pass on both dash/ash without root;25 source methods pass. This closes source
archive/prepare admission within scope, not full Rust bootstrap, new client
compilation/package installation, GitHub Actions or firmware qualification.

## Maintainer 32-bit preflight helper qualification (development 0.8.2)

The live Gate2 helper now passes actual ARMv7/MIPS release builds from the current
committed qeli/ tree, with the pinned maintainer Zig/Rust policy, downloaded SHA256
and static ELF checks.32 actual QEMU CLI/INI inspection executions pass without
root on cortex-a7/24Kc. This complements the SDK1.89 compiler/package scope above;
these two builds use the maintainer Zig recipe, not SDK Rust bootstrap.

The entire preflight/Actions workflow and production release-cut pin/hash remain
separate. QEMU CLI inspection does not qualify router VPN, TUN, firewall or firmware.
Raw logs/artifacts are retained, temporary lab build/emulation roots cleaned;
no published artifacts or production source pin/hash were changed.

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
other SDK targets, production release pin/hash cut and a successful current Actions/
preflight are still unqualified. Production source pin/hash are unchanged. Use the
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


## Rust feed LLVM download failure (SDK24.10.4, 14 October 2026)

The pinned packages feed f1470815f41f uses Rust1.89.0 and
`--set=llvm.download-ci-llvm=true`. A real isolated Host/Compile attempt built
bootstrap successfully, then received HTTP404 for its pinned CI rust-dev artifact.
The Qeli client had not started compiling. Repeating the same download or changing
Qeli INI/DNS/firewall settings does not repair that dependency failure.

For a full source toolchain build, use a private SDK/feed copy and change only
`--set=llvm.download-ci-llvm=true` to `--set=llvm.download-ci-llvm=false` in
`feeds/packages/lang/rust/Makefile`, preserving the existing host/target flags and
source version/hash. Clean the Rust host package's own build state and reconfigure
before compiling; changing a generated bootstrap.toml alone may be overwritten by
Host/Configure. This selects bundled LLVM source compilation rather than the
unavailable CI binary. It requires additional build resources and a separately
validated Host/Compile/Host/Install and Qeli SDK package. The later qualified
Clang-host result below records that completed variant; preserve the pinned
source version/hash and explicit host/target configuration.

The already-qualified SDK/IPK run used a private official prebuilt Rust/std1.89.
That remains a package integration result, not proof of cold compiler bootstrap.
See [actual refusal and cleanup evidence](../docs/eng/reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

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

### Exact GNU-host Clang configuration for the qualified variant

This configuration describes the x86_64 GNU build host and x86_64 musl target
used in the qualified source-bootstrap campaign. Other build hosts, firmware
and target architectures require separate validation.

Use a private SDK/feed copy with the pinned Rust source version/hash. Set the
Rust feed's existing `llvm.download-ci-llvm` argument to `false`, then complete
Host/Prepare and Host/Configure. In the resolved `rustc-1.89.0-src` directory,
edit the existing generated `config.toml` or `bootstrap.toml`; do not create a
second configuration file. The recorded GNU-host executables are
`/usr/bin/clang` and `/usr/bin/clang++`, both Clang 19.

The following shows only the entries to add or change **inside the existing
sections**, not a replacement for the complete configuration:

```toml
[build]
jobs = 1

[target.x86_64-unknown-linux-gnu]
cc = "/usr/bin/clang"
cxx = "/usr/bin/clang++"
```

Preserve all other configuration fields, including the GNU build/host triples,
the target list and the entire `[target.x86_64-unknown-linux-musl]` section.
The musl target keeps its SDK `x86_64-openwrt-linux-musl-gcc` / `g++` and gcc
linker; the host Clang selection must not replace those target tools.
Host/Configure can regenerate the file, so inspect the effective configuration
again if it runs after these edits.

Verify actual LLVM CMake compiler IDs/paths, completed Host/Compile and
Host/Install, installed Rust/Cargo 1.89, and the installed musl standard library
before using the toolchain for the Qeli SDK package. A successful intermediate
compiler or `Dist` message alone does not establish the complete result.

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
