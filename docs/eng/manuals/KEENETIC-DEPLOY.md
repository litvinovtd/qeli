# qeli-client on Keenetic — step-by-step deployment

> **0.8.3, issue #205:** update the binary and init/lifecycle bundle together.
> Both ordinary and OpkgTun launchers pass the real `/var` target + `/lib/qeli`
> as `STATE_DIRECTORY`. The physical journal directory stays unchanged, with no
> `O_NOFOLLOW` bypass, unsafe chmod or hidden recovery state. Identity/TOFU remain
> in `/opt/etc/qeli`. [Storage and manual launch](OPERATIONS.md#client-physical-route-recovery).
> The firmware kernel must support `SO_NETNS_COOKIE`, including with `dns=off`;
> CPU architecture and a successful build do not qualify this requirement.

> **Benchmark scope:** any Reality speed or double-framing estimate in this document comes from
> the legacy carrier through 0.7.16. The current genuine H2 carrier needs a separate router benchmark.

Deploying the qeli VPN client on a Keenetic router (Entware) as a gateway for the whole
LAN. The architecture and rationale of the port — [KEENETIC-PORT.md](../reference/KEENETIC-PORT.md).
The bundle files — in `release/keenetic/`.

> **OpenWrt:** its native client shares this core. Fixes require updating the client
> binary; upgrading the server alone does not update the router.

> **0.8.2 scope:** physical Keenetic/OpenWrt tests were excluded from the agreed audit.
> Earlier hardware results do not qualify these new files. Source, target ELF, SDK
> export/prepare and isolated lifecycle checks retain the limits recorded in their
> reports. Verify interface names and firewall behaviour on your firmware.

---

## Prerequisites

- **Entware** is installed on the router (the `opkg` package manager, the `/opt`
  directory).
- **SSH** is enabled and you have shell access to the router.
- The **VPN** component is enabled in KeeneticOS (any of WireGuard/OpenVPN/IPsec) — it
  ensures `/dev/net/tun` is present. Added in the web UI: *Management → General settings →
  Change the component set*.
- There's a working **qeli server** with a profile and a client provisioned for the
  router.

---

## Step 0. Router reconnaissance (over SSH to the router)

```sh
opkg print-architecture | grep -E 'aarch64|mipsel|mips'   # the package arch
cat /proc/cpuinfo | grep -E 'cpu model|FPU|system type'   # CPU/FPU
ls -l /dev/net/tun                                         # must exist
df -h /opt                                                 # reserve for binary, dependencies, old and staged copies
```

- `mipsel-…` → the binary `qeli-client-mipsel` (MT7621/7628, etc.).
- `aarch64-…` → the binary `qeli-client-aarch64` (new ARM models).
- No `/dev/net/tun` → go back to the prerequisites and enable the VPN component.

---

## Step 1. Obtain the prepared distribution (on your workstation)

After publication choose an exact version on [GitHub Releases](https://github.com/litvinovtd/qeli/releases).
Download `qeli-keenetic-files.tar.gz`, the matching `qeli-client-keenetic-aarch64` or
`qeli-client-keenetic-mipsel`, and `SHA256SUMS` from that same release. The ELF occupies
8.93 MiB (aarch64) or 10.87 MiB (mipsel); also reserve space for dependencies, the
previous binary and a staged update.

For example, for aarch64 on a workstation with `sha256sum`:

```sh
grep -E ' [ *](qeli-keenetic-files[.]tar[.]gz|qeli-client-keenetic-aarch64)$' SHA256SUMS > selected.sha256
test "$(wc -l < selected.sha256)" -eq 2
sha256sum -c selected.sha256
tar -xzf qeli-keenetic-files.tar.gz
cp qeli-client-keenetic-aarch64 qeli-keenetic/
```

For mipsel replace the binary name in both the filter and `cp`. The archive contains
integration files and examples; place the ELF beside `install-keenetic.sh` inside
`qeli-keenetic/`. The separately downloadable installer does not replace the other files.

### Optional: maintainer source build

```sh
python scripts/build_keenetic.py --sync
# → release/keenetic/qeli-client-keenetic-aarch64   (static ARM aarch64)
# → release/keenetic/qeli-client-keenetic-mipsel    (static-pie MIPS32r2)
```

You can build only the needed arch: `python scripts/build_keenetic.py --sync mipsel`.

The helper is maintainer-internal and requires access to the private lab.
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
builds or firmware runtime. The shared policy selects Rust1.97.0, nightly-2026-06-10 for MIPS,
Zig0.13.0 and cargo-zigbuild0.23.0. Wrong versions fail; missing named Rust/target
components are installed without changing the default toolchain. The same policy
builds both helpers. Encoded/ambient RUSTFLAGS cannot override the recipe; MIPS
keeps its explicit soft-float linker argument. Compiler overrides are cleared and
Rust wrappers disabled for Qeli compilation. Global Cargo config, PATH, shared
cache/tool installations and local changes during upload still prevent a claim
of hermetic or reproducible builds. The SDK uses its own Rust feed policy. See [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).


---

## Step 2. Get the client credentials from the server (on the qeli server)

```sh
# Provision a client and get a qeli:// link right away (and the password — printed ONCE):
qeli add-client router1 --link --host <server_public_address>

# The server public key for pinning (anti-MITM):
qeli show-identity
```

From the link/output you'll need: `server` (host:port), `proto` (tcp/udp), `user`, `pass`,
`key` (the server pubkey), `mode` (fake-tls/obfs/plain/…), `sni`.

---

## Step 3. Copy the prepared directory to the router

```sh
scp -r qeli-keenetic <user>@<router-ip>:/opt/tmp/keenetic
# <user> — the router account with access to /opt (usually admin/root). An alternative is USB.
```

---

After a maintainer helper build, copy `release/keenetic` with its ELF instead of `qeli-keenetic`.

## Step 4. Installation (on the router)

```sh
cd /opt/tmp/keenetic
sh install-keenetic.sh
```

The script: detects the arch → places the right binary in `/opt/bin/qeli-client`; installs
`ip-full` and `iptables` (Keenetic's busybox `ip` is stripped — no `tuntap`); checks
`/dev/net/tun`; lays out `S99qeli` and a config stub.

Development0.8.2 installer consumes the canonical qeli-client-keenetic-aarch64/mipsel
artifacts; old qeli-client-aarch64/mipsel names remain a fallback. Required package
errors stop publication. Existing INI content is preserved and restricted to0600.
Copies are prepared first and each file is renamed atomically; the bundle is not
an atomic transaction. Correct an installation error and retry; no automatic VPN
restart occurs. Optional ip6tables failure requires checking IPv6 support.
[Q31 fixture evidence](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md) does not qualify real
opkg, ELF/ABI, power-loss or firmware runtime.

---

## Step 5. Fill in the config (on the router)

```sh
vi /opt/etc/qeli/client.conf
```

Substitute the values from Step 2.

In ordinary mode Qeli creates the TUN and an updated Linux client sets its queue
to `1000` packets. Optional `[qeli] tun.tx_queue_len = 1000` (`1..32767`, no auto)
belongs in `/opt/etc/qeli/client.conf`; stop/start the client itself after editing.
The installed binary must contain this development 0.8.2 change; Linux amd64
checks do not replace testing a new build on the actual router.
With OpkgTun/`dev_attach=true`, **omit the key**: `ndm` owns the queue and an
explicit value is rejected. [Full contract](CONFIG.md#client-tun-tx-queue).

For a gateway router, note `gateway` and `dns` in the example below:

```ini
[qeli]
server = vpn.example.com:443
proto  = tcp
user   = router1
pass   = <password>
# Pin the server's static key (anti-MITM). Empty / all-zero = TOFU.
key    = <server pubkey from show-identity>
# H-1 (since 0.7.1, ON by default): binds session keys to the server's static
# identity. REQUIRES a real key. With a TOFU key (zeros) set false; with a real
# key leave the default (you may drop the line). Safest: real key + bind_static=true.
bind_static = false
# Wire mode — must match the server. MIPS: fake-tls | obfs | plain (ChaCha20).
# reality-tls on mipsel is very slow (double AEAD) — ARM only.
mode   = fake-tls
# SNI for fake-tls (front domain). Not needed for obfs.
sni    = www.cloudflare.com
# ONLY for mode = reality-tls (short_id required since 0.7.1)
# reality_sid = <hex>

# ── Router / gateway ─────────────────────────────────────────────────────────
# full-tunnel: all LAN traffic into the tunnel (+ NAT in S99qeli)
gateway = true
# DON'T touch the router's resolver (the firmware owns it)
dns     = off
# kill_switch: leak-blocking via iptables (now works on Keenetic, which ships
# iptables). On a gateway the firewall is handled by S99qeli, so you can leave it off. Default off.
# kill_switch = false

[logging]
level = info
file  = /opt/var/log/qeli-client.log
# timestamp on each line: datetime (default) | rfc3339 | time | epoch | none.
# Here the log goes to its own file rather than syslog, so the timestamp is
# needed; rfc3339 is handy if you later correlate this log with the server's.
time_format = datetime
```

**H-1 / `bind_static` (important on 0.7.1):** by default the client binds the session
to the server's pinned static key. Two working router options:
- **Secure (recommended):** set a real `key` (from `qeli show-identity`) and leave
  `bind_static` at the default (on). The TOFU pin is stored in `QELI_KNOWN_HOSTS`
  (`S99qeli` points it at `/opt/etc/qeli/known_hosts` — survives reboot, unlike `/var`).
- **TOFU (simpler):** `key` = zeros and `bind_static = false` — trust on first use.

---

## Step 6. Check the interfaces for NAT (on the router)

```sh
ip a            # find the LAN bridge (usually br0) and confirm the tun will be vpn0
```

If the LAN bridge isn't `br0` or the tun isn't `vpn0` — fix the variables at the top of
`S99qeli`:

```sh
vi /opt/etc/init.d/S99qeli      # TUN=…, LAN_IF=…, GATEWAY=yes
```

---

## Step 7. Start

```sh
/opt/etc/init.d/S99qeli start
tail -f /opt/var/log/qeli-client.log
```

Wait for the line `Auth OK, assigned IP: 10.x.x.x` — that's a successful connection to the
server. Entware starts an init script with the `S` prefix **automatically when the router
boots**.

---

## Step 8. Check the tunnel

On the router:

```sh
ip a show vpn0                                  # the tun has an address 10.x.x.x
ip route | grep -E 'default|vpn0'               # with gateway=true — default via vpn0
iptables -t nat -L POSTROUTING -n | grep MASQUERADE   # NAT on vpn0 is set
curl -s https://ifconfig.me ; echo             # the external IP = the VPN server address
```

From any LAN client (a phone/PC behind the router):

```sh
# the external IP should become the VPN server address; DNS and sites open
curl -s https://ifconfig.me ; echo
```

---

## Selective mode (only part of the traffic via the VPN)

Instead of full-tunnel (`gateway=true`) you can route only the needed addresses:
`gateway = false` in the config + `ipset` + `iptables` + DNS overrides on the router's
dnsmasq (an approach like the `kvas` / `antizapret` projects for Keenetic). This is more
flexible and doesn't cut the speed on non-VPN traffic, but the setup is manual and outside
this bundle.

---

## Diagnostics

| Symptom | Cause / what to do |
|---|---|
| `no /dev/net/tun` at start | Enable the VPN component in KeeneticOS (prerequisites) |
| `ip: ... tuntap` doesn't work | `opkg install ip-full` (busybox `ip` is stripped) |
| No `Auth OK`, `SERVER KEY MISMATCH` | A wrong `key` — check against `qeli show-identity` on the server |
| No `Auth OK`, error about `bind_static`/all-zero TOFU | H-1 (0.7.1) is ON by default: set a real `key` OR `bind_static = false` for TOFU |
| No `Auth OK`, `auth failed` | Wrong `user`/`pass`, or `mode`/`sni` don't match the server profile |
| `kill-switch: iptables is not installed` | Ensure `iptables` is in PATH (Keenetic ships it); otherwise set `kill_switch = false` |
| LAN without internet, the router with internet | Check `ip_forward`, `MASQUERADE`, the correct `LAN_IF` name in `S99qeli` |
| After a reboot: "new device" / repeated TOFU | `QELI_DEVICE_ID_FILE` and `QELI_KNOWN_HOSTS` must be on `/opt` (in `S99qeli` they are; `/var` is tmpfs) |
| Very slow (mipsel) | The CPU ceiling without AES-NI; set `mode = obfs`/`plain`, not `reality-tls` |
| The tunnel breaks | Auto-reconnect is on; check `/opt/var/log/qeli-client.log` |

---

## Update / removal

```sh
# update the binary: stop, replace, start
/opt/etc/init.d/S99qeli stop
install -m755 qeli-client-<arch> /opt/bin/qeli-client
/opt/etc/init.d/S99qeli start

# remove completely
/opt/etc/init.d/S99qeli stop
rm -f /opt/etc/init.d/S99qeli /opt/bin/qeli-client
rm -rf /opt/etc/qeli /opt/var/log/qeli-client.log
```

## Legacy gateway recovery during template upgrades

Development0.8.2 templates use tagged qeli-keenetic-legacy firewall rules and a
version2 forwarding checkpoint with saved interfaces and touched families. Failed
cleanup retains the checkpoint and blocks start/restart. Correct the cause and
retry; recovery uses the saved interfaces even after template mode changes. The
legacy path requires the iptables comment extension. Actual router compatibility
is unqualified; the audit used isolated command/file models.

Before replacing an active legacy template, stop it with its previous script and
inspect the old rules and forwarding values. An old checkpoint without version2
requires manual ownership review and recovery; the new script preserves it and
refuses automatic cleanup. Keep its original values until recovery is verified.
Do not delete it to bypass the failure. Matching untagged administrator rules are
not automatically removed. See [Q31 evidence and remaining limits](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Process lifecycle and PID records

Development0.8.2 init templates store `PID start_ticks` in the0600 PID file and
check Linux proc start time/executable before signals. Old single-PID records and
unverified processes require manual identity review; they are not automatically
adopted. Stop with the previously installed template and verify the process/rules
before upgrading. The installer refuses existing PID or pending publication files.

Stop sends TERM and waits up to15 one-second polls before compatibility cleanup.
Timeout or signal failure retains the process record, plan and OpkgTun marker;
restart fails without starting another client. Correct the cause and retry. A
pending publication file requires ownership review, not deletion to bypass the gate.
There is no automatic KILL escalation. Status codes:0 running,3 stopped,4 unverified.
The wrapper delegates TUN lifetime to core/kernel/ndm, including persistent TUNs.
A successful start confirms a live executable, not authentication or connectivity.
Shell/proc checks do not provide atomic pidfd identity or serialize all operations.
Linux native-helper tests qualify the wrapper's order; actual router integration
is excluded. See [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).


## OpkgTun plan application receipt

The hook writes `/opt/var/run/qeli.opkgtun.applied` (0600) only after all ndm commands and save succeed. A changed plan, including MTU alone, or missing receipt forces reapplication. Connected/address matches alone cannot skip it. Publication/removal errors preserve `.apply-pending`; correct the cause and retry. Successful stop clears both records after client exit. This is a command receipt, not a lock or full readback: concurrent events, external setting changes and real firmware remain unqualified. See [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).


## Maintainer host verification

`python scripts/keenetic_verify.py` uses `QELI_LAB_PASS`, optional `QELI_LAB_SERVER` (default10.66.116.11) and `QELI_LAB_USER` (defaultroot). It builds in a new private `/var/tmp/qeli-keenetic-verify.*` directory with its own target, locked dependencies and one compiler job; services remain running. The printed directory is retained for inspection and should be removed after use. Exit0 means host build/tests/Clippy/graph/ELF/hash passed; exit1 means verification/connect/close failure; exit2 means credentials missing. Host success does not certify MIPS/ARM ABI or firmware. [Audit details](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).


## Gateway ownership through the core INI parser

The current binary supports:

```sh
qeli-client --config /opt/etc/qeli/client.conf --print-gateway-owner
```

It validates the same INI grammar as runtime and prints only `core` when
`gateway_nat`, `forward` or `exit_node` is enabled, otherwise `legacy`. It exits
without connecting, executing hooks or configuring networking. Both init templates
use this command once before gateway startup. Quoted/case/on/BOM values follow the
core parser; invalid configs or unsupported/invalid replies fail startup. With
`GATEWAY=no` or active OpkgTun, no legacy ownership query is needed.

Update standalone binary and template together; an old binary without the command
cannot start the compatibility gateway path. Core ownership suppresses wrapper
LAN NAT, including exit-node operation. Legacy ownership preserves the fallback
when core flags are absent/false. The init templates now inspect and launch from
one private copy described below. Use restart to admit edited INI. Actual router
firmware and concurrent generation handling remain unqualified. [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## Serialized lifecycle and upgrade (development0.8.2)

Install the complete bundle: the installer also publishes
/opt/etc/qeli/lifecycle.sh with0600 permissions. Both init variants and the OpkgTun
wan.d hook require this shared library; copying a new template alone is incomplete.
When upgrading an older deployment, stop/review the old client first, then replace
library, binary, init and any installed hook together.

Start/stop/restart, wan.d and installation share /var/run/qeli.lifecycle.lock.
A busy operation returns an error without competing mutations; retry after the
owner finishes. Restart holds one lock across stop and start. Hook events are not
queued. Normal exit/signals release it; after SIGKILL, verify that no init/hook/
installer owner remains before removing only the empty directory with rmdir.
Retain PID/plan/forwarding/pending recovery files. No automatic stale-lock deletion
or process killing is performed; router reboot normally clears volatile /var/run.

Hook checks plan/marker replacement before L3/save and before its applied receipt.
An observed change retains pending for retry; already completed ndm commands are
not rolled back. Core publication uses the separate plan publication lock described
below; the lifecycle lock itself is not used by the core. Matching core/hook builds
serialize file publication and application, while complete NDM atomicity and real
firmware ordering remain unqualified. Directory targets fail installation before dependencies.

Installation now keeps same-directory backups of the previous binary/init/helper
and a0600 /opt/etc/qeli/install-pending recovery record while publishing code.
Ordinary publication failures and a handled termination signal restore old bytes
and modes (or remove new code that was originally absent). A failed restore keeps
remaining backups and the marker. Installer retry, both updated init starts and
the updated active wan.d hook refuse it; stop remains available. Existing INI
contents are preserved. A newly published example and stricter600 config mode
may remain after a late error; package/dependency changes are not rolled back.

If install-pending remains, keep the client stopped and inspect the record and
remaining backups before any start or retry. Verify no init/hook/installer owns
the lifecycle action before repairing the complete compatible binary/init/helper
set. Empty backup fields mean the target was originally absent; a missing named
backup may already have been restored and does not authorize blind file deletion.
After verifying recovery, remove install-pending and, if SIGKILL left it, only the
empty lifecycle lock directory. Do not delete PID/plan/forwarding recovery records.
Older installed scripts may not honor this marker: manual stop/review remains
mandatory. No automatic SIGKILL/power-loss recovery or fsync-backed bundle
transaction is claimed. Symlink/nonregular publication targets and a linked
/opt/etc/qeli directory are rejected before package updates. Root/admin path
replacement during installation remains outside this cooperative protocol.

Before start/restart the updated template checks configuration through the binary's
shared parser: dev must match template TUN, and device_type must be tun. The normal
template requires dev_attach=false; active OpkgTun requires dev_attach=true and
dev matching OPKGTUN. Disable gateway_nat, forward and exit_node for OpkgTun because
ndm owns L3/gateway. GATEWAY=no does not bypass this check.

A mismatch rejects launch before process creation or old state changes. Align
INI and template, then retry start. Upgrade binary and template together: an older
binary does not understand --expect-router-device/--expect-router-attach and will
reject inspection. Inspection and launch now use the same private INI copy
described below.

## INI admitted before launch (development0.8.2)

Both init templates create `/opt/var/run/qeli-launch/client.conf` before inspection
and pass that same path to the core check and client. The original
`/opt/etc/qeli/client.conf` stays editable; replacing it after inspection cannot
change this launch. A repeated start of a running client retains its copy;
restart reads the updated original after successful stop. The hook variable
`QELI_CONFIG_PATH` points to the runtime copy. Edit the original file.

`stat -c`, `cp -p` and `mktemp` are required. The original INI must be a nonempty
regular file without a symlink, in a root-owned0700 directory. The installer checks
an existing directory's owner before package updates, then restricts its mode0700;
it does not transfer an unowned directory to root. The runtime directory must
also be root-owned0700; links, nonregular targets and unsafe modes reject startup.
File owner/mode survive copying, so the copy does not promote core command trust.
A bounded copy precedes the INI parser; the exact256KiB limit and grammar remain
owned by the core.

Successful stop removes the copy after verified client exit and network cleanup.
Failed join/cleanup retains it with recovery state. A prelaunch validation failure
may leave a private copy; the next admitted start replaces it. After SIGKILL/power
loss, review lifecycle ownership and temporary copies manually. Do not remove a
runtime copy while client ownership is active or uncertain. Direct binary launch
outside the templates does not use this protocol. Root/admin replacement of
private paths, core plan generation/ABA and real firmware remain unqualified.

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
Qeli cross build, Zig invocation, SDK Rust toolchain or router ABI/runtime. See [Q31](../reports/audit-0.8.2/AUDIT-Q31-OPENWRT-CONTROLS.md).

## NetworkPlan publication and NDM application

<!-- normative-sync: plan-publication-lock-v1 -->

On Linux, publication also acquires the sibling directory
`$QELI_TUNIP_FILE.publish-lock` with atomic `mkdir`. The matching Keenetic hook
holds the same lock from its final plan snapshot through NDM apply/save and receipt
publication. The client waits within the existing shared NetworkPlan budget
(maximum 15 seconds); a busy hook returns an error for a later event to retry.
The lock is separate from `/var/run/qeli.lifecycle.lock`: the hook creates the
attach device and waits for the first address without holding the publication lock.
It releases the lock before a later core publication can proceed; the core releases
it before any post-up hook. A newly published plan still needs a later wan.d event.

Update the binary, `lifecycle.sh` and hook together. Older binaries/hooks and
administrator writes do not participate. NDM commands remain sequential and may
partially succeed; pending/applied records retain address ownership for retry.
Normal return, Rust unwind and handled shell signals release the lock. SIGKILL or
power loss, including a standalone release panic with `panic=abort`, can leave a
directory: do not remove an active or unknown owner's lock.
After independently verifying that the client and hook have stopped, review the
saved/pending addresses, then remove only the empty stale publication directory
with `rmdir`. Never discard the plan or recovery receipts to bypass this check.
