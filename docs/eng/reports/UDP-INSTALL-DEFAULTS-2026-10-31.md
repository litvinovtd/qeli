# UDP auto and Recordizer defaults: installation audit, 31 October 2026

Prepared for **0.8.4, not published**. This check does not replace any binary in
`release/dist`.

## Findings and fixes

The full `install-qeli-server.sh` already set UDP rmem/wmem max to 16777216,
sufficient for auto's largest 16 MiB request. The `.deb` and normal package
upgrade lacked that step. The package now includes:

- `/usr/lib/sysctl.d/60-qeli-udp-buffers.conf` with 16 MiB ceilings for boot;
- `/usr/lib/qeli/udp-buffer-limits`, invoked by `postinst configure` on both
  installation and upgrade. It raises only lower runtime ceilings and verifies
  readback; higher current values are retained;
- a `procps` dependency providing `sysctl`.

The full installer also retains higher rmem/wmem ceilings in its persistent
file and recovery receipt. Its dependency check also installs `procps` when
`sysctl` is missing, including separate-binary installations on minimal systems.
The package helper does not change socket defaults, qdisc, TUN or Qeli configuration.
Existing full-installer tuning remains.
Linux raw `SO_RCVBUF` normally doubles the request: a 16 MiB request does not
require a 32 MiB `rmem_max`.

Previously the sparse parser defaulted Recordizer to `off`, new profiles to
`prefer`, and batching to `timed`. The common default is now **`prefer` +
`opportunistic`** across Rust/serde/INI, the panel and 14 server profiles in five
shipped templates. Three client templates do not pin UDP receive or invent
client Recordizer keys: the server pushes the mode after AUTH.

Explicit `off`, `required`, `timed`, fixed buffers and `0` survive upgrades.
Omitted keys adopt the new parser defaults on a new session. `prefer` negotiates
PACKET_MUX_V1 with compatible clients, retaining legacy-client fallback.

## Checks

Build VM302 only; raw: `/opt/qeli-udp-install-defaults-20261031-r01`.

Result: **97 Python/chroot tests, 23 unique Rust unit tests and 11 actual CLI template
checks passed**: 10 defaults/helper/postinst, 18 binary-installer, 19 dependency
admission, 11 tuning/recovery, 21 updater, 17 real Makefile/dpkg lifecycle and
1 RU/EN defaults-table test. The Recordizer filter ran 23 Rust tests; its included
profile-default test was also repeated separately, not counted twice as unique.

- Actual helper/postinst in private chroots with mocked sysctl: initial install,
  repeated configure/upgrade, configuration preservation, higher limits, denied
  writes, successful commands with no effect and unreadable previous values.
- Lifecycle tests use real Makefile/dpkg with inert packages in chroots to check
  delivery of helper/sysctl.d, hook execution and state preservation. CLI,
  debconf/systemctl and sysctl are explicit seams, not a production-daemon boot.
- Full-installer regression checks preserve recovery receipts and confirm that
  existing 64 MiB ceilings are not lowered to 16 MiB.
- Source/docs guards cover templates, UDP auto and RU/EN default tables. The new
  test is included in Linux CI.

Two initial attempts stopped at the free-space gate **before Rust compilation**;
`result.json` and `result-r2.json` preserve those failures. Only this check's newly
created intermediate-cache copies were removed. The next check uses a read-only
lower cache and separate writable overlay in a private mount namespace; previous
candidates, sources, logs and results are not overwritten.

Release `config_examples` integration tests were not counted as PASS: their
`panic=unwind` test harness conflicted with `panic=abort` release dependencies.
The failure remains in `r3-examples-integration.log`; production panic policy was
not changed. That same invocation successfully built a native CLI, subsequently
used for `check-config` on five server and six client templates without running
VPN sessions. Private copies substitute documented test pins/short IDs and an
empty private users DB. Initial REALITY placeholder refusal is preserved in
`cli-check-result.json`; materialized checks are in `cli-check-result-r2.json`.

Native CLI SHA256: `1c31081e60caee767ec342421245c8e39ee7ef373d1a1a547dff9b465bd068de`,
15448408 bytes. This is a qualification tool, not a portable distribution or
qualification of both release architectures.

## Limits

An ordinary Linux installation obtains suitable ceilings without manually editing
client/server configuration **unless explicit overrides are present**. Administrator
sysctl.d files can override packaged defaults at boot; kernels/containers can deny
writes. These cases warn and require checking live socket readback rather than
assuming a requested size was granted.

Server RAM budgeting still applies; not every worker is promised 16 MiB.
Android/iOS and router firmware retain platform limits. No claim of eliminating
all UDP loss/CPU steal or changing throughput. VM300/301 and Proxmox were not
changed; no release publication.

See [UDP buffers](../manuals/UDP-BUFFERS.md) and [Recordizer](../reference/RECORDIZER.md).
