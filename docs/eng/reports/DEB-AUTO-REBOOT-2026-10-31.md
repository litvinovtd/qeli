# .deb installation, upgrade and reboot — 31 October 2026

**Acceptance passed.** Real package installation, upgrade from 0.8.3, reboot and
actual UDP buffers/Recordizer were checked on VM300/301. Original guest state
was restored and verified after another real reboot. No release publication
or replacement of `release/dist` artifacts.

## Package and lab

- VM302 build only: base `e3a430fd7ad0f9a2180bf9da7c4f91b728bcf26c` plus an
  isolated installation/default overlay, excluding neighboring unfinished
  application changes. Overlay hashes are in the evidence file.
- Official `make deb-portable ARCH=amd64`, **glibc 2.28**, **jemalloc**.
  Binary, CPU and package gates passed without bypasses.
- Package: 5071372 bytes, SHA256
  `3f6d9d6951c76148642fbab5c93b3c95c97f93e6674706ad4d40c6db59f1c4e2`.
- Embedded binary: 15300832 bytes, SHA256
  `dc16ba813a5b6124dabfc4f8a105e3d3b0386a8a7b86bcdbd03655f37790c80d`.
- Old 0.8.3 package matched its `SHA256SUMS`:
  `7afb2033fe3e0dba1f228b2c17b21574fc9eac3e4994e0fe635c8f4afe82291a`.
- VM300/server and VM301/client: **2 vCPU/2 GiB** each, kernel
  `6.12.111+deb13-amd64`. No build or command execution on Proxmox.

## Actual checks

Both guests initially had no installed Qeli package. The candidate was installed
with real dpkg on both. The server used the packaged `qeli.service`, running as
`qeli`, enabled for boot. The client used installed `/usr/bin/qeli client`,
explicitly started again after reboot: client-application autostart was not tested.

The first phase used shipped `server-ipv6.conf.example` with explicit
`prefer/opportunistic`. Only lab addressing, local DNS, authentication and
endpoint-only routing were adapted. NAT was disabled and IPv6 routing manual;
Internet forwarding/NAT were not qualified. No Qeli receive/send buffer keys
were added.

After reboot the checks were repeated. Then the actual 0.8.3 package was installed
and a config **without Recordizer keys or UDP buffer overrides** prepared.
VM300 upgraded through `update-qeli-server.sh` with local `QELI_DEB`; VM301 used
dpkg. Configurations, users DB and identity files retained SHA256. New defaults
were confirmed by real sessions after upgrade and another reboot.

| Case | Both guests' rmem/wmem max | Post-AUTH Recordizer | Active server RX | Client RX |
|---|---:|---|---:|---:|
| Fresh install | 16 MiB | prefer / opportunistic | 4→16 MiB | 4→16 MiB |
| Reboot after install | 16 MiB | prefer / opportunistic | 4→16 MiB | 4→16 MiB |
| Upgrade from 0.8.3 | 16 MiB | prefer / opportunistic | 4→16 MiB | 4→16 MiB |
| Reboot after upgrade | 16 MiB | prefer / opportunistic | 4→16 MiB | 4→16 MiB |

Actual normalized RX of 16 MiB matched raw `SO_RCVBUF`/`ss rb` **33554432** by
inode: `mode=auto`, cap 16777216, no OS clipping. Idle server workers may remain
at 4 MiB. System `rmem_default/wmem_default` stayed **212992**; the package did
not enlarge every socket default.

Every case passed inner IPv4/IPv6 ping, `PACKET_MUX_V1 active`,
`Recordizer batching: opportunistic` and
`plan.data_plane.recordizer_policy=prefer`. UDP-FakeTLS was tested; this is not
a new 12-profile benchmark.

## Growth acceptance, not a performance reference

Eight UDP windows, upload/download for each case, offered 800 Mbps, payload
1200, 8+1 warm-up seconds. Two controlled 200 ms Qeli-receiver pauses per window
exercise auto growth reproducibly. PID/exe were verified and resumed in finally.
Only iperf generator/receiver sockets explicitly requested 4 MiB.

These pauses intentionally create backlog/loss. Window throughput/loss is not
a release performance reference or evidence of eliminating all network loss.
Reboot can reset nonpersistent qdisc state; this is not a speed A/B across cases.

## Preserved harness failures

The first attempt stopped before traffic because the collector changed the TUN
address but retained old `dns.listen`; validation correctly refused it. The
fixture and early-SSH-disconnect reboot handling were corrected without changing
the binary. Initial `r01` raw and independent restoration verification remain.

After eight windows, cleanup checks found empty ACCEPT tables and a FQ-rate
restore-unit error: tc JSON uses bytes/s, the CLI uses bits/s. No windows were
rerun or overwritten. Original qdisc parameters/table absence were restored
using only iptables/ip6tables, never nft commands. Original collector FAIL and
separate final-restoration evidence are preserved.

## Restoration and evidence

The test package was removed; original files/permissions, accounts, debconf,
package inventory, sysctls, routes/rules, qdisc and firewall restored. Both guests
then rebooted: **all 18 check groups passed per guest**. No Qeli package,
processes or TUN remain; rmem/wmem max/default are again 212992. Previous raw
were not overwritten; metadata was compared, with additional SHA256 checks for
executables and `.deb` files. Boot IDs naturally changed and OS journals gained
test events; this is not a byte-for-byte live-OS rollback.

- VM302 build raw: `/opt/qeli-deb-auto-reboot-20261031-r01`.
- Both-guest main raw: `/opt/qeli-release-short-deb-auto-reboot-20261031-r02`.
- Initial failure: `/opt/qeli-release-short-deb-auto-reboot-20261031-r01`.
- Private `original-state.tar.gz` and `post-test-state.tar.gz` retained;
  configurations, account data and keys are not published.
- [Compact nonsecret evidence](../../ru/reports/deb_auto_reboot_2026-10-31.json).

Ordinary Linux `.deb` installation/upgrade needs no manual client/server buffer
settings unless explicit overrides exist. Administrator sysctl.d overrides and
container restrictions remain separate limits. This is amd64 package-behavior
acceptance, not full amd64+arm64 release qualification or publication approval.

See [UDP buffers](../manuals/UDP-BUFFERS.md), [Recordizer](../reference/RECORDIZER.md)
and [earlier isolated checks](UDP-INSTALL-DEFAULTS-2026-10-31.md).
