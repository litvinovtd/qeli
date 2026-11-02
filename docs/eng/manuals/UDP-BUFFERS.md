# UDP buffer management and actual-size diagnostics

Qeli requests UDP socket memory itself. An OS limit is not the size of a live
socket: verify the result using `getsockopt`, logs and per-socket metadata.
This applies to UDP-FakeTLS, UDP-padding/AWG and QUIC. TCP retains its separate
autotuning policy and does not use the UDP controller.

## Configuration

Client: `[qeli]` in its INI. Server: the corresponding `[profile:name]`.
Values are bytes, not packets. There is no additional `auto` key.

| Setting | Client | Server |
|---|---|---|
| Receive | `recv_buffer_size` | `perf.udp.recv_buffer_size` |
| Send | `send_buffer_size` | `perf.udp.send_buffer_size` |

- Receive key **absent**: auto, initial request 4194304 (4 MiB), then bounded
  8/16 MiB rungs. Server startup/cap may be lower under the shared UDP-worker RAM budget.
- Explicit number, including `4194304`: fixed request, no automatic growth.
- Explicit `0`: preserve the OS value; neither auto nor a zero-length buffer.
- Maximum manual request: 67108864 (64 MiB) per socket. The server also checks
  aggregate memory accounting across all sockets.
- Send defaults to `0` (OS-managed); no automatic send-buffer growth.

Fixed client receive buffer:

```ini
[qeli]
# Keep the rest of your existing connection parameters.
recv_buffer_size = 8388608
send_buffer_size = 0
```

Server profile:

```ini
[profile:udp]
# Keep the rest of your existing profile parameters.
perf.udp.recv_buffer_size = 8388608
perf.udp.send_buffer_size = 0
```

To restore auto, remove the **receive line**, not replace it with `0`.
Restart the corresponding connection/listener. These are configuration fragments,
not complete runnable configurations.

## Automatic behavior and limits

About once per second the controller considers received wire traffic, local
socket drops and its own tick delay. Measured rate and a stall budget of at
least 50 ms determine demand; local overflow also permits the next rung.
Growth is capped and live buffers never shrink. Network sequence gaps alone
do not trigger memory growth.

The running Qeli UDP controller does **not** change `rmem_max`, `wmem_max`, VM
CPU/RAM, qdisc or TUN queues. Installer-managed system limits are a separate operation.
Requests are best-effort: the OS may refuse or grant less. On Linux inspect
`sysctl net.core.rmem_max net.core.wmem_max`. Raise limits separately and
deliberately, considering all sockets. The server plans a safe aggregate budget
within 12.5% of `MemAvailable`, not an unconditional 16 MiB per worker.

Bounded growth attempts are not retried indefinitely every second. After an OS
limit change, recreate the socket by reconnecting/restarting its listener for
reliable application. Larger buffers absorb brief stalls, not sustained overload
or hypervisor CPU steal.

## Linux/OpenWrt client automatic setup in dev

The 2 November 2026 change is in `dev` sources; an earlier 0.8.4 candidate needs a
rebuild/update to acquire it. All OpenWrt architectures and UDP-FakeTLS, QUIC
masking, padding/AWG and obfs use the shared controller.

With `recv_buffer_size` absent, the Linux client requests ordinary `SO_RCVBUF`
and checks the actual grant. If clipped, it tries per-socket `SO_RCVBUFFORCE`
and verifies readback again. This requires `CAP_NET_ADMIN`, normally held by
root on standard OpenWrt. Successful FORCE does not require a higher global
`rmem_max` and does not change sysctls. Failure keeps the connection working
with the actual grant; permission/unsupported failures are not retried every
second. After successful FORCE, growth uses FORCE so an ordinary request
cannot shrink the queue back to the host ceiling.

Automatic client sockets within one process share at most 12.5% of observed
`MemAvailable`. Reservations include Linux's doubled receive accounting and
the actual send buffer. Growth is reserved before the request; unknown readback
retains the conservative reservation. Low/unknown memory authorizes no increase
and does not shrink a live queue. The 16 MiB per-auto-socket cap remains; actual
requests can be lower. A network candidate retains its controller after COMMIT;
the previous controller retains its reservation until the old receiver drains.

Explicit fixed/`0`, sending, TCP and server socket policy keep their meaning.
FORCE is enabled for Linux auto clients, not Android/iOS/macOS/Windows builds.

## Android and other clients

| Platform | Can UDP reception be limited? | Applicability |
|---|---|---|
| OpenWrt/Keenetic/Linux with `CAP_NET_ADMIN` | Yes, including `rmem_max` | Auto clients use bounded FORCE |
| Linux without that capability | Yes | FORCE refusal preserves the connection and clipped-size diagnostics |
| Ordinary Android app | Yes: Linux socket caps and the same UDP controller | VPN permission does not grant `CAP_NET_ADMIN`; Android FORCE is disabled |
| Windows | Small receive queues remain possible; Linux `rmem_max` does not apply | Ordinary auto and SO_RCVBUF readback remain |
| macOS/iOS | Their own socket-memory limits may apply | Platform APIs/readback remain; Linux FORCE does not apply |

Android needs live `receive_normalized_bytes`, `receive_clamped` and socket
kernel-drop evidence. VPN permission and `protect(fd)` control routing, not
root privileges. See [Android VPN](https://developer.android.com/develop/connectivity/vpn),
[the application sandbox](https://source.android.com/docs/security/app-sandbox), and
[the kernel CAP_NET_ADMIN check](https://github.com/torvalds/linux/blob/v6.12/net/core/sock.c#L1277).
Similar symptoms do not establish the same cause on a phone.

An isolated Windows 10 probe obtained full 4/8/16 MiB grants with ordinary
SO_RCVBUF. That is one PC's socket-option check, not a throughput test or a
guarantee for other devices. [Winsock SO_RCVBUF](https://learn.microsoft.com/en-us/windows/win32/winsock/sol-socket-socket-options)
and [Apple socket-memory code](https://github.com/apple-oss-distributions/xnu/blob/main/bsd/kern/uipc_socket2.c)
describe their separate platform mechanisms.

## Linux installation and upgrade

[31 October installation/upgrade and Recordizer-default audit](../reports/UDP-INSTALL-DEFAULTS-2026-10-31.md).

[Actual .deb installation/upgrade and VM300/301 reboot](../reports/DEB-AUTO-REBOOT-2026-10-31.md):
auto 4→16 MiB and prefer/opportunistic confirmed before/after reboot; guests restored.

The full installer sets rmem/wmem max to 16 MiB. Since 0.8.4, the `.deb` also
ships `/usr/lib/sysctl.d/60-qeli-udp-buffers.conf`; `postinst configure` raises
only lower runtime ceilings to 16777216 on first install and every upgrade,
then verifies readback. Higher current ceilings are retained. The package does
not enlarge every socket default. Kernel/container refusal is a warning, not
a successful setup. Administrator rules in `/etc/sysctl.d` may override packaged
values after reboot.

Client and server use auto when receive keys are absent, with no manual tuning.
Explicit fixed/0 settings are not migrated; Recordizer is server-pushed, defaulting
to `prefer` + `opportunistic` in 0.8.4. Upgrades preserve existing config files.
This covers ordinary Linux `.deb`/full installations, not control over Android/iOS
or router firmware limits, which remain platform-managed.

## Size diagnostics

Socket creation/state changes log `UDP socket buffers: {…}` with:

| Field | Meaning |
|---|---|
| `mode` | `auto`, `fixed`, `os-default` |
| `requested_receive_bytes` / `requested_send_bytes` | Last Qeli request; `0` means no explicit setting |
| `auto_receive_cap_bytes` | Auto cap, or `0` for fixed/OS-default |
| `receive_os_bytes` / `send_os_bytes` | Actual OS-accounted `getsockopt` readback |
| `receive_normalized_bytes` / `send_normalized_bytes` | Linux/Android raw / 2; other OSes unchanged |
| `receive_clamped` / `send_clamped` | Normalized grant below the nonzero request |
| `socket_inode` | Linux/Android inode for matching `ss`, when available |
| `receive_set_method` | `standard`, `force`, or `os-default` |
| `receive_force_error` | Last FORCE errno, or `null` |
| `receive_budget_limited` | Growth was limited by the automatic-client memory budget |

**Failed readback is `null`, never the requested size.** Successful `setsockopt`
does not prove a full grant. Growth counts only an observed actual increase.
Clipping/readback failures warn; identical diagnostic state is not logged every tick.

Linux `ss skmem rb/tb` matches `*_os_bytes`. An explicit 4 MiB request usually
means `rb8388608`; this is kernel accounting, not guaranteed payload capacity.
OS-default mode also exposes raw and raw/2, but a zero request is not considered
clipped. Do not confuse a new iperf socket's raw `rmem_default` with Qeli's
normalized metric.

```bash
journalctl -u qeli --since '-10min' | grep 'UDP socket buffers:'
ss -uanmpe '( sport = :4443 or dport = :4443 )'
```

Replace the port with your profile's UDP port. Inspecting other users' PID/inode
may require root; no payload capture or keys are needed.

Detailed metadata is also available through:

- Linux CLI JSON: `stats.udp_socket_buffers` in the existing `QELI_CLIENT_STATUS`
  file. Its directory must be writable by the client user.
- Server: `udp_socket_buffers` by profile in the existing private Unix control
  socket `queue-stats` response. This is not a new public TCP API.
- No new mandatory GUI field. Existing aggregate FFI/JNI counters and ABI layout
  remain unchanged. `udp_recv_buffer_bytes` remains the sum of known normalized
  receive sizes across live sockets, not one worker's buffer size.

## Interpreting loss

Separate socket kernel drops, internal queue/pool drops, TUN drops and iperf
receiver loss. Even sufficient buffers can overflow during processing stalls.
Global UDP SNMP describes the whole guest/IP family, not one inode. Growing
memory does not prove an algorithm fix; zero on one layer does not prove zero
loss elsewhere.

See [configuration](CONFIG.md). Per-socket metadata complements, not replaces,
checks of CPU, loss and the receiver's actual buffer during speed measurements.

[VM300/301 acceptance, SHA and limitations](../reports/UDP-BUFFERS-READY-2026-10-31.md).
