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
