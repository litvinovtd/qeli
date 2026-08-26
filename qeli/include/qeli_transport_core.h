#ifndef QELI_TRANSPORT_CORE_H
#define QELI_TRANSPORT_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QELI_CLIENT_ABI_VERSION UINT32_C(0x0001000c)
#define QELI_CLIENT_ABI_MAJOR(version) ((uint32_t)(version) >> 16)
#define QELI_CLIENT_ABI_MINOR(version) ((uint32_t)(version) & UINT32_C(0xffff))
#define QELI_CLIENT_ABI_IS_COMPATIBLE(library_version)                            \
    (QELI_CLIENT_ABI_MAJOR(library_version) ==                                    \
         QELI_CLIENT_ABI_MAJOR(QELI_CLIENT_ABI_VERSION) &&                        \
     QELI_CLIENT_ABI_MINOR(library_version) >=                                    \
         QELI_CLIENT_ABI_MINOR(QELI_CLIENT_ABI_VERSION))

enum qeli_client_result {
    QELI_CLIENT_OK = 0,
    QELI_CLIENT_NO_EVENT = 1,
    QELI_CLIENT_INVALID_ARGUMENT = -1,
    QELI_CLIENT_INVALID_CONFIG = -2,
    QELI_CLIENT_INVALID_STATE = -3,
    QELI_CLIENT_STALE_PLAN = -4,
    QELI_CLIENT_EVENT_QUEUE_FULL = -5,
    QELI_CLIENT_BUFFER_TOO_SMALL = -6,
    QELI_CLIENT_INVALID_HANDLE = -7,
    QELI_CLIENT_PANIC = -8,
    QELI_CLIENT_UNSUPPORTED = -9,
    QELI_CLIENT_PLATFORM_REJECTED = -10,
    QELI_CLIENT_STALE_REQUEST = -11
};

enum qeli_client_state {
    QELI_CLIENT_CREATED = 0,
    QELI_CLIENT_CONNECTING = 1,
    QELI_CLIENT_AWAITING_NETWORK = 2,
    QELI_CLIENT_RUNNING = 3,
    QELI_CLIENT_STOPPING = 4,
    QELI_CLIENT_STOPPED = 5,
    QELI_CLIENT_FAILED = 6
};

enum qeli_client_event_kind {
    QELI_CLIENT_STATE_CHANGED = 1,
    QELI_CLIENT_NETWORK_PLAN = 2,
    QELI_CLIENT_ERROR = 3,
    QELI_CLIENT_SOCKET_PROTECT = 4,
    QELI_CLIENT_SERVER_IDENTITY = 5,
    QELI_CLIENT_PATH_COMMAND = 6
};

enum qeli_client_payload_format {
    QELI_CLIENT_PAYLOAD_NONE = 0,
    QELI_CLIENT_PAYLOAD_JSON = 1,
    QELI_CLIENT_PAYLOAD_UTF8 = 2
};

/* ABI 1.11 adds the dual-family platform capability contract. ABI 1.12 adds opt-in path
 * transactions and exact candidate socket binding. Unknown bits must be ignored; neither
 * roaming bit may be advertised before the platform implements atomic rollback. */
enum qeli_client_platform_capability {
    QELI_PLATFORM_ROUTES = UINT64_C(1) << 0,
    QELI_PLATFORM_DNS = UINT64_C(1) << 1,
    QELI_PLATFORM_KILL_SWITCH = UINT64_C(1) << 2,
    QELI_PLATFORM_TUN_FD = UINT64_C(1) << 3,
    QELI_PLATFORM_TUN_PACKET_BATCH = UINT64_C(1) << 4,
    QELI_PLATFORM_SOCKET_PROTECT = UINT64_C(1) << 5,
    QELI_PLATFORM_SERVER_IDENTITY = UINT64_C(1) << 6,
    QELI_PLATFORM_TUN_WINTUN = UINT64_C(1) << 7,
    QELI_PLATFORM_IPV6_TUN = UINT64_C(1) << 8,
    QELI_PLATFORM_IPV6_ROUTES = UINT64_C(1) << 9,
    QELI_PLATFORM_IPV6_DNS = UINT64_C(1) << 10,
    QELI_PLATFORM_IPV6_KILL_SWITCH = UINT64_C(1) << 11,
    QELI_PLATFORM_PATH_TRANSACTIONS = UINT64_C(1) << 12,
    QELI_PLATFORM_PATH_SOCKET_BINDING = UINT64_C(1) << 13
};

enum qeli_client_core_capability {
    QELI_CORE_STRICT_CONFIG = UINT64_C(1) << 0,
    QELI_CORE_LIFECYCLE_EVENTS = UINT64_C(1) << 1,
    QELI_CORE_NETWORK_PLAN_ACK = UINT64_C(1) << 2,
    QELI_CORE_TUN_FD_OWNERSHIP = UINT64_C(1) << 3,
    QELI_CORE_SOCKET_PROTECT_ACK = UINT64_C(1) << 4,
    QELI_CORE_DEVICE_ID_INPUT = UINT64_C(1) << 5,
    QELI_CORE_SERVER_IDENTITY_ACK = UINT64_C(1) << 6,
    QELI_CORE_HANDSHAKE_NETWORK_INPUT = UINT64_C(1) << 7,
    QELI_CORE_NATIVE_DATA_PLANE = UINT64_C(1) << 8,
    QELI_CORE_TUN_PACKET_IO = UINT64_C(1) << 9,
    QELI_CORE_UDP_DIAGNOSTIC = UINT64_C(1) << 10,
    QELI_CORE_WINTUN_IO = UINT64_C(1) << 11,
    QELI_CORE_NETWORK_PLAN_V2 = UINT64_C(1) << 12,
    QELI_CORE_PATH_TRANSACTIONS = UINT64_C(1) << 13
};

typedef struct qeli_client_event {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t kind;
    uint32_t state;
    uint32_t payload_format;
    uint32_t reserved;
    uint64_t sequence;
    uint64_t plan_generation;
    int32_t error_code;
    uint32_t payload_len;
} qeli_client_event_t;

#define QELI_CLIENT_EVENT_V1_SIZE UINT32_C(48)
#define QELI_CLIENT_EVENT_INIT                                                    \
    { (uint32_t)sizeof(qeli_client_event_t), QELI_CLIENT_ABI_VERSION, 0, 0, 0, 0, 0, 0, 0, 0 }

/*
 * ABI 1.10 appends UDP receive-path observability after the unchanged V1 prefix.
 * Drop/grow fields are cumulative for the handle; udp_recv_buffer_bytes is the latest
 * effective SO_RCVBUF value granted by the OS (not merely the requested value).
 * ABI 1.12 appends six roaming fields after the unchanged V2 prefix. Attempts, successes,
 * failures and reconnect fallbacks are cumulative; roam_candidates is a gauge and
 * last_roam_latency_ms is the latest successful transaction latency.
 */
typedef struct qeli_client_stats {
    uint32_t struct_size;
    uint32_t abi_version;
    uint32_t state;
    uint32_t reserved;
    uint64_t tx_packets;
    uint64_t tx_bytes;
    uint64_t rx_packets;
    uint64_t rx_bytes;
    uint64_t reconnects;
    uint64_t uptime_ms;
    uint64_t udp_kernel_drops;
    uint64_t udp_internal_drops;
    uint64_t udp_buffer_grows;
    uint64_t udp_recv_buffer_bytes;
    uint64_t roam_attempts;
    uint64_t roam_successes;
    uint64_t roam_failures;
    uint64_t roam_reconnect_fallbacks;
    uint64_t roam_candidates;
    uint64_t last_roam_latency_ms;
} qeli_client_stats_t;

#define QELI_CLIENT_STATS_V1_SIZE UINT32_C(64)
#define QELI_CLIENT_STATS_V2_SIZE UINT32_C(96)
#define QELI_CLIENT_STATS_V3_SIZE UINT32_C(144)
#define QELI_CLIENT_STATS_INIT                                                    \
    { (uint32_t)sizeof(qeli_client_stats_t), QELI_CLIENT_ABI_VERSION, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 }

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(qeli_client_event_t) == QELI_CLIENT_EVENT_V1_SIZE,
              "qeli_client_event_t ABI layout mismatch");
static_assert(sizeof(qeli_client_stats_t) == QELI_CLIENT_STATS_V3_SIZE,
              "qeli_client_stats_t ABI layout mismatch");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(qeli_client_event_t) == QELI_CLIENT_EVENT_V1_SIZE,
               "qeli_client_event_t ABI layout mismatch");
_Static_assert(sizeof(qeli_client_stats_t) == QELI_CLIENT_STATS_V3_SIZE,
               "qeli_client_stats_t ABI layout mismatch");
#endif

/*
 * ABI compatibility:
 * - the high 16 bits are the major version and must match this header;
 * - a library minor version must be at least the header minor version;
 * - unknown capability bits, event kinds and additive JSON fields must be tolerated.
 * Call qeli_client_abi_version() and QELI_CLIENT_ABI_IS_COMPATIBLE() before creating
 * a handle. Unknown negative result codes are failures, not success.
 *
 * Ownership and concurrency:
 * - input bytes are borrowed only for the duration of a call; parsed configuration and
 *   platform rejection reasons are copied by the core;
 * - event payloads and output structs remain caller-owned;
 * - calls on distinct handles may execute concurrently. Short control calls on one handle
 *   are serialized, but qeli_client_run deliberately releases that mutex while it blocks:
 *   another worker must poll/ACK events and may call stop/free. Exactly one run is allowed per
 *   handle. Concurrent free invalidates the public handle and cancels the leased runner without
 *   UAF; the runner may return after free, so adapters should still join their own worker.
 */

uint32_t qeli_client_abi_version(void);
uint64_t qeli_client_core_capabilities(void);

/*
 * ABI 1.8 handle-free UDP reachability diagnostic. The core parses the strict profile and
 * sends the same bounded fake-TLS/QUIC/obfs first flight as the live transport. `timeout_ms`
 * is per attempt and must be 100..5000. On success `out_latency_ms` is time to first reply.
 */
int32_t qeli_client_udp_probe(const uint8_t *config,
                              size_t config_len,
                              uint32_t timeout_ms,
                              uint64_t *out_latency_ms);

/* event_capacity is 2..256; zero selects the default. */
int32_t qeli_client_new(const uint8_t *config,
                        size_t config_len,
                        uint64_t platform_capabilities,
                        uint32_t event_capacity,
                        uint64_t *out_handle);
int32_t qeli_client_start(uint64_t handle);
/*
 * ABI 1.6. Run one complete Rust-owned transport generation. This call blocks and must
 * execute on a platform IO worker while another worker drains and acknowledges events.
 * `input` is bounded JSON. Optional `fallback_dns_servers` supplies platform DNS fallback;
 * optional `carrier_addresses` supplies ordered IPv4/IPv6 A/AAAA records resolved on the
 * physical network before/while the TUN is retained, avoiding resolver loops during reconnect.
 * Callers must require QELI_CORE_NATIVE_DATA_PLANE before invoking it.
 */
int32_t qeli_client_run(uint64_t handle, const uint8_t *input, size_t input_len);
/*
 * ABI 1.7 packet seam for iOS packetFlow and compatibility adapters. `lengths` partitions one
 * contiguous packet buffer. Push may accept only a prefix and returns NO_EVENT so the
 * caller can retry it; pull returns NO_EVENT when no downlink packet is queued.
 */
int32_t qeli_client_tun_push(uint64_t handle,
                             uint64_t generation,
                             const uint8_t *packets,
                             size_t packets_len,
                             const uint32_t *lengths,
                             size_t packet_count,
                             size_t *out_accepted);
int32_t qeli_client_tun_pull(uint64_t handle,
                             uint64_t generation,
                             uint8_t *packets,
                             size_t packets_capacity,
                             uint32_t *lengths,
                             size_t length_capacity,
                             size_t *out_packet_count,
                             size_t *out_bytes);
int32_t qeli_client_stop(uint64_t handle);
/*
 * ABI 1.3. Copy the platform's stable 16-byte, non-zero device id before start.
 * The core does not retain the caller's buffer and never generates a competing id.
 */
int32_t qeli_client_set_device_id(uint64_t handle,
                                  const uint8_t *device_id,
                                  size_t device_id_len);
/*
 * ABI 1.5. Publish authenticated network values from a legacy platform handshake.
 * `input` is bounded UTF-8 JSON with the complete `auth_ok` plaintext, the final
 * `effective_mtu`, and an optional `fallback_dns_servers` array. Rust re-parses the
 * untrusted server push, constructs QELI_CLIENT_NETWORK_PLAN, and writes its non-zero
 * generation to `out_generation`.
 */
int32_t qeli_client_publish_handshake_network(uint64_t handle,
                                              const uint8_t *input,
                                              size_t input_len,
                                              uint64_t *out_generation);
/*
 * ABI 1.1. Duplicate and adopt `fd` for the pending network-plan generation.
 * The caller retains `fd`; the core owns a separate CLOEXEC duplicate and closes it on
 * replacement, stop or free. A positive network-plan ACK is rejected until this succeeds
 * whenever QELI_PLATFORM_TUN_FD was declared at qeli_client_new(). This call does not start
 * packet IO; it establishes ownership for the platform data-plane handoff.
 */
int32_t qeli_client_set_tun_fd(uint64_t handle, uint64_t generation, int32_t fd);
/*
 * ABI 1.9. Attach the UTF-8 name of a platform-created Wintun adapter to the pending
 * generation. The platform retains its creator handle for interface lifetime and network
 * setup. After a positive ACK the core opens a separate adapter handle and owns the Wintun
 * session, wait event and both packet rings until the generation stops.
 */
int32_t qeli_client_set_wintun_adapter(uint64_t handle,
                                      uint64_t generation,
                                      const uint8_t *adapter_name,
                                      size_t adapter_name_len);
int32_t qeli_client_network_plan_result(uint64_t handle,
                                        uint64_t generation,
                                        int32_t result_code,
                                        const uint8_t *reason,
                                        size_t reason_len);
/*
 * ABI 1.12 experimental roaming control plane. `input` is bounded UTF-8 JSON:
 * {
 *   "generation": N, "update_id": N, "platform_path_id": "opaque",
 *   "reason": "network_changed" | "default_route_changed" | "wake" |
 *             "same_network_nat_failure" | "manual_probe",
 *   "network_token": "opaque", "interface_index": N,
 *   "local_addresses": ["literal IP"],
 *   "resolved_addresses": [{"address":"literal A/AAAA","ttl_secs":N}],
 *   "flags": {"default_route_changed":bool,"wake":bool,
 *             "same_network_nat_failure":bool}
 * }
 * Exactly one stable network token or non-zero interface index is sufficient. The generation
 * must equal the active NetworkPlan generation; update_id is monotonic and repeated values are
 * idempotent. On success out_candidate_id receives a non-zero transaction id.
 *
 * QELI_CLIENT_PATH_COMMAND carries JSON with generation, candidate_id, action, the validated
 * path object and optional socket_fd/reason. Actions are "prepare_path", "bind_socket",
 * "commit_path" and "abort_path". Every command must be acknowledged with all three
 * correlation values below. Rejecting PREPARE/BIND/COMMIT produces ABORT; rejecting ABORT is
 * a platform error requiring a full reconnect and increments the reconnect-fallback counter.
 * The adapter must tear down any temporary candidate state before reconnecting.
 *
 * The library advertises QELI_CORE_PATH_TRANSACTIONS only in an experimental-roaming build.
 * A handle must advertise both QELI_PLATFORM_PATH_TRANSACTIONS and
 * QELI_PLATFORM_PATH_SOCKET_BINDING. Stage 1 does not switch the current data plane.
 */
int32_t qeli_client_path_update(uint64_t handle,
                                const uint8_t *input,
                                size_t input_len,
                                uint64_t *out_candidate_id);
int32_t qeli_client_path_command_result(uint64_t handle,
                                        uint64_t generation,
                                        uint64_t candidate_id,
                                        uint64_t request_sequence,
                                        int32_t result_code,
                                        const uint8_t *reason,
                                        size_t reason_len);
/*
 * ABI 1.2. QELI_CLIENT_SOCKET_PROTECT carries {"fd": N} as UTF-8 JSON. The event
 * sequence is its one-shot request id. The core-owned socket remains open until the
 * platform synchronously protects that fd and reports success/failure here. Unknown,
 * repeated or cancelled request ids return QELI_CLIENT_STALE_REQUEST.
 */
int32_t qeli_client_socket_protect_result(uint64_t handle,
                                          uint64_t request_sequence,
                                          int32_t result_code,
                                          const uint8_t *reason,
                                          size_t reason_len);
/*
 * ABI 1.4. QELI_CLIENT_SERVER_IDENTITY carries
 * {"server_id":"host:port","public_key":"64 lowercase hex chars"} as UTF-8 JSON.
 * The handshake publishes it only after the peer proves possession of that key. The event
 * sequence is a one-shot request id for platform known-host/pinning policy; unknown,
 * repeated or cancelled ids return QELI_CLIENT_STALE_REQUEST.
 */
int32_t qeli_client_server_identity_result(uint64_t handle,
                                           uint64_t request_sequence,
                                           int32_t result_code,
                                           const uint8_t *reason,
                                           size_t reason_len);
/*
 * QELI_CLIENT_NETWORK_PLAN uses a UTF-8 JSON payload. ABI 1.0 fields:
 *   generation, tunnel_address, prefix_len, mtu, tunnel_gateway,
 *   routes: [{cidr, gateway, metric}],
 *   dns_servers: [{address, port}], full_tunnel, kill_switch.
 * ABI 1.6 additive fields: max_streams, adaptive.
 * ABI 1.8 additive fields: pushed_routes and data_plane (effective padding, heartbeat and
 * shaping facts for platform status UI; Rust already applies them).
 * ABI 1.11 additive fields:
 *   family_mode: "ipv4" | "dual" | "ipv6",
 *   addresses: [{family, address, prefix_len, on_link_prefix_len, gateway}],
 *   carrier_address,
 *   allow_ipv4_leak, allow_ipv6_leak,
 *   connection_log: [string].
 * `addresses` is the authoritative inner-address set. `tunnel_address`, `prefix_len` and
 * `tunnel_gateway` remain a legacy projection of its primary entry for older platforms;
 * an ABI 1.11 platform must apply every supported family in `addresses`, routes and DNS as
 * one generation. `carrier_address` is the already-resolved outer server address that must
 * remain outside a full tunnel. The leak flags are authenticated exceptions used only when
 * a full-tunnel plan omits that address family; false means the platform must capture or
 * block the missing family fail-closed.
 * A platform must apply or reject the complete generation before packet flow starts.
 * Unknown additive fields must be ignored; changing an existing field's meaning requires
 * a new ABI major version.
 */
/*
 * Initialise *out_event with QELI_CLIENT_EVENT_INIT before its first use. struct_size is
 * the caller's capacity and is preserved by the library, so the same object can be reused.
 * The library writes only the prefix understood by both sides and never writes past the
 * advertised size. A short v1 prefix returns QELI_CLIENT_INVALID_ARGUMENT without
 * consuming an event.
 */
int32_t qeli_client_poll_event(uint64_t handle,
                               qeli_client_event_t *out_event,
                               uint8_t *payload,
                               size_t payload_capacity,
                               size_t *out_payload_len);
int32_t qeli_client_state(uint64_t handle, uint32_t *out_state);
/* Initialise *out_stats with QELI_CLIENT_STATS_INIT before its first use. */
int32_t qeli_client_stats(uint64_t handle, qeli_client_stats_t *out_stats);
int32_t qeli_client_free(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif
