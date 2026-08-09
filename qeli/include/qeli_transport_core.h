#ifndef QELI_TRANSPORT_CORE_H
#define QELI_TRANSPORT_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QELI_CLIENT_ABI_VERSION UINT32_C(0x00010003)
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
    QELI_CLIENT_SOCKET_PROTECT = 4
};

enum qeli_client_payload_format {
    QELI_CLIENT_PAYLOAD_NONE = 0,
    QELI_CLIENT_PAYLOAD_JSON = 1,
    QELI_CLIENT_PAYLOAD_UTF8 = 2
};

enum qeli_client_platform_capability {
    QELI_PLATFORM_ROUTES = UINT64_C(1) << 0,
    QELI_PLATFORM_DNS = UINT64_C(1) << 1,
    QELI_PLATFORM_KILL_SWITCH = UINT64_C(1) << 2,
    QELI_PLATFORM_TUN_FD = UINT64_C(1) << 3,
    QELI_PLATFORM_TUN_PACKET_BATCH = UINT64_C(1) << 4,
    QELI_PLATFORM_SOCKET_PROTECT = UINT64_C(1) << 5
};

enum qeli_client_core_capability {
    QELI_CORE_STRICT_CONFIG = UINT64_C(1) << 0,
    QELI_CORE_LIFECYCLE_EVENTS = UINT64_C(1) << 1,
    QELI_CORE_NETWORK_PLAN_ACK = UINT64_C(1) << 2,
    QELI_CORE_TUN_FD_OWNERSHIP = UINT64_C(1) << 3,
    QELI_CORE_SOCKET_PROTECT_ACK = UINT64_C(1) << 4,
    QELI_CORE_DEVICE_ID_INPUT = UINT64_C(1) << 5
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
} qeli_client_stats_t;

#define QELI_CLIENT_STATS_V1_SIZE UINT32_C(64)
#define QELI_CLIENT_STATS_INIT                                                    \
    { (uint32_t)sizeof(qeli_client_stats_t), QELI_CLIENT_ABI_VERSION, 0, 0, 0, 0, 0, 0, 0, 0 }

#if defined(__cplusplus) && __cplusplus >= 201103L
static_assert(sizeof(qeli_client_event_t) == QELI_CLIENT_EVENT_V1_SIZE,
              "qeli_client_event_t ABI layout mismatch");
static_assert(sizeof(qeli_client_stats_t) == QELI_CLIENT_STATS_V1_SIZE,
              "qeli_client_stats_t ABI layout mismatch");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(sizeof(qeli_client_event_t) == QELI_CLIENT_EVENT_V1_SIZE,
               "qeli_client_event_t ABI layout mismatch");
_Static_assert(sizeof(qeli_client_stats_t) == QELI_CLIENT_STATS_V1_SIZE,
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
 * - calls on distinct handles may execute concurrently; calls sharing one handle are
 *   serialized by the core. A concurrent free is memory-safe, but an already in-flight
 *   call may finish after free returns, so adapters should quiesce their own workers first.
 */

uint32_t qeli_client_abi_version(void);
uint64_t qeli_client_core_capabilities(void);

int32_t qeli_client_new(const uint8_t *config,
                        size_t config_len,
                        uint64_t platform_capabilities,
                        uint32_t event_capacity,
                        uint64_t *out_handle);
int32_t qeli_client_start(uint64_t handle);
int32_t qeli_client_stop(uint64_t handle);
/*
 * ABI 1.3. Copy the platform's stable 16-byte, non-zero device id before start.
 * The core does not retain the caller's buffer and never generates a competing id.
 */
int32_t qeli_client_set_device_id(uint64_t handle,
                                  const uint8_t *device_id,
                                  size_t device_id_len);
/*
 * ABI 1.1. Duplicate and adopt `fd` for the pending network-plan generation.
 * The caller retains `fd`; the core owns a separate CLOEXEC duplicate and closes it on
 * replacement, stop or free. A positive network-plan ACK is rejected until this succeeds
 * whenever QELI_PLATFORM_TUN_FD was declared at qeli_client_new(). This call does not start
 * packet IO; it establishes ownership for the platform data-plane handoff.
 */
int32_t qeli_client_set_tun_fd(uint64_t handle, uint64_t generation, int32_t fd);
int32_t qeli_client_network_plan_result(uint64_t handle,
                                        uint64_t generation,
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
 * QELI_CLIENT_NETWORK_PLAN uses a UTF-8 JSON payload. ABI 1.0 fields:
 *   generation, tunnel_address, prefix_len, mtu, tunnel_gateway,
 *   routes: [{cidr, gateway, metric}],
 *   dns_servers: [{address, port}], full_tunnel, kill_switch.
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
