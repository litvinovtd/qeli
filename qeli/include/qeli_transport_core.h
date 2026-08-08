#ifndef QELI_TRANSPORT_CORE_H
#define QELI_TRANSPORT_CORE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define QELI_CLIENT_ABI_VERSION UINT32_C(0x00010000)

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
    QELI_CLIENT_PLATFORM_REJECTED = -10
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
    QELI_CLIENT_ERROR = 3
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
    QELI_CORE_NETWORK_PLAN_ACK = UINT64_C(1) << 2
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

uint32_t qeli_client_abi_version(void);
uint64_t qeli_client_core_capabilities(void);

int32_t qeli_client_new(const uint8_t *config,
                        size_t config_len,
                        uint64_t platform_capabilities,
                        uint32_t event_capacity,
                        uint64_t *out_handle);
int32_t qeli_client_start(uint64_t handle);
int32_t qeli_client_stop(uint64_t handle);
int32_t qeli_client_network_plan_result(uint64_t handle,
                                        uint64_t generation,
                                        int32_t result_code,
                                        const uint8_t *reason,
                                        size_t reason_len);
/*
 * QELI_CLIENT_NETWORK_PLAN uses a UTF-8 JSON payload. ABI 1.0 fields:
 *   generation, tunnel_address, prefix_len, mtu, tunnel_gateway,
 *   routes: [{cidr, gateway, metric}],
 *   dns_servers: [{address, port}], full_tunnel, kill_switch.
 * A platform must apply or reject the complete generation before packet flow starts.
 */
int32_t qeli_client_poll_event(uint64_t handle,
                               qeli_client_event_t *out_event,
                               uint8_t *payload,
                               size_t payload_capacity,
                               size_t *out_payload_len);
int32_t qeli_client_state(uint64_t handle, uint32_t *out_state);
int32_t qeli_client_stats(uint64_t handle, qeli_client_stats_t *out_stats);
int32_t qeli_client_free(uint64_t handle);

#ifdef __cplusplus
}
#endif

#endif
