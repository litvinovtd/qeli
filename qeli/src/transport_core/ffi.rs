//! Versioned C ABI for [`super::ClientCore`].
//!
//! Control events are copied into caller buffers. ABI 1.6 exposes one blocking
//! whole-generation runner; ABI 1.7 adds bounded caller-buffer packet batches for
//! platform TUN implementations that cannot yield a portable descriptor, and ABI 1.8
//! exposes the same UDP first-flight diagnostic to every native adapter. ABI 1.9 lets the
//! Windows core own the Wintun session and packet rings. ABI 1.10 appends UDP buffer/drop
//! telemetry while preserving the complete 64-byte stats V1 prefix.

use super::{
    core_capability, ClientCore, ClientEvent, CoreOptions, CoreStats, ErrorCode, EventKind,
    ABI_VERSION, DEFAULT_EVENT_CAPACITY,
};
use crate::protocol::realtls::registry::{Registry, RegistryAccessError};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::time::Duration;
use zeroize::Zeroize;

pub(crate) const OK: i32 = 0;
pub(crate) const NO_EVENT: i32 = 1;
const PAYLOAD_NONE: u32 = 0;
const PAYLOAD_JSON: u32 = 1;
const PAYLOAD_UTF8: u32 = 2;
pub(crate) const EVENT_V1_SIZE: usize = 48;
const STATS_V1_SIZE: usize = 64;
const STATS_V2_SIZE: usize = 96;

pub(crate) static CLIENTS: Registry<ClientCore> = Registry::new();

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QeliClientEvent {
    pub struct_size: u32,
    pub abi_version: u32,
    pub kind: u32,
    pub state: u32,
    pub payload_format: u32,
    pub reserved: u32,
    pub sequence: u64,
    pub plan_generation: u64,
    pub error_code: i32,
    pub payload_len: u32,
}

impl Default for QeliClientEvent {
    fn default() -> Self {
        Self {
            struct_size: std::mem::size_of::<Self>() as u32,
            abi_version: ABI_VERSION,
            kind: 0,
            state: 0,
            payload_format: PAYLOAD_NONE,
            reserved: 0,
            sequence: 0,
            plan_generation: 0,
            error_code: 0,
            payload_len: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct QeliClientStats {
    pub struct_size: u32,
    pub abi_version: u32,
    pub state: u32,
    pub reserved: u32,
    pub tx_packets: u64,
    pub tx_bytes: u64,
    pub rx_packets: u64,
    pub rx_bytes: u64,
    pub reconnects: u64,
    pub uptime_ms: u64,
    pub udp_kernel_drops: u64,
    pub udp_internal_drops: u64,
    pub udp_buffer_grows: u64,
    pub udp_recv_buffer_bytes: u64,
}

impl Default for QeliClientStats {
    fn default() -> Self {
        Self {
            struct_size: STATS_V2_SIZE as u32,
            abi_version: ABI_VERSION,
            state: 0,
            reserved: 0,
            tx_packets: 0,
            tx_bytes: 0,
            rx_packets: 0,
            rx_bytes: 0,
            reconnects: 0,
            uptime_ms: 0,
            udp_kernel_drops: 0,
            udp_internal_drops: 0,
            udp_buffer_grows: 0,
            udp_recv_buffer_bytes: 0,
        }
    }
}

#[no_mangle]
pub extern "C" fn qeli_client_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub extern "C" fn qeli_client_core_capabilities() -> u64 {
    core_capability::ALL
}

/// Run the shared UDP first-flight diagnostic without creating a tunnel handle.
///
/// The strict profile is parsed by Rust and the same fake-TLS/QUIC/obfs flight as the live
/// transport is sent. On success `out_latency_ms` receives time to the first reply.
///
/// # Safety
/// `config` must address `config_len` readable bytes and `out_latency_ms` must be writable.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_udp_probe(
    config: *const u8,
    config_len: usize,
    timeout_ms: u32,
    out_latency_ms: *mut u64,
) -> i32 {
    ffi_guard(|| {
        if out_latency_ms.is_null()
            || config.is_null()
            || config_len == 0
            || config_len > super::MAX_CONFIG_BYTES
            || !(super::diagnostic::MIN_PROBE_TIMEOUT_MS..=super::diagnostic::MAX_PROBE_TIMEOUT_MS)
                .contains(&timeout_ms)
        {
            return ErrorCode::InvalidArgument as i32;
        }
        unsafe { *out_latency_ms = 0 };
        let bytes = unsafe { std::slice::from_raw_parts(config, config_len) };
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return ErrorCode::InvalidConfig as i32,
        };
        let mut parsed = match super::parse_config(text) {
            Ok(config) if config.server.protocol == "udp" => config,
            Ok(mut config) => {
                wipe_config_secrets(&mut config);
                return ErrorCode::InvalidConfig as i32;
            }
            Err(_) => return ErrorCode::InvalidConfig as i32,
        };
        let host = parsed.server.address.clone();
        let result = super::diagnostic::udp_reachability(
            &parsed,
            &host,
            Duration::from_millis(timeout_ms as u64),
        );
        wipe_config_secrets(&mut parsed);
        match result {
            Ok(milliseconds) => {
                unsafe { *out_latency_ms = milliseconds };
                OK
            }
            Err(_) => ErrorCode::PlatformRejected as i32,
        }
    })
}

fn wipe_config_secrets(config: &mut crate::config::client::ClientConfig) {
    config.auth.password.zeroize();
    config.auth.password_command.zeroize();
    config.obfuscation.obfs_key.zeroize();
}

/// Create a client from strict flat INI or a `qeli://` link.
///
/// Returns zero on success and writes a non-zero generation-checked handle. A zero
/// `event_capacity` selects [`DEFAULT_EVENT_CAPACITY`].
///
/// # Safety
/// `config` must address `config_len` readable bytes and `out_handle` must be writable.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_new(
    config: *const u8,
    config_len: usize,
    platform_capabilities: u64,
    event_capacity: u32,
    out_handle: *mut u64,
) -> i32 {
    ffi_guard(|| {
        if out_handle.is_null() || (config.is_null() && config_len != 0) {
            return ErrorCode::InvalidArgument as i32;
        }
        unsafe { *out_handle = 0 };
        let bytes = if config_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(config, config_len) }
        };
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return ErrorCode::InvalidConfig as i32,
        };
        let event_capacity = if event_capacity == 0 {
            DEFAULT_EVENT_CAPACITY
        } else {
            event_capacity as usize
        };
        let core = match ClientCore::new(
            text,
            CoreOptions {
                platform_capabilities,
                event_capacity,
            },
        ) {
            Ok(core) => core,
            Err(error) => return error.code() as i32,
        };
        unsafe { *out_handle = CLIENTS.insert(core) };
        OK
    })
}

#[no_mangle]
pub extern "C" fn qeli_client_start(handle: u64) -> i32 {
    ffi_guard(|| with_core(handle, ClientCore::start))
}

#[no_mangle]
pub extern "C" fn qeli_client_stop(handle: u64) -> i32 {
    ffi_guard(|| with_core(handle, ClientCore::stop))
}

/// Copy the platform's stable device identity into the core before start.
///
/// # Safety
/// `device_id` must address exactly `device_id_len` readable bytes.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_set_device_id(
    handle: u64,
    device_id: *const u8,
    device_id_len: usize,
) -> i32 {
    ffi_guard(|| {
        if device_id.is_null() && device_id_len != 0 {
            return ErrorCode::InvalidArgument as i32;
        }
        let bytes = if device_id_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(device_id, device_id_len) }
        };
        with_core(handle, |core| core.set_device_id(bytes))
    })
}

/// Publish the canonical network plan derived from an authenticated platform handshake.
///
/// # Safety
/// `input` must address `input_len` readable UTF-8 bytes and `out_generation` must be
/// writable. The input is borrowed only for this call; the emitted plan owns its values.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_publish_handshake_network(
    handle: u64,
    input: *const u8,
    input_len: usize,
    out_generation: *mut u64,
) -> i32 {
    ffi_guard(|| {
        if out_generation.is_null() || (input.is_null() && input_len != 0) {
            return ErrorCode::InvalidArgument as i32;
        }
        unsafe { *out_generation = 0 };
        let bytes = if input_len == 0 {
            &[]
        } else {
            unsafe { std::slice::from_raw_parts(input, input_len) }
        };
        let text = match std::str::from_utf8(bytes) {
            Ok(text) => text,
            Err(_) => return ErrorCode::InvalidArgument as i32,
        };
        match CLIENTS.try_with(handle, |core| core.publish_handshake_network(text)) {
            Ok(Ok(generation)) => {
                unsafe { *out_generation = generation };
                OK
            }
            Ok(Err(error)) => error.code() as i32,
            Err(error) => registry_error_code(error),
        }
    })
}

/// Duplicate and adopt a platform TUN descriptor for the pending network-plan generation.
///
/// The caller keeps ownership of `fd` and may close it immediately after this call succeeds.
/// The core closes only its own CLOEXEC duplicate on replacement, stop or free. Packet IO is
/// not started by this control-plane call.
#[no_mangle]
pub extern "C" fn qeli_client_set_tun_fd(handle: u64, generation: u64, fd: i32) -> i32 {
    ffi_guard(|| with_core(handle, |core| core.attach_tun_fd(generation, fd)))
}

/// Attach a platform-created Wintun adapter name to the pending plan generation.
///
/// # Safety
/// `adapter_name` must address `adapter_name_len` readable UTF-8 bytes. The name is copied;
/// the caller retains its adapter handle, while the core opens and owns a separate handle and
/// session only after the platform acknowledges the complete network plan.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_set_wintun_adapter(
    handle: u64,
    generation: u64,
    adapter_name: *const u8,
    adapter_name_len: usize,
) -> i32 {
    ffi_guard(|| {
        let adapter_name = match unsafe { optional_utf8(adapter_name, adapter_name_len) } {
            Ok(Some(name)) => name,
            Ok(None) | Err(_) => return ErrorCode::InvalidArgument as i32,
        };
        with_core(handle, |core| {
            core.attach_wintun_adapter(generation, adapter_name)
        })
    })
}

/// Acknowledge or reject the pending system network plan.
///
/// `result_code == 0` means the platform successfully applied the complete plan. Any
/// non-zero value fails closed and records `reason` as an error event.
///
/// # Safety
/// A non-empty `reason` must address `reason_len` readable UTF-8 bytes.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_network_plan_result(
    handle: u64,
    generation: u64,
    result_code: i32,
    reason: *const u8,
    reason_len: usize,
) -> i32 {
    ffi_guard(|| {
        let reason = match unsafe { optional_utf8(reason, reason_len) } {
            Ok(reason) => reason,
            Err(code) => return code as i32,
        };
        match CLIENTS.try_with(handle, |core| {
            core.ack_network_plan(generation, result_code == 0, reason)
        }) {
            Ok(Ok(())) => OK,
            Ok(Err(error)) => error.code() as i32,
            Err(error) => registry_error_code(error),
        }
    })
}

/// Acknowledge or reject one `SocketProtect` request by its event sequence.
///
/// `result_code == 0` means the platform synchronously excluded the supplied socket fd from
/// VPN routing. The request producer keeps the descriptor open until this call completes.
/// A repeated, unknown or cancelled sequence returns `StaleRequest`.
///
/// # Safety
/// A non-empty `reason` must address `reason_len` readable UTF-8 bytes.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_socket_protect_result(
    handle: u64,
    request_sequence: u64,
    result_code: i32,
    reason: *const u8,
    reason_len: usize,
) -> i32 {
    ffi_guard(|| {
        let reason = match unsafe { optional_utf8(reason, reason_len) } {
            Ok(reason) => reason,
            Err(code) => return code as i32,
        };
        match CLIENTS.try_with(handle, |core| {
            core.ack_socket_protect(request_sequence, result_code == 0, reason)
        }) {
            Ok(Ok(())) => OK,
            Ok(Err(error)) => error.code() as i32,
            Err(error) => registry_error_code(error),
        }
    })
}

/// Acknowledge or reject one proven `ServerIdentity` request by its event sequence.
///
/// `result_code == 0` means the platform trust store matched an existing pin or persisted
/// the first-use key. The core emits this request only after the peer proved ownership of
/// the advertised key. A repeated, unknown or cancelled sequence returns `StaleRequest`.
///
/// # Safety
/// A non-empty `reason` must address `reason_len` readable UTF-8 bytes.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_server_identity_result(
    handle: u64,
    request_sequence: u64,
    result_code: i32,
    reason: *const u8,
    reason_len: usize,
) -> i32 {
    ffi_guard(|| {
        let reason = match unsafe { optional_utf8(reason, reason_len) } {
            Ok(reason) => reason,
            Err(code) => return code as i32,
        };
        match CLIENTS.try_with(handle, |core| {
            core.ack_server_identity(request_sequence, result_code == 0, reason)
        }) {
            Ok(Ok(())) => OK,
            Ok(Err(error)) => error.code() as i32,
            Err(error) => registry_error_code(error),
        }
    })
}

/// Pop one event, copying its optional payload to caller-owned memory.
///
/// Returns `1` when the queue is empty. If the payload buffer is too small, returns
/// `BufferTooSmall`, writes the required byte count, and leaves the event queued.
/// Network plans and platform requests use UTF-8 JSON; errors use plain UTF-8; state events
/// have no payload. Platform requests are correlated by `sequence`, not plan generation.
///
/// # Safety
/// Before every call, `out_event->struct_size` must contain the caller's allocated struct
/// size. The output pointer must provide at least the ABI 1.0 prefix. A non-empty payload
/// buffer must address `payload_capacity` writable bytes.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_poll_event(
    handle: u64,
    out_event: *mut QeliClientEvent,
    payload: *mut u8,
    payload_capacity: usize,
    out_payload_len: *mut usize,
) -> i32 {
    ffi_guard(|| {
        if out_event.is_null() || out_payload_len.is_null() {
            return ErrorCode::InvalidArgument as i32;
        }
        let caller_event_size = match unsafe { output_size(out_event, EVENT_V1_SIZE) } {
            Ok(size) => size,
            Err(code) => return code as i32,
        };
        unsafe { *out_payload_len = 0 };
        match CLIENTS.try_with(handle, |core| {
            let Some(event) = core.peek_event().cloned() else {
                return NO_EVENT;
            };
            let (payload_bytes, payload_format) = match event_payload(&event) {
                Ok(payload) => payload,
                Err(code) => return code as i32,
            };
            unsafe { *out_payload_len = payload_bytes.len() };
            let header = event_header(&event, payload_format, payload_bytes.len());
            unsafe { write_output(out_event, &header, caller_event_size) };
            if payload_bytes.len() > payload_capacity {
                return ErrorCode::BufferTooSmall as i32;
            }
            if !payload_bytes.is_empty() {
                if payload.is_null() {
                    return ErrorCode::InvalidArgument as i32;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        payload_bytes.as_ptr(),
                        payload,
                        payload_bytes.len(),
                    )
                };
            }
            let popped = core.poll_event();
            debug_assert_eq!(
                popped.as_ref().map(|item| item.sequence),
                Some(event.sequence)
            );
            OK
        }) {
            Ok(code) => code,
            Err(error) => registry_error_code(error),
        }
    })
}

/// # Safety
/// `out_state` must be writable.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_state(handle: u64, out_state: *mut u32) -> i32 {
    ffi_guard(|| {
        if out_state.is_null() {
            return ErrorCode::InvalidArgument as i32;
        }
        match CLIENTS.try_with(handle, |core| core.state() as u32) {
            Ok(state) => {
                unsafe { *out_state = state };
                OK
            }
            Err(error) => registry_error_code(error),
        }
    })
}

/// # Safety
/// `out_stats` must be writable and its `struct_size` field must contain the caller's
/// allocated struct size. The output must provide at least the ABI 1.0 prefix.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_stats(handle: u64, out_stats: *mut QeliClientStats) -> i32 {
    ffi_guard(|| {
        if out_stats.is_null() {
            return ErrorCode::InvalidArgument as i32;
        }
        let caller_stats_size = match unsafe { output_size(out_stats, STATS_V1_SIZE) } {
            Ok(size) => size,
            Err(code) => return code as i32,
        };
        match CLIENTS.try_with(handle, |core| core.stats()) {
            Ok(stats) => {
                let output = ffi_stats(stats);
                unsafe { write_output(out_stats, &output, caller_stats_size) };
                OK
            }
            Err(error) => registry_error_code(error),
        }
    })
}

#[no_mangle]
pub extern "C" fn qeli_client_free(handle: u64) -> i32 {
    ffi_guard(|| {
        // Wake a leased blocking runner before invalidating the public handle. The runner's
        // generation-checked Arc keeps memory alive only until it observes cancellation.
        let _ = CLIENTS.try_with(handle, |core| {
            core.runtime_cancel
                .store(true, std::sync::atomic::Ordering::Release);
        });
        if CLIENTS.remove(handle) {
            OK
        } else {
            ErrorCode::InvalidHandle as i32
        }
    })
}

/// Run one complete native transport generation. This call blocks until cancellation or
/// disconnect and must therefore be made on a platform IO worker, never the UI thread.
///
/// # Safety
/// `input` must reference `input_len` readable UTF-8 bytes for the duration of this call.
#[cfg(any(
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
))]
#[no_mangle]
pub unsafe extern "C" fn qeli_client_run(handle: u64, input: *const u8, input_len: usize) -> i32 {
    ffi_guard(|| {
        if input_len > 16 * 1024 || (input_len > 0 && input.is_null()) {
            return ErrorCode::InvalidArgument as i32;
        }
        let text = if input_len == 0 {
            "{}"
        } else {
            let bytes = unsafe { std::slice::from_raw_parts(input, input_len) };
            match std::str::from_utf8(bytes) {
                Ok(text) => text,
                Err(_) => return ErrorCode::InvalidArgument as i32,
            }
        };
        let runtime_input = match serde_json::from_str(text) {
            Ok(input) => input,
            Err(_) => return ErrorCode::InvalidArgument as i32,
        };
        let lease = match CLIENTS.acquire(handle) {
            Ok(lease) => lease,
            Err(error) => return registry_error_code(error),
        };
        match super::runtime::run(lease, runtime_input) {
            Ok(()) => OK,
            Err(_) => ErrorCode::PlatformRejected as i32,
        }
    })
}

#[cfg(not(any(
    target_os = "android",
    target_os = "windows",
    target_os = "macos",
    target_os = "ios"
)))]
#[no_mangle]
/// Unsupported-target ABI stub; shipped Android/Windows/macOS/iOS cores execute the runner.
///
/// # Safety
/// The stub never dereferences `_input`; callers must still use the public header contract so
/// the same call remains valid when native execution is enabled on another target.
pub unsafe extern "C" fn qeli_client_run(
    _handle: u64,
    _input: *const u8,
    _input_len: usize,
) -> i32 {
    ErrorCode::Unsupported as i32
}

/// Push a contiguous batch of platform TUN packets into the native transport.
///
/// `lengths[0..packet_count]` partitions `packets[0..packets_len]`. A bounded pool may
/// accept only a prefix; that count is returned in `out_accepted` and `NO_EVENT` tells the
/// adapter to retry the remaining packets without dropping them.
///
/// # Safety
/// Every non-empty pointer must address the corresponding readable/writable element count.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_tun_push(
    handle: u64,
    generation: u64,
    packets: *const u8,
    packets_len: usize,
    lengths: *const u32,
    packet_count: usize,
    out_accepted: *mut usize,
) -> i32 {
    ffi_guard(|| {
        if out_accepted.is_null()
            || packet_count == 0
            || packet_count > super::packet_tun::MAX_BATCH_PACKETS
            || lengths.is_null()
            || packets.is_null()
        {
            return ErrorCode::InvalidArgument as i32;
        }
        unsafe { *out_accepted = 0 };
        let packet_bytes = unsafe { std::slice::from_raw_parts(packets, packets_len) };
        let packet_lengths = unsafe { std::slice::from_raw_parts(lengths, packet_count) };
        let bridge = match CLIENTS.try_with(handle, |core| core.packet_tun_bridge(generation)) {
            Ok(Ok(bridge)) => bridge,
            Ok(Err(error)) => return error.code() as i32,
            Err(error) => return registry_error_code(error),
        };
        match bridge.push_batch(packet_bytes, packet_lengths) {
            Ok(accepted) => {
                unsafe { *out_accepted = accepted };
                if accepted == packet_count {
                    OK
                } else {
                    NO_EVENT
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                ErrorCode::InvalidArgument as i32
            }
            Err(_) => ErrorCode::InvalidState as i32,
        }
    })
}

/// Pull a contiguous batch of native downlink packets into platform-owned storage.
///
/// The caller supplies at least one packet-sized byte buffer and `length_capacity` slots.
/// On success `out_packet_count` lengths partition the first `out_bytes` output bytes.
/// `NO_EVENT` means the bounded downlink queue is currently empty.
///
/// # Safety
/// Output pointers must be writable for their advertised capacities.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_tun_pull(
    handle: u64,
    generation: u64,
    packets: *mut u8,
    packets_capacity: usize,
    lengths: *mut u32,
    length_capacity: usize,
    out_packet_count: *mut usize,
    out_bytes: *mut usize,
) -> i32 {
    ffi_guard(|| {
        if packets.is_null()
            || packets_capacity < super::packet_tun::MAX_PACKET_BYTES
            || lengths.is_null()
            || length_capacity == 0
            || length_capacity > super::packet_tun::MAX_BATCH_PACKETS
            || out_packet_count.is_null()
            || out_bytes.is_null()
        {
            return ErrorCode::InvalidArgument as i32;
        }
        unsafe {
            *out_packet_count = 0;
            *out_bytes = 0;
        }
        let packet_bytes = unsafe { std::slice::from_raw_parts_mut(packets, packets_capacity) };
        let packet_lengths = unsafe { std::slice::from_raw_parts_mut(lengths, length_capacity) };
        let bridge = match CLIENTS.try_with(handle, |core| core.packet_tun_bridge(generation)) {
            Ok(Ok(bridge)) => bridge,
            Ok(Err(error)) => return error.code() as i32,
            Err(error) => return registry_error_code(error),
        };
        match bridge.pull_batch(packet_bytes, packet_lengths) {
            Ok((count, bytes)) => {
                unsafe {
                    *out_packet_count = count;
                    *out_bytes = bytes;
                }
                if count == 0 {
                    NO_EVENT
                } else {
                    OK
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                ErrorCode::InvalidArgument as i32
            }
            Err(_) => ErrorCode::InvalidState as i32,
        }
    })
}

fn with_core(
    handle: u64,
    operation: impl FnOnce(&mut ClientCore) -> Result<(), super::CoreError>,
) -> i32 {
    match CLIENTS.try_with(handle, operation) {
        Ok(Ok(())) => OK,
        Ok(Err(error)) => error.code() as i32,
        Err(error) => registry_error_code(error),
    }
}

fn registry_error_code(error: RegistryAccessError) -> i32 {
    match error {
        RegistryAccessError::InvalidHandle => ErrorCode::InvalidHandle as i32,
        RegistryAccessError::Panicked => ErrorCode::Panic as i32,
    }
}

/// Read the first, caller-initialised `struct_size` field without assuming alignment.
/// The caller still owns the usual C responsibility to provide the number of writable bytes
/// it advertises. The stable v1 prefix remains the minimum even when Rust later appends fields.
unsafe fn output_size<T>(output: *mut T, minimum: usize) -> Result<usize, ErrorCode> {
    let size = unsafe { std::ptr::read_unaligned(output.cast::<u32>()) } as usize;
    if size < minimum {
        Err(ErrorCode::InvalidArgument)
    } else {
        Ok(size)
    }
}

/// Copy only the prefix understood by both sides. A future library can append fields while
/// continuing to serve a caller compiled against ABI 1.0 without overrunning its struct.
unsafe fn write_output<T>(output: *mut T, value: &T, caller_size: usize) {
    let bytes = caller_size.min(std::mem::size_of::<T>());
    unsafe {
        std::ptr::copy_nonoverlapping(
            std::ptr::from_ref(value).cast::<u8>(),
            output.cast::<u8>(),
            bytes,
        );
        // `struct_size` is the caller's reusable capacity marker, not the size of the
        // current library's private Rust type. Preserve it across successive polls.
        std::ptr::write_unaligned(output.cast::<u32>(), caller_size as u32);
    };
}

fn event_payload(event: &ClientEvent) -> Result<(Vec<u8>, u32), ErrorCode> {
    match event.kind {
        EventKind::StateChanged => Ok((Vec::new(), PAYLOAD_NONE)),
        EventKind::NetworkPlan => event
            .plan
            .as_ref()
            .ok_or(ErrorCode::Panic)
            .and_then(|plan| {
                serde_json::to_vec(plan)
                    .map(|payload| (payload, PAYLOAD_JSON))
                    .map_err(|_| ErrorCode::Panic)
            }),
        EventKind::Error => event
            .fault
            .as_ref()
            .map(|fault| (fault.message.as_bytes().to_vec(), PAYLOAD_UTF8))
            .ok_or(ErrorCode::Panic),
        EventKind::SocketProtect => event
            .socket_protect
            .as_ref()
            .ok_or(ErrorCode::Panic)
            .and_then(|request| {
                serde_json::to_vec(request)
                    .map(|payload| (payload, PAYLOAD_JSON))
                    .map_err(|_| ErrorCode::Panic)
            }),
        EventKind::ServerIdentity => event
            .server_identity
            .as_ref()
            .ok_or(ErrorCode::Panic)
            .and_then(|request| {
                serde_json::to_vec(request)
                    .map(|payload| (payload, PAYLOAD_JSON))
                    .map_err(|_| ErrorCode::Panic)
            }),
    }
}

fn event_header(event: &ClientEvent, payload_format: u32, payload_len: usize) -> QeliClientEvent {
    QeliClientEvent {
        struct_size: std::mem::size_of::<QeliClientEvent>() as u32,
        abi_version: ABI_VERSION,
        kind: event.kind as u32,
        state: event.state as u32,
        payload_format,
        reserved: 0,
        sequence: event.sequence,
        plan_generation: event.plan.as_ref().map_or(0, |plan| plan.generation),
        error_code: event.fault.as_ref().map_or(0, |fault| fault.code as i32),
        payload_len: payload_len.min(u32::MAX as usize) as u32,
    }
}

fn ffi_stats(stats: CoreStats) -> QeliClientStats {
    QeliClientStats {
        struct_size: std::mem::size_of::<QeliClientStats>() as u32,
        abi_version: ABI_VERSION,
        state: stats.state as u32,
        reserved: 0,
        tx_packets: stats.tx_packets,
        tx_bytes: stats.tx_bytes,
        rx_packets: stats.rx_packets,
        rx_bytes: stats.rx_bytes,
        reconnects: stats.reconnects,
        uptime_ms: stats.uptime_ms,
        udp_kernel_drops: stats.udp_kernel_drops,
        udp_internal_drops: stats.udp_internal_drops,
        udp_buffer_grows: stats.udp_buffer_grows,
        udp_recv_buffer_bytes: stats.udp_recv_buffer_bytes,
    }
}

unsafe fn optional_utf8<'a>(ptr: *const u8, len: usize) -> Result<Option<&'a str>, ErrorCode> {
    if len == 0 {
        return Ok(None);
    }
    if ptr.is_null() {
        return Err(ErrorCode::InvalidArgument);
    }
    std::str::from_utf8(unsafe { std::slice::from_raw_parts(ptr, len) })
        .map(Some)
        .map_err(|_| ErrorCode::InvalidArgument)
}

fn ffi_guard(operation: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or(ErrorCode::Panic as i32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport_core::{platform_capability, NetworkDns, NetworkPlan, NetworkRoute};

    const CONFIG: &str = "[qeli]\nserver = 127.0.0.1:443\nproto = tcp\nuser = test\npass = secret\nkey = 1111111111111111111111111111111111111111111111111111111111111111\nmode = fake-tls\n";

    unsafe fn new_handle() -> u64 {
        let mut handle = 0;
        let rc = unsafe {
            qeli_client_new(
                CONFIG.as_ptr(),
                CONFIG.len(),
                platform_capability::SYSTEM_PLAN,
                0,
                &mut handle,
            )
        };
        assert_eq!(rc, OK);
        assert_ne!(handle, 0);
        handle
    }

    #[test]
    fn abi_reports_version_and_capabilities() {
        assert_eq!(qeli_client_abi_version(), ABI_VERSION);
        assert_eq!(qeli_client_core_capabilities(), core_capability::ALL);
        assert_eq!(std::mem::size_of::<QeliClientEvent>(), 48);
        assert_eq!(std::mem::size_of::<QeliClientStats>(), 96);
        assert_eq!(std::mem::size_of::<QeliClientEvent>(), EVENT_V1_SIZE);
        assert_eq!(std::mem::size_of::<QeliClientStats>(), STATS_V2_SIZE);

        let header = include_str!("../../include/qeli_transport_core.h");
        assert!(header.contains("QELI_CLIENT_ABI_VERSION UINT32_C(0x0001000a)"));
        assert!(header.contains("QELI_CLIENT_ABI_IS_COMPATIBLE"));
        assert!(header.contains("QELI_CLIENT_PLATFORM_REJECTED = -10"));
        assert!(header.contains("QELI_CLIENT_EVENT_V1_SIZE UINT32_C(48)"));
        assert!(header.contains("QELI_CLIENT_STATS_V1_SIZE UINT32_C(64)"));
        assert!(header.contains("QELI_CLIENT_STATS_V2_SIZE UINT32_C(96)"));
        assert!(header.contains("qeli_client_network_plan_result"));
        assert!(header.contains("qeli_client_set_tun_fd"));
        assert!(header.contains("qeli_client_set_wintun_adapter"));
        assert!(header.contains("QELI_PLATFORM_TUN_WINTUN"));
        assert!(header.contains("QELI_CORE_WINTUN_IO"));
        assert!(header.contains("QELI_CORE_SOCKET_PROTECT_ACK"));
        assert!(header.contains("QELI_CLIENT_SOCKET_PROTECT = 4"));
        assert!(header.contains("QELI_CLIENT_STALE_REQUEST = -11"));
        assert!(header.contains("qeli_client_socket_protect_result"));
        assert!(header.contains("QELI_CORE_DEVICE_ID_INPUT"));
        assert!(header.contains("qeli_client_set_device_id"));
        assert!(header.contains("QELI_CLIENT_SERVER_IDENTITY = 5"));
        assert!(header.contains("QELI_CORE_SERVER_IDENTITY_ACK"));
        assert!(header.contains("QELI_CORE_HANDSHAKE_NETWORK_INPUT"));
        assert!(header.contains("qeli_client_publish_handshake_network"));
        assert!(header.contains("qeli_client_server_identity_result"));
        assert!(header.contains("QELI_CORE_TUN_PACKET_IO"));
        assert!(header.contains("QELI_PLATFORM_TUN_PACKET_BATCH"));
        assert!(header.contains("qeli_client_tun_push"));
        assert!(header.contains("qeli_client_tun_pull"));
        assert!(header.contains("QELI_CORE_UDP_DIAGNOSTIC"));
        assert!(header.contains("qeli_client_udp_probe"));
    }

    #[test]
    fn udp_probe_abi_rejects_wrong_protocol_and_invalid_outputs() {
        let mut latency = 99;
        assert_eq!(
            unsafe { qeli_client_udp_probe(CONFIG.as_ptr(), CONFIG.len(), 1_000, &mut latency) },
            ErrorCode::InvalidConfig as i32
        );
        assert_eq!(latency, 0);
        assert_eq!(
            unsafe { qeli_client_udp_probe(CONFIG.as_ptr(), CONFIG.len(), 99, &mut latency) },
            ErrorCode::InvalidArgument as i32
        );
        assert_eq!(
            unsafe {
                qeli_client_udp_probe(CONFIG.as_ptr(), CONFIG.len(), 1_000, std::ptr::null_mut())
            },
            ErrorCode::InvalidArgument as i32
        );
    }

    #[test]
    fn udp_probe_abi_uses_the_shared_first_flight() {
        let server = std::net::UdpSocket::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let port = server.local_addr().unwrap().port();
        let reply = std::thread::spawn(move || {
            let mut buffer = [0u8; 2048];
            let (received, peer) = server.recv_from(&mut buffer).unwrap();
            assert!(received > crate::protocol::udp_frag::FRAG_HDR_LEN);
            server.send_to(b"server hello", peer).unwrap();
            // Keep the bound port alive while the probe finishes sending the rest of its
            // fragmented ClientHello. Dropping it immediately can race a connected UDP
            // socket with ICMP Port Unreachable and hide the already queued reply.
            std::thread::sleep(Duration::from_millis(100));
        });
        let config = CONFIG
            .replace("127.0.0.1:443", &format!("127.0.0.1:{port}"))
            .replace("proto = tcp", "proto = udp");
        let mut latency = u64::MAX;
        assert_eq!(
            unsafe { qeli_client_udp_probe(config.as_ptr(), config.len(), 1_000, &mut latency) },
            OK
        );
        assert!(latency < 2_000);
        reply.join().unwrap();
    }

    #[tokio::test]
    async fn packet_batch_abi_moves_packets_and_rejects_null_storage() {
        let mut handle = 0;
        assert_eq!(
            unsafe {
                qeli_client_new(
                    CONFIG.as_ptr(),
                    CONFIG.len(),
                    platform_capability::SYSTEM_PLAN | platform_capability::TUN_PACKET_BATCH,
                    0,
                    &mut handle,
                )
            },
            OK
        );
        assert_eq!(qeli_client_start(handle), OK);
        CLIENTS
            .with(handle, |core| {
                core.publish_network_plan(NetworkPlan {
                    generation: 7,
                    tunnel_address: "10.0.0.2".into(),
                    prefix_len: 24,
                    mtu: 1400,
                    tunnel_gateway: "10.0.0.1".into(),
                    carrier_address: Some("127.0.0.1".into()),
                    routes: Vec::new(),
                    pushed_routes: Vec::new(),
                    dns_servers: Vec::new(),
                    full_tunnel: false,
                    kill_switch: false,
                    max_streams: 1,
                    adaptive: false,
                    data_plane: Default::default(),
                    connection_log: Vec::new(),
                })
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            unsafe { qeli_client_network_plan_result(handle, 7, 0, std::ptr::null(), 0) },
            OK
        );
        let mut pump = CLIENTS
            .with(handle, |core| core.take_packet_tun_pump(7))
            .unwrap()
            .unwrap();

        let lengths = [2u32, 3];
        let mut accepted = 0usize;
        assert_eq!(
            unsafe {
                qeli_client_tun_push(
                    handle,
                    7,
                    b"abcde".as_ptr(),
                    5,
                    lengths.as_ptr(),
                    lengths.len(),
                    &mut accepted,
                )
            },
            OK
        );
        assert_eq!(accepted, 2);
        assert_eq!(&*pump.recv_from_tun().await.unwrap(), b"ab");
        assert_eq!(&*pump.recv_from_tun().await.unwrap(), b"cde");

        let writer = pump.sender_to_tun();
        let mut packet = writer.acquire().await.unwrap();
        packet.as_vec_mut().extend_from_slice(b"downlink");
        writer.try_send(packet).unwrap();
        let mut bytes = vec![0u8; super::super::packet_tun::MAX_PACKET_BYTES];
        let mut output_lengths = [0u32; 4];
        let mut count = 0usize;
        let mut used = 0usize;
        assert_eq!(
            unsafe {
                qeli_client_tun_pull(
                    handle,
                    7,
                    bytes.as_mut_ptr(),
                    bytes.len(),
                    output_lengths.as_mut_ptr(),
                    output_lengths.len(),
                    &mut count,
                    &mut used,
                )
            },
            OK
        );
        assert_eq!((count, used, output_lengths[0]), (1, 8, 8));
        assert_eq!(&bytes[..used], b"downlink");

        assert_eq!(
            unsafe {
                qeli_client_tun_push(
                    handle,
                    7,
                    std::ptr::null(),
                    0,
                    lengths.as_ptr(),
                    1,
                    &mut accepted,
                )
            },
            ErrorCode::InvalidArgument as i32
        );
        pump.shutdown().await;
        assert_eq!(qeli_client_free(handle), OK);
    }

    #[test]
    fn device_id_abi_requires_a_nonzero_fixed_size_value_before_start() {
        let handle = unsafe { new_handle() };
        let mut device_id = [7u8; crate::protocol::DEVICE_ID_LEN];
        assert_eq!(
            unsafe { qeli_client_set_device_id(handle, device_id.as_ptr(), device_id.len()) },
            OK
        );
        assert_eq!(
            CLIENTS
                .with(handle, |core| *core.device_id().unwrap())
                .unwrap(),
            device_id
        );
        assert_eq!(
            unsafe { qeli_client_set_device_id(handle, std::ptr::null(), device_id.len()) },
            ErrorCode::InvalidArgument as i32
        );
        assert_eq!(
            unsafe { qeli_client_set_device_id(handle, device_id.as_ptr(), device_id.len() - 1) },
            ErrorCode::InvalidArgument as i32
        );
        device_id.fill(0);
        assert_eq!(
            unsafe { qeli_client_set_device_id(handle, device_id.as_ptr(), device_id.len()) },
            ErrorCode::InvalidArgument as i32
        );
        assert_eq!(qeli_client_start(handle), OK);
        assert_eq!(
            unsafe { qeli_client_set_device_id(handle, device_id.as_ptr(), device_id.len()) },
            ErrorCode::InvalidState as i32
        );
        assert_eq!(qeli_client_free(handle), OK);
    }

    #[test]
    fn invalid_config_returns_code_and_no_handle() {
        let config = b"not an ini";
        let mut handle = 99;
        let rc = unsafe { qeli_client_new(config.as_ptr(), config.len(), 0, 0, &mut handle) };
        assert_eq!(rc, ErrorCode::InvalidConfig as i32);
        assert_eq!(handle, 0);
    }

    #[test]
    fn handshake_network_input_returns_the_emitted_generation() {
        let handle = unsafe { new_handle() };
        assert_eq!(qeli_client_start(handle), OK);
        let auth = serde_json::json!({
            "client_ip": "10.8.0.2",
            "server_ip": "10.8.0.1",
            "prefix": 24,
            "mtu": 1400,
            "dns": "10.8.0.1",
            "dns_port": 53,
            "routes": []
        });
        let input = serde_json::json!({
            "auth_ok": format!("OK:{auth}"),
            "effective_mtu": 1400,
            "fallback_dns_servers": ["1.1.1.1", "8.8.8.8"]
        })
        .to_string();
        let mut generation = 0;
        assert_eq!(
            unsafe {
                qeli_client_publish_handshake_network(
                    handle,
                    input.as_ptr(),
                    input.len(),
                    &mut generation,
                )
            },
            OK
        );
        assert_eq!(generation, 1);
        let plan = CLIENTS
            .with(handle, |core| {
                while let Some(event) = core.poll_event() {
                    if event.kind == EventKind::NetworkPlan {
                        return event.plan;
                    }
                }
                None
            })
            .unwrap()
            .unwrap();
        assert_eq!(plan.generation, generation);
        assert_eq!(plan.tunnel_address, "10.8.0.2");
        assert!(
            plan.connection_log
                .iter()
                .any(|line| line.contains("server push: mtu 1400 ACCEPTED")),
            "FFI NetworkPlan must carry the shared MTU decision journal"
        );
        assert!(
            plan.connection_log
                .iter()
                .any(|line| line.contains("DNS 10.8.0.1:53 ACCEPTED")),
            "FFI NetworkPlan must carry the shared DNS decision journal"
        );
        assert_eq!(
            unsafe {
                qeli_client_publish_handshake_network(
                    handle,
                    input.as_ptr(),
                    input.len(),
                    std::ptr::null_mut(),
                )
            },
            ErrorCode::InvalidArgument as i32
        );
        assert_eq!(qeli_client_free(handle), OK);
    }

    #[test]
    fn event_buffer_probe_does_not_consume_network_plan() {
        let handle = unsafe { new_handle() };
        assert_eq!(qeli_client_start(handle), OK);
        CLIENTS.with(handle, |core| {
            core.poll_event();
            core.poll_event();
            core.publish_network_plan(NetworkPlan {
                generation: 1,
                tunnel_address: "10.0.0.2".into(),
                prefix_len: 24,
                mtu: 1400,
                tunnel_gateway: "10.0.0.1".into(),
                carrier_address: None,
                routes: vec![NetworkRoute {
                    cidr: "0.0.0.0/0".into(),
                    gateway: "10.0.0.1".into(),
                    metric: 100,
                }],
                pushed_routes: Vec::new(),
                dns_servers: vec![NetworkDns {
                    address: "1.1.1.1".into(),
                    port: 53,
                }],
                full_tunnel: true,
                kill_switch: true,
                max_streams: 1,
                adaptive: false,
                data_plane: Default::default(),
                connection_log: Vec::new(),
            })
            .unwrap();
            core.poll_event();
        });

        let mut event = QeliClientEvent::default();
        let mut required = 0;
        let rc = unsafe {
            qeli_client_poll_event(handle, &mut event, std::ptr::null_mut(), 0, &mut required)
        };
        assert_eq!(rc, ErrorCode::BufferTooSmall as i32);
        assert!(required > 0);
        assert_eq!(event.kind, EventKind::NetworkPlan as u32);

        let mut payload = vec![0; required];
        let rc = unsafe {
            qeli_client_poll_event(
                handle,
                &mut event,
                payload.as_mut_ptr(),
                payload.len(),
                &mut required,
            )
        };
        assert_eq!(rc, OK);
        assert_eq!(event.payload_format, PAYLOAD_JSON);
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(json["generation"], 1);
        assert_eq!(json["routes"][0]["gateway"], "10.0.0.1");
        assert_eq!(json["dns_servers"][0]["port"], 53);
        assert_eq!(qeli_client_free(handle), OK);
    }

    #[cfg(unix)]
    #[test]
    fn socket_protect_event_round_trips_through_the_frozen_abi() {
        use std::os::fd::AsRawFd;

        let mut handle = 0;
        let rc = unsafe {
            qeli_client_new(
                CONFIG.as_ptr(),
                CONFIG.len(),
                platform_capability::SYSTEM_PLAN | platform_capability::SOCKET_PROTECT,
                0,
                &mut handle,
            )
        };
        assert_eq!(rc, OK);
        assert_eq!(qeli_client_start(handle), OK);
        let (sequence, fd) = CLIENTS
            .with(handle, |core| {
                core.poll_event();
                core.poll_event();
                let pending = core.pending_wire_socket.as_ref().unwrap();
                (pending.sequence, pending.socket.as_raw_fd())
            })
            .unwrap();

        let mut event = QeliClientEvent::default();
        let mut required = 0;
        assert_eq!(
            unsafe {
                qeli_client_poll_event(handle, &mut event, std::ptr::null_mut(), 0, &mut required)
            },
            ErrorCode::BufferTooSmall as i32
        );
        assert_eq!(event.kind, EventKind::SocketProtect as u32);
        assert_eq!(event.sequence, sequence);
        assert_eq!(event.plan_generation, 0);
        assert_eq!(event.payload_format, PAYLOAD_JSON);

        let mut payload = vec![0; required];
        assert_eq!(
            unsafe {
                qeli_client_poll_event(
                    handle,
                    &mut event,
                    payload.as_mut_ptr(),
                    payload.len(),
                    &mut required,
                )
            },
            OK
        );
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(json["fd"], fd);

        assert_eq!(
            unsafe { qeli_client_socket_protect_result(handle, sequence, 0, std::ptr::null(), 0,) },
            OK
        );
        assert_eq!(
            CLIENTS
                .with(handle, |core| core.protected_wire_socket_raw_fd())
                .unwrap(),
            Some(fd)
        );
        assert_eq!(
            unsafe { qeli_client_socket_protect_result(handle, sequence, 0, std::ptr::null(), 0,) },
            ErrorCode::StaleRequest as i32
        );
        assert_eq!(qeli_client_free(handle), OK);
    }

    #[test]
    fn server_identity_event_round_trips_through_the_frozen_abi() {
        let mut handle = 0;
        let rc = unsafe {
            qeli_client_new(
                CONFIG.as_ptr(),
                CONFIG.len(),
                platform_capability::SYSTEM_PLAN | platform_capability::SERVER_IDENTITY,
                0,
                &mut handle,
            )
        };
        assert_eq!(rc, OK);
        assert_eq!(qeli_client_start(handle), OK);
        let (sequence, mut result) = CLIENTS
            .with(handle, |core| {
                core.poll_event();
                core.poll_event();
                core.request_server_identity([0xabu8; 32]).unwrap()
            })
            .unwrap();

        let mut event = QeliClientEvent::default();
        let mut required = 0;
        assert_eq!(
            unsafe {
                qeli_client_poll_event(handle, &mut event, std::ptr::null_mut(), 0, &mut required)
            },
            ErrorCode::BufferTooSmall as i32
        );
        assert_eq!(event.kind, EventKind::ServerIdentity as u32);
        assert_eq!(event.sequence, sequence);
        assert_eq!(event.plan_generation, 0);

        let mut payload = vec![0; required];
        assert_eq!(
            unsafe {
                qeli_client_poll_event(
                    handle,
                    &mut event,
                    payload.as_mut_ptr(),
                    payload.len(),
                    &mut required,
                )
            },
            OK
        );
        let json: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(json["server_id"], "127.0.0.1:443");
        assert_eq!(json["public_key"], "ab".repeat(32));
        assert_eq!(
            unsafe { qeli_client_server_identity_result(handle, sequence, 0, std::ptr::null(), 0) },
            OK
        );
        assert_eq!(result.try_recv().unwrap(), Ok(()));
        assert_eq!(
            unsafe { qeli_client_server_identity_result(handle, sequence, 0, std::ptr::null(), 0) },
            ErrorCode::StaleRequest as i32
        );
        assert_eq!(qeli_client_free(handle), OK);
    }

    #[test]
    fn stale_and_double_freed_handles_are_rejected() {
        let handle = unsafe { new_handle() };
        assert_eq!(qeli_client_free(handle), OK);
        assert_eq!(qeli_client_free(handle), ErrorCode::InvalidHandle as i32);
        assert_eq!(qeli_client_start(handle), ErrorCode::InvalidHandle as i32);
    }

    #[test]
    fn output_struct_size_is_required_and_future_tail_is_preserved() {
        #[repr(C)]
        struct FutureEvent {
            event: QeliClientEvent,
            future_tail: u64,
        }

        let handle = unsafe { new_handle() };
        let mut short = QeliClientEvent {
            struct_size: (EVENT_V1_SIZE - 1) as u32,
            ..QeliClientEvent::default()
        };
        let mut required = usize::MAX;
        assert_eq!(
            unsafe {
                qeli_client_poll_event(handle, &mut short, std::ptr::null_mut(), 0, &mut required)
            },
            ErrorCode::InvalidArgument as i32
        );
        assert_eq!(required, usize::MAX, "invalid output is not touched");

        let canary = 0xA5A5_A5A5_5A5A_5A5A;
        let mut future = FutureEvent {
            event: QeliClientEvent {
                struct_size: std::mem::size_of::<FutureEvent>() as u32,
                ..QeliClientEvent::default()
            },
            future_tail: canary,
        };
        assert_eq!(
            unsafe {
                qeli_client_poll_event(
                    handle,
                    &mut future.event,
                    std::ptr::null_mut(),
                    0,
                    &mut required,
                )
            },
            OK
        );
        assert_eq!(future.event.kind, EventKind::StateChanged as u32);
        assert_eq!(
            future.event.struct_size as usize,
            std::mem::size_of::<FutureEvent>()
        );
        assert_eq!(future.future_tail, canary);

        let mut short_stats = QeliClientStats {
            struct_size: (STATS_V1_SIZE - 1) as u32,
            ..QeliClientStats::default()
        };
        assert_eq!(
            unsafe { qeli_client_stats(handle, &mut short_stats) },
            ErrorCode::InvalidArgument as i32
        );
        let mut stats = QeliClientStats::default();
        assert_eq!(unsafe { qeli_client_stats(handle, &mut stats) }, OK);
        assert_eq!(stats.struct_size as usize, STATS_V2_SIZE);

        // An ABI 1.x caller that allocated only the original 64-byte prefix remains valid;
        // the four V2 counters beyond its declared size are not touched.
        let canary = 0x1122_3344_5566_7788;
        let mut v1_stats = QeliClientStats {
            struct_size: STATS_V1_SIZE as u32,
            udp_kernel_drops: canary,
            udp_internal_drops: canary,
            udp_buffer_grows: canary,
            udp_recv_buffer_bytes: canary,
            ..QeliClientStats::default()
        };
        v1_stats.struct_size = STATS_V1_SIZE as u32;
        assert_eq!(unsafe { qeli_client_stats(handle, &mut v1_stats) }, OK);
        assert_eq!(v1_stats.struct_size as usize, STATS_V1_SIZE);
        assert_eq!(v1_stats.udp_kernel_drops, canary);
        assert_eq!(v1_stats.udp_internal_drops, canary);
        assert_eq!(v1_stats.udp_buffer_grows, canary);
        assert_eq!(v1_stats.udp_recv_buffer_bytes, canary);
        assert_eq!(qeli_client_free(handle), OK);
    }

    #[test]
    fn panic_guard_returns_error_instead_of_unwinding() {
        let result = ffi_guard(|| panic!("intentional ABI test panic"));
        assert_eq!(result, ErrorCode::Panic as i32);
    }

    #[test]
    fn panic_inside_handle_operation_is_not_reported_as_invalid_handle() {
        let handle = unsafe { new_handle() };
        let result = with_core(handle, |_| panic!("intentional handle operation panic"));
        assert_eq!(result, ErrorCode::Panic as i32);
        assert_eq!(qeli_client_start(handle), ErrorCode::InvalidHandle as i32);
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn wintun_adapter_abi_validates_and_gates_positive_ack() {
        let mut handle = 0;
        let rc = unsafe {
            qeli_client_new(
                CONFIG.as_ptr(),
                CONFIG.len(),
                platform_capability::SYSTEM_PLAN | platform_capability::TUN_WINTUN,
                0,
                &mut handle,
            )
        };
        assert_eq!(rc, OK);
        assert_eq!(qeli_client_start(handle), OK);
        CLIENTS.with(handle, |core| {
            core.poll_event();
            core.poll_event();
            core.publish_network_plan(NetworkPlan {
                generation: 9,
                tunnel_address: "10.0.0.2".into(),
                prefix_len: 24,
                mtu: 1400,
                tunnel_gateway: "10.0.0.1".into(),
                carrier_address: None,
                routes: Vec::new(),
                pushed_routes: Vec::new(),
                dns_servers: Vec::new(),
                full_tunnel: false,
                kill_switch: false,
                max_streams: 1,
                adaptive: false,
                data_plane: Default::default(),
                connection_log: Vec::new(),
            })
            .unwrap();
        });

        assert_eq!(
            unsafe { qeli_client_network_plan_result(handle, 9, 0, std::ptr::null(), 0) },
            ErrorCode::InvalidState as i32
        );
        assert_eq!(
            unsafe { qeli_client_set_wintun_adapter(handle, 9, std::ptr::null(), 0) },
            ErrorCode::InvalidArgument as i32
        );
        let adapter_name = b"Qeli-test";
        assert_eq!(
            unsafe {
                qeli_client_set_wintun_adapter(handle, 8, adapter_name.as_ptr(), adapter_name.len())
            },
            ErrorCode::StalePlan as i32
        );
        assert_eq!(
            unsafe {
                qeli_client_set_wintun_adapter(handle, 9, adapter_name.as_ptr(), adapter_name.len())
            },
            OK
        );
        assert_eq!(
            unsafe { qeli_client_network_plan_result(handle, 9, 0, std::ptr::null(), 0) },
            OK
        );
        assert_eq!(
            CLIENTS
                .with(handle, |core| core.take_attached_wintun(9).unwrap())
                .unwrap(),
            "Qeli-test"
        );
        assert_eq!(qeli_client_stop(handle), OK);
        assert_eq!(qeli_client_free(handle), OK);
    }

    #[cfg(unix)]
    #[test]
    fn tun_fd_abi_duplicates_the_descriptor_and_gates_positive_ack() {
        use std::os::fd::AsRawFd;
        use std::os::unix::net::UnixStream;

        let mut handle = 0;
        let rc = unsafe {
            qeli_client_new(
                CONFIG.as_ptr(),
                CONFIG.len(),
                platform_capability::SYSTEM_PLAN | platform_capability::TUN_FD,
                0,
                &mut handle,
            )
        };
        assert_eq!(rc, OK);
        assert_eq!(qeli_client_start(handle), OK);
        CLIENTS.with(handle, |core| {
            core.poll_event();
            core.poll_event();
            core.publish_network_plan(NetworkPlan {
                generation: 9,
                tunnel_address: "10.0.0.2".into(),
                prefix_len: 24,
                mtu: 1400,
                tunnel_gateway: "10.0.0.1".into(),
                carrier_address: None,
                routes: Vec::new(),
                pushed_routes: Vec::new(),
                dns_servers: Vec::new(),
                full_tunnel: false,
                kill_switch: false,
                max_streams: 1,
                adaptive: false,
                data_plane: Default::default(),
                connection_log: Vec::new(),
            })
            .unwrap();
        });

        assert_eq!(
            unsafe { qeli_client_network_plan_result(handle, 9, 0, std::ptr::null(), 0) },
            ErrorCode::InvalidState as i32
        );
        let (original, peer) = UnixStream::pair().unwrap();
        assert_eq!(
            qeli_client_set_tun_fd(handle, 8, original.as_raw_fd()),
            ErrorCode::StalePlan as i32
        );
        assert_eq!(qeli_client_set_tun_fd(handle, 9, original.as_raw_fd()), OK);
        let duplicate = CLIENTS
            .with(handle, |core| core.attached_tun_raw_fd().unwrap())
            .unwrap();
        assert_ne!(duplicate, original.as_raw_fd());
        assert_ne!(
            unsafe { libc::fcntl(duplicate, libc::F_GETFD) } & libc::FD_CLOEXEC,
            0
        );
        let (replacement, replacement_peer) = UnixStream::pair().unwrap();
        assert_eq!(
            qeli_client_set_tun_fd(handle, 9, replacement.as_raw_fd()),
            OK
        );
        let replacement_duplicate = CLIENTS
            .with(handle, |core| core.attached_tun_raw_fd().unwrap())
            .unwrap();
        assert_ne!(replacement_duplicate, duplicate);
        assert_eq!(unsafe { libc::fcntl(duplicate, libc::F_GETFD) }, -1);
        drop(original);
        drop(replacement);
        assert!(unsafe { libc::fcntl(replacement_duplicate, libc::F_GETFD) } >= 0);
        drop(peer);
        drop(replacement_peer);
        assert_eq!(
            unsafe { qeli_client_network_plan_result(handle, 9, 0, std::ptr::null(), 0) },
            OK
        );
        assert_eq!(qeli_client_stop(handle), OK);
        assert_eq!(
            unsafe { libc::fcntl(replacement_duplicate, libc::F_GETFD) },
            -1
        );
        assert_eq!(qeli_client_free(handle), OK);
    }
}
