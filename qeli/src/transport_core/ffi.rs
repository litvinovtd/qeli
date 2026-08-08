//! Versioned C ABI for [`super::ClientCore`].
//!
//! This is intentionally a control-plane API. Event payloads are copied into a buffer
//! supplied by the caller; the future packet path will have a separate batched API and
//! must not allocate per packet.

use super::{
    core_capability, ClientCore, ClientEvent, CoreOptions, CoreStats, ErrorCode, EventKind,
    ABI_VERSION, DEFAULT_EVENT_CAPACITY,
};
use crate::protocol::realtls::registry::Registry;
use std::panic::{catch_unwind, AssertUnwindSafe};

const OK: i32 = 0;
const NO_EVENT: i32 = 1;
const PAYLOAD_NONE: u32 = 0;
const PAYLOAD_JSON: u32 = 1;
const PAYLOAD_UTF8: u32 = 2;

static CLIENTS: Registry<ClientCore> = Registry::new();

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
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

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
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
}

#[no_mangle]
pub extern "C" fn qeli_client_abi_version() -> u32 {
    ABI_VERSION
}

#[no_mangle]
pub extern "C" fn qeli_client_core_capabilities() -> u64 {
    core_capability::ALL
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
        match CLIENTS.with(handle, |core| {
            core.ack_network_plan(generation, result_code == 0, reason)
        }) {
            Some(Ok(())) => OK,
            Some(Err(error)) => error.code() as i32,
            None => ErrorCode::InvalidHandle as i32,
        }
    })
}

/// Pop one event, copying its optional payload to caller-owned memory.
///
/// Returns `1` when the queue is empty. If the payload buffer is too small, returns
/// `BufferTooSmall`, writes the required byte count, and leaves the event queued.
/// Network plans use UTF-8 JSON; errors use plain UTF-8; state events have no payload.
///
/// # Safety
/// The output pointers must be writable. A non-empty payload buffer must address
/// `payload_capacity` writable bytes.
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
        unsafe { *out_payload_len = 0 };
        match CLIENTS.with(handle, |core| {
            let Some(event) = core.peek_event().cloned() else {
                return NO_EVENT;
            };
            let (payload_bytes, payload_format) = match event_payload(&event) {
                Ok(payload) => payload,
                Err(code) => return code as i32,
            };
            unsafe { *out_payload_len = payload_bytes.len() };
            let header = event_header(&event, payload_format, payload_bytes.len());
            unsafe { *out_event = header };
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
            Some(code) => code,
            None => ErrorCode::InvalidHandle as i32,
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
        match CLIENTS.with(handle, |core| core.state() as u32) {
            Some(state) => {
                unsafe { *out_state = state };
                OK
            }
            None => ErrorCode::InvalidHandle as i32,
        }
    })
}

/// # Safety
/// `out_stats` must be writable.
#[no_mangle]
pub unsafe extern "C" fn qeli_client_stats(handle: u64, out_stats: *mut QeliClientStats) -> i32 {
    ffi_guard(|| {
        if out_stats.is_null() {
            return ErrorCode::InvalidArgument as i32;
        }
        match CLIENTS.with(handle, |core| core.stats()) {
            Some(stats) => {
                unsafe { *out_stats = ffi_stats(stats) };
                OK
            }
            None => ErrorCode::InvalidHandle as i32,
        }
    })
}

#[no_mangle]
pub extern "C" fn qeli_client_free(handle: u64) -> i32 {
    ffi_guard(|| {
        if CLIENTS.remove(handle) {
            OK
        } else {
            ErrorCode::InvalidHandle as i32
        }
    })
}

fn with_core(
    handle: u64,
    operation: impl FnOnce(&mut ClientCore) -> Result<(), super::CoreError>,
) -> i32 {
    match CLIENTS.with(handle, operation) {
        Some(Ok(())) => OK,
        Some(Err(error)) => error.code() as i32,
        None => ErrorCode::InvalidHandle as i32,
    }
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
    use crate::transport_core::{platform_capability, NetworkPlan};

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
        assert_eq!(std::mem::size_of::<QeliClientStats>(), 64);

        let header = include_str!("../../include/qeli_transport_core.h");
        assert!(header.contains("QELI_CLIENT_ABI_VERSION UINT32_C(0x00010000)"));
        assert!(header.contains("QELI_CLIENT_PLATFORM_REJECTED = -10"));
        assert!(header.contains("qeli_client_network_plan_result"));
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
                routes: vec!["0.0.0.0/0".into()],
                dns_servers: vec!["1.1.1.1".into()],
                full_tunnel: true,
                kill_switch: true,
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
    fn panic_guard_returns_error_instead_of_unwinding() {
        let result = ffi_guard(|| panic!("intentional ABI test panic"));
        assert_eq!(result, ErrorCode::Panic as i32);
    }
}
