//! Android JNI adapter for the versioned whole-client control-plane ABI.
//!
//! This intentionally wraps the C ABI rather than maintaining a second registry or state
//! machine. Kotlin therefore exercises the same generation checks, panic boundary and error
//! taxonomy as every other foreign-language adapter. The only handle-free operation is the
//! bounded UDP first-flight diagnostic; it never authenticates or creates a tunnel.

#![cfg(all(target_os = "android", feature = "transport-core-ffi"))]

use super::ffi::{
    qeli_client_abi_version, qeli_client_core_capabilities, qeli_client_free,
    qeli_client_network_plan_result, qeli_client_new, qeli_client_poll_event,
    qeli_client_publish_handshake_network, qeli_client_run, qeli_client_server_identity_result,
    qeli_client_set_device_id, qeli_client_set_tun_fd, qeli_client_socket_protect_result,
    qeli_client_start, qeli_client_state, qeli_client_stats, qeli_client_stop, QeliClientEvent,
    QeliClientStats, EVENT_V1_SIZE, NO_EVENT, OK,
};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong, jlongArray};
use jni::JNIEnv;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const MAX_JNI_EVENT_PAYLOAD: usize = 1024 * 1024;
const MAX_PROBE_HOST_BYTES: usize = 253;

const MAX_PROBE_TERMINAL_HISTORY: usize = 1024;

enum ProbeState {
    /// Cancellation beat the blocking JNI call to registration.
    CancelBeforeStart,
    Active(Arc<AtomicBool>),
    /// Distinguishes a harmless late coroutine cancellation from an early one.
    Completed,
}

#[derive(Default)]
struct ProbeRegistry {
    probes: HashMap<u64, ProbeState>,
    terminal_order: VecDeque<u64>,
}

impl ProbeRegistry {
    fn record_terminal(&mut self, id: u64) {
        self.terminal_order.push_back(id);
        while self.terminal_order.len() > MAX_PROBE_TERMINAL_HISTORY {
            if let Some(expired) = self.terminal_order.pop_front() {
                if !matches!(self.probes.get(&expired), Some(ProbeState::Active(_))) {
                    self.probes.remove(&expired);
                }
            }
        }
    }

    fn cancel(&mut self, id: u64) {
        match self.probes.get(&id) {
            Some(ProbeState::Active(cancelled)) => {
                cancelled.store(true, Ordering::Release);
            }
            Some(ProbeState::CancelBeforeStart | ProbeState::Completed) => {}
            None => {
                self.probes.insert(id, ProbeState::CancelBeforeStart);
                self.record_terminal(id);
            }
        }
    }
}

static CANCELLABLE_UDP_PROBES: LazyLock<Mutex<ProbeRegistry>> =
    LazyLock::new(|| Mutex::new(ProbeRegistry::default()));

fn cancellable_udp_probes() -> MutexGuard<'static, ProbeRegistry> {
    CANCELLABLE_UDP_PROBES
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

struct ProbeRegistration {
    id: u64,
    cancelled: Arc<AtomicBool>,
}

impl ProbeRegistration {
    fn register(id: u64) -> Option<Self> {
        if id == 0 {
            return None;
        }
        let mut registry = cancellable_udp_probes();
        let cancelled = match registry.probes.remove(&id) {
            None => Arc::new(AtomicBool::new(false)),
            Some(ProbeState::CancelBeforeStart) => {
                // Remove the old terminal queue entry before this id becomes active;
                // otherwise expiry of that entry could remove the live registration.
                registry.terminal_order.retain(|queued| *queued != id);
                Arc::new(AtomicBool::new(true))
            }
            Some(existing @ (ProbeState::Active(_) | ProbeState::Completed)) => {
                registry.probes.insert(id, existing);
                return None;
            }
        };
        registry
            .probes
            .insert(id, ProbeState::Active(Arc::clone(&cancelled)));
        Some(Self { id, cancelled })
    }
}

impl Drop for ProbeRegistration {
    fn drop(&mut self) {
        let mut registry = cancellable_udp_probes();
        match registry.probes.remove(&self.id) {
            Some(ProbeState::Active(current)) if Arc::ptr_eq(&current, &self.cancelled) => {
                registry.probes.insert(self.id, ProbeState::Completed);
                registry.record_terminal(self.id);
            }
            Some(other) => {
                registry.probes.insert(self.id, other);
            }
            None => {}
        }
    }
}

fn guard<T>(fallback: T, operation: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or(fallback)
}

fn to_array(env: &JNIEnv, bytes: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(bytes)
        .map(|array| array.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

fn udp_reachability_jni<'local>(
    env: &JNIEnv<'local>,
    config: &JByteArray<'local>,
    host: &JByteArray<'local>,
    timeout_ms: jint,
    cancelled: Option<&AtomicBool>,
) -> jlong {
    let timeout_ms = match u32::try_from(timeout_ms) {
        Ok(value)
            if (super::diagnostic::MIN_PROBE_TIMEOUT_MS
                ..=super::diagnostic::MAX_PROBE_TIMEOUT_MS)
                .contains(&value) =>
        {
            value
        }
        _ => return -1,
    };
    let config_bytes = match env.convert_byte_array(config) {
        Ok(bytes) if bytes.len() <= super::MAX_CONFIG_BYTES => Zeroizing::new(bytes),
        _ => return -1,
    };
    let config_text = match std::str::from_utf8(&config_bytes) {
        Ok(text) => text,
        Err(_) => return -1,
    };
    let mut parsed = match super::parse_config(config_text) {
        Ok(config) if config.server.protocol == "udp" => config,
        _ => return -1,
    };
    let host_bytes = match env.convert_byte_array(host) {
        Ok(bytes) if !bytes.is_empty() && bytes.len() <= MAX_PROBE_HOST_BYTES => {
            Zeroizing::new(bytes)
        }
        _ => return -1,
    };
    let host = match std::str::from_utf8(&host_bytes) {
        Ok(value)
            if !value.is_empty()
                && !value.chars().any(char::is_control)
                && !value.contains(':') =>
        {
            value
        }
        _ => return -1,
    };
    let timeout = Duration::from_millis(timeout_ms as u64);
    let result = match cancelled {
        Some(cancelled) => {
            super::diagnostic::udp_reachability_cancellable(&parsed, host, timeout, cancelled)
        }
        None => super::diagnostic::udp_reachability(&parsed, host, timeout),
    };
    parsed.obfuscation.obfs_key.zeroize();
    if let Some(password) = parsed.auth.password.as_mut() {
        password.zeroize();
    }
    match result {
        Ok(milliseconds) => milliseconds.min(i64::MAX as u64) as jlong,
        Err(_) => -1,
    }
}

/// Internal Android event frame: the ABI 1.0 48-byte event header encoded explicitly in
/// little-endian order, followed by `payload_len` bytes. Both shipped Android ABIs are
/// little-endian, but explicit encoding keeps the Kotlin parser independent of Rust layout.
fn event_frame(event: &QeliClientEvent, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(EVENT_V1_SIZE + payload.len());
    frame.extend_from_slice(&(EVENT_V1_SIZE as u32).to_le_bytes());
    frame.extend_from_slice(&event.abi_version.to_le_bytes());
    frame.extend_from_slice(&event.kind.to_le_bytes());
    frame.extend_from_slice(&event.state.to_le_bytes());
    frame.extend_from_slice(&event.payload_format.to_le_bytes());
    frame.extend_from_slice(&event.reserved.to_le_bytes());
    frame.extend_from_slice(&event.sequence.to_le_bytes());
    frame.extend_from_slice(&event.plan_generation.to_le_bytes());
    frame.extend_from_slice(&event.error_code.to_le_bytes());
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    debug_assert_eq!(frame.len(), EVENT_V1_SIZE);
    frame.extend_from_slice(payload);
    frame
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeAbiVersion(
    _env: JNIEnv,
    _class: JClass,
) -> jint {
    qeli_client_abi_version() as jint
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeCoreCapabilities(
    _env: JNIEnv,
    _class: JClass,
) -> jlong {
    qeli_client_core_capabilities() as jlong
}

/// `TransportCore.nativeUdpReachability(config, host, timeoutMs) -> long`.
///
/// The strict profile is intentionally minimal and credential-free on the Kotlin side. Rust
/// builds the same hybrid PQ ClientHello flight as the live UDP transport, applies QUIC/obfs,
/// retries once and returns milliseconds to the first reply (`-1` on any failure).
#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeUdpReachability<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    config: JByteArray<'local>,
    host: JByteArray<'local>,
    timeout_ms: jint,
) -> jlong {
    guard(-1, || {
        udp_reachability_jni(&env, &config, &host, timeout_ms, None)
    })
}

/// Cancellable Android-only UDP diagnostic. `probe_id` identifies exactly one blocking JNI
/// invocation; cancellation drops its Rust future/socket instead of waiting out both retries.
#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeUdpReachabilityCancellable<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    config: JByteArray<'local>,
    host: JByteArray<'local>,
    timeout_ms: jint,
    probe_id: jlong,
) -> jlong {
    guard(-1, || {
        let probe_id = match u64::try_from(probe_id) {
            Ok(value) if value != 0 => value,
            _ => return -1,
        };
        let registration = match ProbeRegistration::register(probe_id) {
            Some(registration) => registration,
            None => return -1,
        };
        udp_reachability_jni(
            &env,
            &config,
            &host,
            timeout_ms,
            Some(registration.cancelled.as_ref()),
        )
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeCancelUdpReachability(
    _env: JNIEnv,
    _class: JClass,
    probe_id: jlong,
) {
    guard((), || {
        let Ok(probe_id) = u64::try_from(probe_id) else {
            return;
        };
        cancellable_udp_probes().cancel(probe_id);
    });
}

/// Create a core from strict UTF-8 configuration. Returning zero mirrors the existing
/// Android native-handle convention and never exposes configuration bytes in an exception.
#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeNew<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    config: JByteArray<'local>,
    platform_capabilities: jlong,
    event_capacity: jint,
) -> jlong {
    guard(0, || {
        if event_capacity < 0 {
            return 0;
        }
        let bytes = match env.convert_byte_array(&config) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return 0,
        };
        let mut handle = 0;
        let result = unsafe {
            qeli_client_new(
                bytes.as_ptr(),
                bytes.len(),
                platform_capabilities as u64,
                event_capacity as u32,
                &mut handle,
            )
        };
        if result == 0 {
            handle as jlong
        } else {
            0
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeStart(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    qeli_client_start(handle as u64) as jint
}

/// Blocks on one complete Rust-owned transport generation. Kotlin invokes this from
/// Dispatchers.IO while its event pump continues to service protect/trust/NetworkPlan ACKs.
#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeRunTransport<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    input: JByteArray<'local>,
) -> jint {
    guard(super::ErrorCode::Panic as jint, || {
        let bytes = match env.convert_byte_array(&input) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return super::ErrorCode::InvalidArgument as jint,
        };
        unsafe { qeli_client_run(handle as u64, bytes.as_ptr(), bytes.len()) as jint }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    qeli_client_stop(handle as u64) as jint
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeSetDeviceId<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    device_id: JByteArray<'local>,
) -> jint {
    guard(super::ErrorCode::Panic as jint, || {
        let bytes = match env.convert_byte_array(&device_id) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return super::ErrorCode::InvalidArgument as jint,
        };
        unsafe { qeli_client_set_device_id(handle as u64, bytes.as_ptr(), bytes.len()) as jint }
    })
}

/// Return a non-negative state value or the negative ABI error code.
#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeState(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    guard(super::ErrorCode::Panic as jint, || {
        let mut state = 0;
        let result = unsafe { qeli_client_state(handle as u64, &mut state) };
        if result == 0 {
            state as jint
        } else {
            result as jint
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeStats(
    env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jlongArray {
    guard(std::ptr::null_mut(), || {
        let mut stats = QeliClientStats::default();
        let result = unsafe { qeli_client_stats(handle as u64, &mut stats) };
        if result != OK {
            return std::ptr::null_mut();
        }
        let values = [
            stats.tx_bytes as jlong,
            stats.rx_bytes as jlong,
            stats.tx_packets as jlong,
            stats.rx_packets as jlong,
            stats.udp_kernel_drops as jlong,
            stats.udp_internal_drops as jlong,
            stats.udp_buffer_grows as jlong,
            stats.udp_recv_buffer_bytes as jlong,
        ];
        let array = match env.new_long_array(values.len() as jint) {
            Ok(array) => array,
            Err(_) => return std::ptr::null_mut(),
        };
        if env.set_long_array_region(&array, 0, &values).is_err() {
            return std::ptr::null_mut();
        }
        array.into_raw()
    })
}

/// Poll one control-plane event. `null` means only that the bounded queue is currently empty.
/// Invalid handles, ABI failures, oversized payloads and panic-boundary failures raise a Java
/// IllegalStateException, so Kotlin cannot silently confuse a broken native core with quiescence.
#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativePollEvent<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    let polled = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut event = QeliClientEvent::default();
        let mut required = 0usize;
        let first = unsafe {
            qeli_client_poll_event(
                handle as u64,
                &mut event,
                std::ptr::null_mut(),
                0,
                &mut required,
            )
        };
        if first == NO_EVENT {
            return Ok(None);
        }
        if required > MAX_JNI_EVENT_PAYLOAD {
            return Err(format!(
                "native event payload {required} exceeds JNI cap {MAX_JNI_EVENT_PAYLOAD}"
            ));
        }
        let payload = if first == OK {
            Vec::new()
        } else if first == super::ErrorCode::BufferTooSmall as i32 {
            let mut payload = vec![0u8; required];
            let mut actual = 0usize;
            let second = unsafe {
                qeli_client_poll_event(
                    handle as u64,
                    &mut event,
                    payload.as_mut_ptr(),
                    payload.len(),
                    &mut actual,
                )
            };
            if second != OK || actual != payload.len() {
                return Err(format!(
                    "qeli_client_poll_event payload read failed (rc={second}, expected={required}, actual={actual})"
                ));
            }
            payload
        } else {
            return Err(format!("qeli_client_poll_event failed (rc={first})"));
        };
        Ok(Some(event_frame(&event, &payload)))
    }));

    match polled {
        Ok(Ok(None)) => std::ptr::null_mut(),
        Ok(Ok(Some(frame))) => match env.byte_array_from_slice(&frame) {
            Ok(array) => array.into_raw(),
            Err(error) => {
                let _ = env.throw_new(
                    "java/lang/IllegalStateException",
                    format!("cannot allocate native event frame: {error}"),
                );
                std::ptr::null_mut()
            }
        },
        Ok(Err(message)) => {
            let _ = env.throw_new("java/lang/IllegalStateException", message);
            std::ptr::null_mut()
        }
        Err(_) => {
            let _ = env.throw_new(
                "java/lang/IllegalStateException",
                "nativePollEvent panicked",
            );
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeSetTunFd(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
    generation: jlong,
    fd: jint,
) -> jint {
    qeli_client_set_tun_fd(handle as u64, generation as u64, fd) as jint
}

/// Publish authenticated network input and return its positive generation or a negative
/// stable ABI error code. The JSON bytes are wiped after the C ABI has copied the plan.
#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativePublishHandshakeNetwork<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    input: JByteArray<'local>,
) -> jlong {
    guard(super::ErrorCode::Panic as jlong, || {
        let bytes = match env.convert_byte_array(&input) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return super::ErrorCode::InvalidArgument as jlong,
        };
        let mut generation = 0u64;
        let result = unsafe {
            qeli_client_publish_handshake_network(
                handle as u64,
                bytes.as_ptr(),
                bytes.len(),
                &mut generation,
            )
        };
        if result == OK {
            generation as jlong
        } else {
            result as jlong
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeNetworkPlanResult<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    generation: jlong,
    result_code: jint,
    reason: JByteArray<'local>,
) -> jint {
    guard(super::ErrorCode::Panic as jint, || {
        let bytes = match env.convert_byte_array(&reason) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return super::ErrorCode::InvalidArgument as jint,
        };
        let pointer = if bytes.is_empty() {
            std::ptr::null()
        } else {
            bytes.as_ptr()
        };
        unsafe {
            qeli_client_network_plan_result(
                handle as u64,
                generation as u64,
                result_code,
                pointer,
                bytes.len(),
            ) as jint
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeSocketProtectResult<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    request_sequence: jlong,
    result_code: jint,
    reason: JByteArray<'local>,
) -> jint {
    guard(super::ErrorCode::Panic as jint, || {
        let bytes = match env.convert_byte_array(&reason) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return super::ErrorCode::InvalidArgument as jint,
        };
        let pointer = if bytes.is_empty() {
            std::ptr::null()
        } else {
            bytes.as_ptr()
        };
        unsafe {
            qeli_client_socket_protect_result(
                handle as u64,
                request_sequence as u64,
                result_code,
                pointer,
                bytes.len(),
            ) as jint
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeServerIdentityResult<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    request_sequence: jlong,
    result_code: jint,
    reason: JByteArray<'local>,
) -> jint {
    guard(super::ErrorCode::Panic as jint, || {
        let bytes = match env.convert_byte_array(&reason) {
            Ok(bytes) => Zeroizing::new(bytes),
            Err(_) => return super::ErrorCode::InvalidArgument as jint,
        };
        let pointer = if bytes.is_empty() {
            std::ptr::null()
        } else {
            bytes.as_ptr()
        };
        unsafe {
            qeli_client_server_identity_result(
                handle as u64,
                request_sequence as u64,
                result_code,
                pointer,
                bytes.len(),
            ) as jint
        }
    })
}

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    qeli_client_free(handle as u64) as jint
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_registry_closes_cancel_before_start_and_ignores_late_cancel() {
        let id = u64::MAX - 17;
        {
            let mut registry = cancellable_udp_probes();
            registry.probes.remove(&id);
            registry.terminal_order.retain(|queued| *queued != id);
            registry.cancel(id);
        }

        let registration = ProbeRegistration::register(id)
            .expect("early cancellation must still admit the matching JNI registration");
        assert!(registration.cancelled.load(Ordering::Acquire));
        drop(registration);

        // A coroutine can be cancelled after JNI has already returned. That late signal must
        // not become CancelBeforeStart for a future call or resurrect this completed id.
        cancellable_udp_probes().cancel(id);
        assert!(ProbeRegistration::register(id).is_none());

        let mut registry = cancellable_udp_probes();
        registry.probes.remove(&id);
        registry.terminal_order.retain(|queued| *queued != id);
    }
}
