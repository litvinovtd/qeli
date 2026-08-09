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
use std::time::Duration;
use zeroize::{Zeroize, Zeroizing};

const MAX_JNI_EVENT_PAYLOAD: usize = 1024 * 1024;
const MAX_PROBE_HOST_BYTES: usize = 253;

fn guard<T>(fallback: T, operation: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or(fallback)
}

fn to_array(env: &JNIEnv, bytes: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(bytes)
        .map(|array| array.into_raw())
        .unwrap_or(std::ptr::null_mut())
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
        let config_bytes = match env.convert_byte_array(&config) {
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
        let host_bytes = match env.convert_byte_array(&host) {
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
        let result = super::diagnostic::udp_reachability(
            &parsed,
            host,
            Duration::from_millis(timeout_ms as u64),
        );
        parsed.obfuscation.obfs_key.zeroize();
        if let Some(password) = parsed.auth.password.as_mut() {
            password.zeroize();
        }
        match result {
            Ok(milliseconds) => milliseconds.min(i64::MAX as u64) as jlong,
            Err(_) => -1,
        }
    })
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

/// Poll one control-plane event. `null` means the bounded queue is currently empty or the
/// handle is invalid; a valid frame contains the stable 48-byte ABI header plus payload.
#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativePollEvent<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    guard(std::ptr::null_mut(), || {
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
            return std::ptr::null_mut();
        }
        if required > MAX_JNI_EVENT_PAYLOAD {
            return std::ptr::null_mut();
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
                return std::ptr::null_mut();
            }
            payload
        } else {
            return std::ptr::null_mut();
        };
        to_array(&env, &event_frame(&event, &payload))
    })
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
