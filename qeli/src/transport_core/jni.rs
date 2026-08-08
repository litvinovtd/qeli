//! Android JNI adapter for the versioned whole-client control-plane ABI.
//!
//! This intentionally wraps the C ABI rather than maintaining a second registry or state
//! machine. Kotlin therefore exercises the same generation checks, panic boundary and error
//! taxonomy as every other foreign-language adapter. Packet IO is not exposed in this slice.

#![cfg(all(target_os = "android", feature = "transport-core-ffi"))]

use super::ffi::{
    qeli_client_abi_version, qeli_client_core_capabilities, qeli_client_free, qeli_client_new,
    qeli_client_poll_event, qeli_client_set_tun_fd, qeli_client_start, qeli_client_state,
    qeli_client_stop, QeliClientEvent, EVENT_V1_SIZE, NO_EVENT, OK,
};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jbyteArray, jint, jlong};
use jni::JNIEnv;
use zeroize::Zeroizing;

const MAX_JNI_EVENT_PAYLOAD: usize = 1024 * 1024;

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

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeStop(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    qeli_client_stop(handle as u64) as jint
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

#[no_mangle]
pub extern "system" fn Java_com_qeli_TransportCore_nativeFree(
    _env: JNIEnv,
    _class: JClass,
    handle: jlong,
) -> jint {
    qeli_client_free(handle as u64) as jint
}
