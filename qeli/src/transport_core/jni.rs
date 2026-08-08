//! Android JNI adapter for the versioned whole-client control-plane ABI.
//!
//! This intentionally wraps the C ABI rather than maintaining a second registry or state
//! machine. Kotlin therefore exercises the same generation checks, panic boundary and error
//! taxonomy as every other foreign-language adapter. Packet IO is not exposed in this slice.

#![cfg(all(target_os = "android", feature = "transport-core-ffi"))]

use super::ffi::{
    qeli_client_abi_version, qeli_client_core_capabilities, qeli_client_free, qeli_client_new,
    qeli_client_set_tun_fd, qeli_client_start, qeli_client_state, qeli_client_stop,
};
use jni::objects::{JByteArray, JClass};
use jni::sys::{jint, jlong};
use jni::JNIEnv;
use zeroize::Zeroizing;

fn guard<T>(fallback: T, operation: impl FnOnce() -> T) -> T {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation)).unwrap_or(fallback)
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
