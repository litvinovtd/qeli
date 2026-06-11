//! A4 — JNI bridge over the sans-IO realtls core for the Android client.
//!
//! Java can't call the plain C ABI ([`super::ffi`]) directly, so these
//! `Java_com_qeli_RealTls_*` functions (JNI calling convention) wrap the same
//! [`SansIoClient`]. The Kotlin side is `com.qeli.RealTls` with matching
//! `external fun` declarations and `System.loadLibrary("qeli")`.
//!
//! Convention: a `long` handle holds a `Box<SansIoClient>`; byte arrays cross as
//! `jbyteArray`. `nativeRecv` returns the bytes to send when the handshake
//! completes, an empty array while more input is needed, or `null` on error.

#![cfg(target_os = "android")]

use super::sansio::{Progress, SansIoClient};
use crate::crypto::reality::SHORT_ID_LEN;
use crate::crypto::PublicKey;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jlong, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

fn to_array(env: &mut JNIEnv, data: &[u8]) -> jbyteArray {
    env.byte_array_from_slice(data)
        .map(|a| a.into_raw())
        .unwrap_or(std::ptr::null_mut())
}

/// `RealTls.nativeNew(realityPub, shortId, sni) -> long` (0 on error).
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeNew<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    reality_pub: JByteArray<'local>,
    short_id: JByteArray<'local>,
    sni: JString<'local>,
) -> jlong {
    let pub_bytes = match env.convert_byte_array(&reality_pub) {
        Ok(b) if b.len() == 32 => b,
        _ => return 0,
    };
    let sid_bytes = match env.convert_byte_array(&short_id) {
        Ok(b) if b.len() >= SHORT_ID_LEN => b,
        _ => return 0,
    };
    let sni_str: String = match env.get_string(&sni) {
        Ok(s) => s.into(),
        Err(_) => return 0,
    };
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pub_bytes);
    let mut sid = [0u8; SHORT_ID_LEN];
    sid.copy_from_slice(&sid_bytes[..SHORT_ID_LEN]);
    let (client, _hello) = SansIoClient::new(&PublicKey::from_bytes(&pk), &sid, &sni_str);
    Box::into_raw(Box::new(client)) as jlong
}

/// `RealTls.nativeClientHello(handle) -> byte[]` — the ClientHello to send first.
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeClientHello<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    let client = unsafe { &*(handle as *const SansIoClient) };
    to_array(&mut env, client.client_hello())
}

/// `RealTls.nativeRecv(handle, data) -> byte[]` — bytes to send (handshake done),
/// empty (need more), or null (error).
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeRecv<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    data: JByteArray<'local>,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    let bytes = env.convert_byte_array(&data).unwrap_or_default();
    let client = unsafe { &mut *(handle as *mut SansIoClient) };
    match client.recv(&bytes) {
        Ok(Progress::NeedMore) => to_array(&mut env, &[]),
        Ok(Progress::Done(to_send)) => to_array(&mut env, &to_send),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `RealTls.nativeSeal(handle, plaintext) -> byte[]` — one application_data record.
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeSeal<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    data: JByteArray<'local>,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    let bytes = env.convert_byte_array(&data).unwrap_or_default();
    let client = unsafe { &mut *(handle as *mut SansIoClient) };
    match client.seal(&bytes) {
        Ok(rec) => to_array(&mut env, &rec),
        Err(_) => std::ptr::null_mut(),
    }
}

/// `RealTls.nativeOpen(handle, data) -> byte[]` — concatenated decrypted plaintext.
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeOpen<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    data: JByteArray<'local>,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    let bytes = env.convert_byte_array(&data).unwrap_or_default();
    let client = unsafe { &mut *(handle as *mut SansIoClient) };
    match client.open_push(&bytes) {
        Ok(msgs) => {
            let mut cat = Vec::new();
            for m in msgs {
                cat.extend_from_slice(&m);
            }
            to_array(&mut env, &cat)
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// `RealTls.nativeEstablished(handle) -> boolean`.
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeEstablished<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    if handle == 0 {
        return JNI_FALSE;
    }
    let client = unsafe { &*(handle as *const SansIoClient) };
    if client.established() {
        JNI_TRUE
    } else {
        JNI_FALSE
    }
}

/// `RealTls.nativeFree(handle)`.
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeFree<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            let _ = Box::from_raw(handle as *mut SansIoClient);
        }
    }
}

// --- ML-KEM-768 bridge (`com.qeli.MlKem`) ---------------------------------
//
// Kotlin has no vetted ML-KEM, so the Android client drives the hybrid qeli
// handshake's post-quantum half through the same `ml-kem` crate the server
// uses. A `long` handle holds a `Box<MlKemKeypair>`: the retained decapsulation
// key plus the public encapsulation key the caller embeds in its ClientHello.
// Lifecycle mirrors the `RealTls` handle — `nativeKeygen` allocates,
// `nativeFree` releases, and the bytes returned by `nativeEncapKey` /
// `nativeDecapsulate` are owned by the JVM once handed back.

struct MlKemKeypair {
    dk: crate::crypto::mlkem::DecapKey,
    ek: Vec<u8>,
}

/// `MlKem.nativeKeygen() -> long` — a fresh ML-KEM-768 keypair handle (0 on error).
#[no_mangle]
pub extern "system" fn Java_com_qeli_MlKem_nativeKeygen<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jlong {
    let (dk, ek) = crate::crypto::mlkem::mlkem768_keypair();
    Box::into_raw(Box::new(MlKemKeypair { dk, ek })) as jlong
}

/// `MlKem.nativeEncapKey(handle) -> byte[]` — the 1184-byte encapsulation key to
/// carry in the ClientHello key_share (null on a bad handle).
#[no_mangle]
pub extern "system" fn Java_com_qeli_MlKem_nativeEncapKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    let kp = unsafe { &*(handle as *const MlKemKeypair) };
    to_array(&mut env, &kp.ek)
}

/// `MlKem.nativeDecapsulate(handle, ct) -> byte[]` — the 32-byte shared secret
/// from the server's ciphertext, or null on a malformed ciphertext / bad handle.
#[no_mangle]
pub extern "system" fn Java_com_qeli_MlKem_nativeDecapsulate<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
    ct: JByteArray<'local>,
) -> jbyteArray {
    if handle == 0 {
        return std::ptr::null_mut();
    }
    let ct_bytes = env.convert_byte_array(&ct).unwrap_or_default();
    let kp = unsafe { &*(handle as *const MlKemKeypair) };
    match crate::crypto::mlkem::mlkem768_decapsulate(&kp.dk, &ct_bytes) {
        Some(ss) => to_array(&mut env, &ss),
        None => std::ptr::null_mut(),
    }
}

/// `MlKem.nativeFree(handle)`.
#[no_mangle]
pub extern "system" fn Java_com_qeli_MlKem_nativeFree<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    if handle != 0 {
        unsafe {
            let _ = Box::from_raw(handle as *mut MlKemKeypair);
        }
    }
}
