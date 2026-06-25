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

use super::registry::Registry;
use super::sansio::{Progress, SansIoClient};
use crate::crypto::reality::SHORT_ID_LEN;
use crate::crypto::PublicKey;
use jni::objects::{JByteArray, JClass, JString};
use jni::sys::{jboolean, jbyteArray, jlong, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

// C-1: opaque handles are generation-checked registry tokens, not raw `Box`
// pointers — a stale/double handle is rejected, never dereferenced. The token is
// still a `jlong`, so the Kotlin side (`com.qeli.RealTls` / `MlKem`) is unchanged.
static REALTLS: Registry<SansIoClient> = Registry::new();
static MLKEM: Registry<MlKemKeypair> = Registry::new();

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
    REALTLS.insert(client) as jlong
}

/// `RealTls.nativeClientHello(handle) -> byte[]` — the ClientHello to send first.
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeClientHello<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    match REALTLS.with(handle as u64, |client| client.client_hello().to_vec()) {
        Some(hello) => to_array(&mut env, &hello),
        None => std::ptr::null_mut(),
    }
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
    let bytes = env.convert_byte_array(&data).unwrap_or_default();
    match REALTLS.with(handle as u64, |client| client.recv(&bytes)) {
        Some(Ok(Progress::NeedMore)) => to_array(&mut env, &[]),
        Some(Ok(Progress::Done(to_send))) => to_array(&mut env, &to_send),
        Some(Err(_)) | None => std::ptr::null_mut(), // None = stale/invalid handle
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
    let bytes = env.convert_byte_array(&data).unwrap_or_default();
    match REALTLS.with(handle as u64, |client| client.seal(&bytes)) {
        Some(Ok(rec)) => to_array(&mut env, &rec),
        Some(Err(_)) | None => std::ptr::null_mut(), // None = stale/invalid handle
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
    let bytes = env.convert_byte_array(&data).unwrap_or_default();
    let result = REALTLS.with(handle as u64, |client| {
        client.open_push(&bytes).map(|msgs| {
            let mut cat = Vec::new();
            for m in msgs {
                cat.extend_from_slice(&m);
            }
            cat
        })
    });
    match result {
        Some(Ok(cat)) => to_array(&mut env, &cat),
        Some(Err(_)) | None => std::ptr::null_mut(), // None = stale/invalid handle
    }
}

/// `RealTls.nativeEstablished(handle) -> boolean`.
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeEstablished<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jboolean {
    match REALTLS.with(handle as u64, |client| client.established()) {
        Some(true) => JNI_TRUE,
        _ => JNI_FALSE, // false, or a stale/invalid handle
    }
}

/// `RealTls.nativeFree(handle)`.
#[no_mangle]
pub extern "system" fn Java_com_qeli_RealTls_nativeFree<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    // A double free or a free of a never-issued handle is a safe no-op (C-1).
    REALTLS.remove(handle as u64);
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
    MLKEM.insert(MlKemKeypair { dk, ek }) as jlong
}

/// `MlKem.nativeEncapKey(handle) -> byte[]` — the 1184-byte encapsulation key to
/// carry in the ClientHello key_share (null on a bad handle).
#[no_mangle]
pub extern "system" fn Java_com_qeli_MlKem_nativeEncapKey<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) -> jbyteArray {
    match MLKEM.with(handle as u64, |kp| kp.ek.clone()) {
        Some(ek) => to_array(&mut env, &ek),
        None => std::ptr::null_mut(),
    }
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
    let ct_bytes = env.convert_byte_array(&ct).unwrap_or_default();
    let result = MLKEM.with(handle as u64, |kp| {
        crate::crypto::mlkem::mlkem768_decapsulate(&kp.dk, &ct_bytes)
    });
    match result {
        Some(Some(ss)) => to_array(&mut env, &ss),
        // inner None = bad ciphertext; outer None = stale/invalid handle
        Some(None) | None => std::ptr::null_mut(),
    }
}

/// `MlKem.nativeFree(handle)`.
#[no_mangle]
pub extern "system" fn Java_com_qeli_MlKem_nativeFree<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    handle: jlong,
) {
    // A double free or a free of a never-issued handle is a safe no-op (C-1).
    MLKEM.remove(handle as u64);
}
