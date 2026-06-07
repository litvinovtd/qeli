//! A2 — C ABI over the sans-IO realtls core ([`super::sansio::SansIoClient`]).
//!
//! This is the boundary the Android (JNI) and Windows (P/Invoke) clients call.
//! All functions are `extern "C"`, exchange bytes as `ptr + len`, return owned
//! buffers the caller frees with [`qeli_realtls_buf_free`], and never unwind
//! across the boundary. Build as a `cdylib` (A3) to export the symbols.
//!
//! Lifecycle: [`qeli_realtls_new`] → send the ClientHello → feed server bytes to
//! [`qeli_realtls_recv`] until it returns `1` (Done; send its output) → then
//! [`qeli_realtls_seal`] / [`qeli_realtls_open`] for application data →
//! [`qeli_realtls_free`].

use super::sansio::{Progress, SansIoClient};
use crate::crypto::reality::SHORT_ID_LEN;
use crate::crypto::PublicKey;
use std::os::raw::c_char;
use std::panic::{catch_unwind, AssertUnwindSafe};

/// Hand a `Vec<u8>` to C as `ptr + len`. Empty vectors yield `(null, 0)`. The
/// caller frees a non-null pointer with [`qeli_realtls_buf_free`].
unsafe fn vec_to_c(v: Vec<u8>, out: *mut *mut u8, out_len: *mut usize) {
    if v.is_empty() {
        *out = std::ptr::null_mut();
        *out_len = 0;
        return;
    }
    let boxed = v.into_boxed_slice();
    let len = boxed.len();
    *out = Box::into_raw(boxed) as *mut u8;
    *out_len = len;
}

/// Free a buffer returned by a `qeli_realtls_*` function.
///
/// # Safety
/// `ptr`/`len` must be exactly what a `qeli_realtls_*` call wrote (or `ptr` null).
#[no_mangle]
pub unsafe extern "C" fn qeli_realtls_buf_free(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len != 0 {
        let _ = Box::from_raw(std::ptr::slice_from_raw_parts_mut(ptr, len));
    }
}

/// Start a handshake. Returns an opaque handle (or null on error) and writes the
/// ClientHello to `*out_hello` / `*out_hello_len`.
///
/// # Safety
/// `reality_pub` must point to 32 bytes, `short_id` to 8 bytes, `sni` to a
/// NUL-terminated UTF-8 string; the out-pointers must be non-null and writable.
#[no_mangle]
pub unsafe extern "C" fn qeli_realtls_new(
    reality_pub: *const u8,
    short_id: *const u8,
    sni: *const c_char,
    out_hello: *mut *mut u8,
    out_hello_len: *mut usize,
) -> *mut SansIoClient {
    catch_unwind(AssertUnwindSafe(|| {
        if reality_pub.is_null()
            || short_id.is_null()
            || sni.is_null()
            || out_hello.is_null()
            || out_hello_len.is_null()
        {
            return std::ptr::null_mut();
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(std::slice::from_raw_parts(reality_pub, 32));
        let mut sid = [0u8; SHORT_ID_LEN];
        sid.copy_from_slice(std::slice::from_raw_parts(short_id, SHORT_ID_LEN));
        let sni_str = match std::ffi::CStr::from_ptr(sni).to_str() {
            Ok(s) => s,
            Err(_) => return std::ptr::null_mut(),
        };
        let (client, hello) = SansIoClient::new(&PublicKey::from_bytes(&pk), &sid, sni_str);
        vec_to_c(hello, out_hello, out_hello_len);
        Box::into_raw(Box::new(client))
    }))
    .unwrap_or(std::ptr::null_mut())
}

/// Feed inbound server bytes. Returns `0` (need more), `1` (handshake done — send
/// `*out`), or `-1` (error).
///
/// # Safety
/// `handle` must come from [`qeli_realtls_new`]; `data`/`len` describe a readable
/// buffer (or `data` null with `len` 0); out-pointers must be writable.
#[no_mangle]
pub unsafe extern "C" fn qeli_realtls_recv(
    handle: *mut SansIoClient,
    data: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out.is_null() || out_len.is_null() {
            return -1;
        }
        *out = std::ptr::null_mut();
        *out_len = 0;
        let client = &mut *handle;
        let input: &[u8] = if data.is_null() || len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(data, len)
        };
        match client.recv(input) {
            Ok(Progress::NeedMore) => 0,
            Ok(Progress::Done(to_send)) => {
                vec_to_c(to_send, out, out_len);
                1
            }
            Err(_) => -1,
        }
    }))
    .unwrap_or(-1)
}

/// Frame application data as one TLS record (only after `recv` returned `1`).
/// Returns `0` (ok — record in `*out`) or `-1`.
///
/// # Safety
/// As [`qeli_realtls_recv`].
#[no_mangle]
pub unsafe extern "C" fn qeli_realtls_seal(
    handle: *mut SansIoClient,
    data: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out.is_null() || out_len.is_null() {
            return -1;
        }
        *out = std::ptr::null_mut();
        *out_len = 0;
        let client = &mut *handle;
        let input: &[u8] = if data.is_null() || len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(data, len)
        };
        match client.seal(input) {
            Ok(rec) => {
                vec_to_c(rec, out, out_len);
                0
            }
            Err(_) => -1,
        }
    }))
    .unwrap_or(-1)
}

/// Feed inbound application bytes; writes the concatenated decrypted plaintext to
/// `*out` (empty ⇒ `(null, 0)`). Returns `0` (ok) or `-1`.
///
/// # Safety
/// As [`qeli_realtls_recv`].
#[no_mangle]
pub unsafe extern "C" fn qeli_realtls_open(
    handle: *mut SansIoClient,
    data: *const u8,
    len: usize,
    out: *mut *mut u8,
    out_len: *mut usize,
) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if handle.is_null() || out.is_null() || out_len.is_null() {
            return -1;
        }
        *out = std::ptr::null_mut();
        *out_len = 0;
        let client = &mut *handle;
        let input: &[u8] = if data.is_null() || len == 0 {
            &[]
        } else {
            std::slice::from_raw_parts(data, len)
        };
        match client.open_push(input) {
            Ok(msgs) => {
                let mut cat = Vec::new();
                for m in msgs {
                    cat.extend_from_slice(&m);
                }
                vec_to_c(cat, out, out_len);
                0
            }
            Err(_) => -1,
        }
    }))
    .unwrap_or(-1)
}

/// Destroy a handle from [`qeli_realtls_new`].
///
/// # Safety
/// `handle` must come from [`qeli_realtls_new`] and not be used afterwards.
#[no_mangle]
pub unsafe extern "C" fn qeli_realtls_free(handle: *mut SansIoClient) {
    if !handle.is_null() {
        let _ = Box::from_raw(handle);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::reality::short_id_from_hex;
    use crate::crypto::StaticKeypair;
    use crate::protocol::realtls::server::{make_server_config, terminate};
    use std::ffi::CString;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Drive a full handshake + app exchange against a real rustls server using
    /// only the C ABI — exactly the call sequence the JNI/P-Invoke bridge makes.
    #[tokio::test]
    async fn ffi_interop_with_rustls() {
        let (mut io, server_io) = tokio::io::duplex(32 * 1024);
        let config = make_server_config("www.microsoft.com");
        let server = tokio::spawn(async move {
            let mut tls = terminate(Vec::new(), server_io, config).await.unwrap();
            let mut buf = [0u8; 4];
            tls.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"ping");
            tls.write_all(b"pong").await.unwrap();
            tls.flush().await.unwrap();
        });

        let reality = StaticKeypair::generate();
        let sid = short_id_from_hex("0123456789abcdef");
        let sni = CString::new("www.microsoft.com").unwrap();

        let mut hp: *mut u8 = std::ptr::null_mut();
        let mut hl: usize = 0;
        let h = unsafe {
            qeli_realtls_new(
                reality.public.as_bytes().as_ptr(),
                sid.as_ptr(),
                sni.as_ptr(),
                &mut hp,
                &mut hl,
            )
        };
        assert!(!h.is_null());
        let hello = unsafe { std::slice::from_raw_parts(hp, hl).to_vec() };
        unsafe { qeli_realtls_buf_free(hp, hl) };
        io.write_all(&hello).await.unwrap();
        io.flush().await.unwrap();

        // Drive the handshake through the C ABI.
        let mut rbuf = [0u8; 4096];
        loop {
            let n = io.read(&mut rbuf).await.unwrap();
            assert!(n > 0, "unexpected EOF");
            let mut op: *mut u8 = std::ptr::null_mut();
            let mut ol: usize = 0;
            let st = unsafe { qeli_realtls_recv(h, rbuf.as_ptr(), n, &mut op, &mut ol) };
            assert!(st >= 0, "recv error");
            if st == 1 {
                let to_send = unsafe { std::slice::from_raw_parts(op, ol).to_vec() };
                unsafe { qeli_realtls_buf_free(op, ol) };
                io.write_all(&to_send).await.unwrap();
                io.flush().await.unwrap();
                break;
            }
        }

        // seal("ping") through the ABI.
        let mut op: *mut u8 = std::ptr::null_mut();
        let mut ol: usize = 0;
        assert_eq!(
            unsafe { qeli_realtls_seal(h, b"ping".as_ptr(), 4, &mut op, &mut ol) },
            0
        );
        let rec = unsafe { std::slice::from_raw_parts(op, ol).to_vec() };
        unsafe { qeli_realtls_buf_free(op, ol) };
        io.write_all(&rec).await.unwrap();
        io.flush().await.unwrap();

        // open() until "pong".
        let pong = loop {
            let n = io.read(&mut rbuf).await.unwrap();
            assert!(n > 0, "unexpected EOF awaiting reply");
            let mut op: *mut u8 = std::ptr::null_mut();
            let mut ol: usize = 0;
            assert_eq!(
                unsafe { qeli_realtls_open(h, rbuf.as_ptr(), n, &mut op, &mut ol) },
                0
            );
            if ol > 0 {
                let pt = unsafe { std::slice::from_raw_parts(op, ol).to_vec() };
                unsafe { qeli_realtls_buf_free(op, ol) };
                break pt;
            }
        };
        assert_eq!(pong, b"pong");

        unsafe { qeli_realtls_free(h) };
        server.await.unwrap();
    }
}
