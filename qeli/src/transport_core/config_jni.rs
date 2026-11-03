//! Portable JNI seam: host JVM conformance executes the same Rust code as Android.
use jni::{
    objects::{JByteArray, JClass},
    sys::jbyteArray,
    JNIEnv,
};
#[no_mangle]
pub extern "system" fn Java_com_qeli_ConfigCore_nativeRequest(
    mut env: JNIEnv,
    _: JClass,
    input: JByteArray,
) -> jbyteArray {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let length = env.get_array_length(&input).ok()? as usize;
        if length > crate::config::editor::MAX_REQUEST {
            return None;
        }
        let bytes = zeroize::Zeroizing::new(env.convert_byte_array(input).ok()?);
        let response = zeroize::Zeroizing::new(crate::config::editor::request(&bytes));
        env.byte_array_from_slice(&response)
            .ok()
            .map(|a| a.into_raw())
    }));
    result.ok().flatten().unwrap_or_else(|| {
        let _ = env.throw_new(
            "java/lang/IllegalArgumentException",
            "native configuration request failed",
        );
        std::ptr::null_mut()
    })
}
