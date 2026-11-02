//! OS-facing Software Device callback bridge for the managed Windows hosts.
//!
//! SwDeviceCreate retains the native module containing its callback using
//! GetModuleHandleExW(FROM_ADDRESS). A CLR delegate thunk lives outside a loaded
//! PE image and fails that lookup with ERROR_MOD_NOT_FOUND. Keep the OS callback
//! in this DLL; only the forwarding target may be a managed delegate.

use std::ffi::c_void;
use std::panic::catch_unwind;
use std::sync::OnceLock;

type Created = unsafe extern "system" fn(*mut c_void, i32, *mut c_void, *const u16);

// The Windows runtime roots its delegate and maps qeli.dll for the process lifetime.
// Never replace the target: an in-flight/late OS callback must keep its original host.
static FORWARD: OnceLock<Created> = OnceLock::new();

unsafe extern "system" fn on_created(
    device: *mut c_void,
    result: i32,
    context: *mut c_void,
    instance: *const u16,
) {
    if let Some(forward) = FORWARD.get() {
        // No allocation, owned context pointer or fallible Rust operation. The
        // managed boundary catches exceptions and ignores expired numeric contexts.
        unsafe { forward(device, result, context, instance) };
    }
}

/// Register one process-lifetime forwarding target and return the native callback.
/// Null or replacement registrations fail closed. No device is created here.
///
/// # Safety
/// `forward` must remain callable for the lifetime of this loaded DLL, use the
/// system calling convention, and never unwind/throw across the native boundary.
#[no_mangle]
pub unsafe extern "C" fn qeli_windows_swdevice_callback_address(
    forward: Option<Created>,
) -> Option<Created> {
    // Match the core's FFI panic contract even if registration grows later.
    catch_unwind(|| {
        let forward = forward?;
        let registered = FORWARD.get_or_init(|| forward);
        if *registered as usize != forward as usize {
            return None;
        }
        Some(on_created as Created)
    })
    .unwrap_or(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    unsafe extern "system" fn receive(d: *mut c_void, r: i32, c: *mut c_void, s: *const u16) {
        assert_eq!(d as usize, 11);
        assert_eq!(r, -7);
        assert_eq!(c as usize, 23);
        assert_eq!(s as usize, 31);
        CALLS.fetch_add(1, Ordering::SeqCst);
    }
    unsafe extern "system" fn other(_: *mut c_void, _: i32, _: *mut c_void, _: *const u16) {}

    #[test]
    fn bridge_is_stable_forwards_exact_arguments_and_refuses_replacement() {
        unsafe {
            assert!(qeli_windows_swdevice_callback_address(None).is_none());
            let callback = qeli_windows_swdevice_callback_address(Some(receive)).unwrap();
            assert_ne!(callback as usize, receive as *const () as usize);
            assert_eq!(
                qeli_windows_swdevice_callback_address(Some(receive)).unwrap() as usize,
                callback as usize
            );
            assert!(qeli_windows_swdevice_callback_address(Some(other)).is_none());
            callback(11usize as _, -7, 23usize as _, 31usize as _);
            assert_eq!(CALLS.load(Ordering::SeqCst), 1);
        }
    }
}
