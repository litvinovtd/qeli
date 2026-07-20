//! C-1 — a generation-tagged handle registry for the FFI/JNI boundary.
//!
//! The C ABI ([`super::ffi`]) and JNI bridge ([`super::jni`]) used to hand the
//! managed caller a raw `Box::into_raw` pointer and blindly `&*` it back. A buggy
//! caller (a double `free`, or using a handle after `free`) therefore caused
//! undefined behaviour — a use-after-free or double-free in native memory.
//!
//! This registry replaces the raw pointer with an **opaque token** that encodes a
//! slot index plus a per-slot *generation* counter: `(generation << 32) | index`.
//! Freeing a handle bumps the slot's generation, so any later use of the stale
//! token fails the generation check and is rejected (returns `None` / an error)
//! instead of dereferencing freed memory. The token is still pointer-width, so the
//! managed side keeps passing it as an opaque `IntPtr` / `jlong` — **no C#/Kotlin
//! change and no ABI change**; only the bytes' meaning changed (a key, not a ptr).
//!
//! Thread-safety is a single `Mutex`. The realtls/ML-KEM FFI is driven by a
//! single-tunnel client on one thread, so holding the lock across an operation is
//! uncontended; if a multi-tunnel use ever appears, a slot would become an
//! `Arc<Mutex<T>>` looked up under a brief registry lock.

use std::sync::Mutex;

struct Slot<T> {
    value: Option<Box<T>>,
    /// Bumped on every free; starts at 1 so a live handle is never `0` (which the
    /// FFI treats as null). Wraps to 1 (never 0) on the astronomically-unlikely
    /// 2^32-reuse of one slot.
    generation: u32,
}

/// A registry of `T` values addressed by opaque, generation-checked handles.
pub struct Registry<T> {
    slots: Mutex<Vec<Slot<T>>>,
}

/// The handle is a packed `u64` (generation << 32 | index), and the FFI hands it to the
/// caller **as a pointer** (`handle as *mut T`). That only round-trips where a pointer is
/// at least 64 bits wide: on a 32-bit target the cast drops the generation half, so the
/// very first handle — generation 1, index 0 — truncates to 0, which the FFI reads as
/// null. Every shipped target today is 64-bit (x86_64/aarch64 desktop, arm64 Android and
/// iOS), so this is latent rather than broken — but a future armv7/watchOS target would
/// hit it as a mysterious "the library returns null immediately". Refuse to build there
/// instead: a compile error names the problem, a silent truncation does not.
const _: () = assert!(
    std::mem::size_of::<usize>() >= std::mem::size_of::<u64>(),
    "realtls FFI handles are u64 passed as pointers — a 32-bit target would truncate the      generation half and turn a valid handle into null. Return the u64 directly (an ABI      change in the C#/Kotlin bindings) before targeting 32-bit."
);

#[inline]
fn pack(generation: u32, index: u32) -> u64 {
    ((generation as u64) << 32) | (index as u64)
}

#[inline]
fn unpack(handle: u64) -> (u32, u32) {
    ((handle >> 32) as u32, (handle & 0xFFFF_FFFF) as u32)
}

#[inline]
fn bump(generation: u32) -> u32 {
    match generation.wrapping_add(1) {
        0 => 1, // never hand out generation 0 (a 0 handle is "null")
        g => g,
    }
}

impl<T> Registry<T> {
    pub const fn new() -> Self {
        Registry {
            slots: Mutex::new(Vec::new()),
        }
    }

    /// Store `value` and return a non-zero opaque handle for it. Reuses a freed
    /// slot when one is available, otherwise grows the table.
    pub fn insert(&self, value: T) -> u64 {
        let mut slots = self.lock();
        if let Some(index) = slots.iter().position(|s| s.value.is_none()) {
            slots[index].value = Some(Box::new(value));
            return pack(slots[index].generation, index as u32);
        }
        let index = slots.len() as u32;
        slots.push(Slot {
            value: Some(Box::new(value)),
            generation: 1,
        });
        pack(1, index)
    }

    /// Run `f` against the live value for `handle`, or return `None` when the
    /// handle is stale / freed / never issued (so the caller fails cleanly instead
    /// of touching freed memory). If `f` panics the slot is invalidated
    /// (poison-on-panic) — a half-mutated object can't be observed by a later
    /// call — and `None` is returned; the lock is released either way.
    pub fn with<R>(&self, handle: u64, f: impl FnOnce(&mut T) -> R) -> Option<R> {
        let (generation, index) = unpack(handle);
        let mut slots = self.lock();
        let slot = slots.get_mut(index as usize)?;
        if slot.generation != generation || slot.value.is_none() {
            return None;
        }
        let value = slot.value.as_mut().unwrap();
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| f(value))) {
            Ok(r) => Some(r),
            Err(_) => {
                // The closure unwound mid-operation: drop the (possibly
                // inconsistent) object and burn the generation so this handle is
                // dead. Returning None surfaces a clean FFI error.
                slot.value = None;
                slot.generation = bump(slot.generation);
                None
            }
        }
    }

    /// Drop the value behind `handle`. Returns `true` if it was live, `false` for a
    /// stale / double / never-issued handle (a no-op — NOT a double-free).
    pub fn remove(&self, handle: u64) -> bool {
        let (generation, index) = unpack(handle);
        let mut slots = self.lock();
        let Some(slot) = slots.get_mut(index as usize) else {
            return false;
        };
        if slot.generation != generation || slot.value.is_none() {
            return false;
        }
        slot.value = None;
        slot.generation = bump(slot.generation);
        true
    }

    /// Lock, recovering the data on poison (a panic elsewhere must not wedge every
    /// later FFI call — `with` already neutralizes the offending slot).
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Slot<T>>> {
        self.slots.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl<T> Default for Registry<T> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_handles_are_nonzero_and_distinct() {
        let r: Registry<u32> = Registry::new();
        let a = r.insert(10);
        let b = r.insert(20);
        assert_ne!(a, 0, "a live handle is never the null token 0");
        assert_ne!(b, 0);
        assert_ne!(a, b, "distinct objects get distinct handles");
        assert_eq!(r.with(a, |v| *v), Some(10));
        assert_eq!(r.with(b, |v| *v), Some(20));
    }

    #[test]
    fn with_mutates_in_place() {
        let r: Registry<u32> = Registry::new();
        let h = r.insert(1);
        r.with(h, |v| *v += 41);
        assert_eq!(r.with(h, |v| *v), Some(42));
    }

    #[test]
    fn stale_handle_after_free_is_rejected() {
        let r: Registry<u32> = Registry::new();
        let h = r.insert(7);
        assert!(r.remove(h), "first free succeeds");
        // Use-after-free: rejected, not UB.
        assert_eq!(r.with(h, |v| *v), None);
        // Double-free: a no-op, not a double Box::from_raw.
        assert!(!r.remove(h));
    }

    #[test]
    fn reused_slot_does_not_alias_old_handle() {
        let r: Registry<u32> = Registry::new();
        let h1 = r.insert(100);
        assert!(r.remove(h1));
        // Re-inserting reuses slot 0 with a bumped generation → a NEW handle that
        // the old (freed) handle must not be able to address.
        let h2 = r.insert(200);
        assert_ne!(h1, h2, "the reused slot yields a fresh generation");
        assert_eq!(r.with(h2, |v| *v), Some(200));
        assert_eq!(r.with(h1, |v| *v), None, "the stale handle stays dead");
    }

    #[test]
    fn never_issued_and_null_handles_are_rejected() {
        let r: Registry<u32> = Registry::new();
        assert_eq!(r.with(0, |v| *v), None, "null token");
        assert_eq!(
            r.with(0xDEAD_BEEF_0000_0001, |v| *v),
            None,
            "out-of-range index"
        );
        assert!(!r.remove(0));
    }

    #[test]
    fn panic_in_closure_poisons_only_that_slot() {
        let r: Registry<u32> = Registry::new();
        let bad = r.insert(1);
        let good = r.insert(2);
        // A panicking operation returns None and burns the slot...
        let caught = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            r.with(bad, |_| panic!("boom"))
        }));
        assert!(
            caught.is_ok(),
            "with() swallows the panic, so the FFI never unwinds"
        );
        assert_eq!(caught.unwrap(), None::<()>);
        // ...the bad handle is now dead...
        assert_eq!(r.with(bad, |v| *v), None);
        // ...but the registry and other handles keep working (no mutex poison).
        assert_eq!(r.with(good, |v| *v), Some(2));
        let fresh = r.insert(3);
        assert_eq!(r.with(fresh, |v| *v), Some(3));
    }
}
