//! Best-effort overwriting of key material held by this crate.

use core::sync::atomic::{Ordering, compiler_fence};

/// Overwrites `bytes` with zeros in a way the compiler does not elide.
///
/// This covers buffers owned by this crate only; key handles created by a
/// backend are the backend's responsibility.
pub(crate) fn wipe(bytes: &mut [u8]) {
    for byte in bytes.iter_mut() {
        // SAFETY: `byte` is a valid, aligned, exclusive reference.
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}
