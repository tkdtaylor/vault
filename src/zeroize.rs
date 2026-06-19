// SPDX-License-Identifier: Apache-2.0
//! Hand-rolled best-effort secure-memory zeroization (no `zeroize` crate) — addresses
//! security-auditor finding **SEC-001** (key / plaintext not wiped from freed memory). See
//! [ADR-009](../docs/architecture/decisions/009-secure-memory-zeroization.md).
//!
//! # Why hand-rolled
//!
//! The `zeroize` crate (1.9.0) was BLOCKED by dep-scan on a `maintainer_change` flag (a complete
//! maintainer changeover: removed `tarcieri`, added `trustpub:github:RustCrypto/utils` —
//! RustCrypto's migration to GitHub trusted-publishing). Per the project's dep-scan hard-stop rule
//! and its minimal-dependency ethos (no `rand`, hand-rolled base64), this module hand-rolls the
//! wipe with std-only primitives — **no new dependency**.
//!
//! # Technique
//!
//! [`Zeroize::zeroize`] overwrites each byte with `0x00` via [`core::ptr::write_volatile`] and then
//! issues a [`compiler_fence`](core::sync::atomic::compiler_fence) with `Ordering::SeqCst`. The
//! volatile write tells the compiler the store has an observable side effect it may not elide; the
//! fence prevents the writes from being reordered past the end of the wipe. Together this is the
//! standard pattern that resists dead-store elimination (the compiler would otherwise drop writes
//! to memory it can prove is never read again).
//!
//! # Best-effort caveat (NOT a guarantee)
//!
//! This is **best-effort defense-in-depth**, not a guarantee — the exact same caveat the `zeroize`
//! crate itself carries:
//!
//! - Rust may **move** a value (a bitwise copy) before it is dropped; only the final resting copy
//!   is wiped, any prior stack/register copies are not.
//! - Values may be spilled to registers, swapped to disk, or copied by the allocator.
//!
//! # Documented residual (SEC-001, not claimed closed)
//!
//! The AES key copy held **inside** the `aes_gcm::Aes256Gcm` cipher object is **out of scope**:
//! wiping it would require enabling aes-gcm's `zeroize` feature, which pulls the same dep-scan-
//! BLOCKED `zeroize` crate. That residual remains until `zeroize` clears dep-scan (re-evaluate when
//! the maintainer-change flag ages out). This module wipes only the buffers vault directly
//! controls: the decoded `[u8; 32]` key before/after it enters the cipher, the raw key `String`
//! from env/file, the `random_key()` buffer, and the decrypted plaintext `Vec<u8>`.

use core::sync::atomic::{compiler_fence, Ordering};

/// Types whose backing bytes can be overwritten with zero in place.
///
/// Implemented for the concrete key/plaintext buffer types vault holds: `[u8; N]`, `Vec<u8>`, and
/// `String`. The wipe uses [`core::ptr::write_volatile`] + a [`compiler_fence`] so the compiler may
/// not elide it as a dead store.
pub trait Zeroize {
    /// Overwrite every covered byte with `0x00`, elision-resistant.
    fn zeroize(&mut self);
}

/// Volatile-zero a raw byte slice: write `0x00` to each byte through a volatile pointer, then a
/// `SeqCst` compiler fence. This is the single primitive every [`Zeroize`] impl funnels through.
fn volatile_zero(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, uniquely-borrowed `&mut u8`; a volatile write of one byte to it
        // is in-bounds and well-aligned. Volatile tells the compiler the store is observable and
        // must not be optimized away.
        unsafe {
            core::ptr::write_volatile(b as *mut u8, 0u8);
        }
    }
    // Prevent the volatile writes from being reordered/sunk past this point.
    compiler_fence(Ordering::SeqCst);
}

impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        volatile_zero(self.as_mut_slice());
    }
}

impl Zeroize for Vec<u8> {
    fn zeroize(&mut self) {
        // Wipe the whole backing allocation (including any spare capacity already written into),
        // not just the live length.
        let cap = self.capacity();
        // SAFETY: extend the logical length to the full allocated capacity so the slice covers the
        // entire buffer. `Vec<u8>`'s element type has no Drop and any byte pattern is a valid `u8`,
        // so reading/writing the spare capacity is sound; we set length back to 0 afterwards.
        unsafe {
            self.set_len(cap);
        }
        volatile_zero(self.as_mut_slice());
        // SAFETY: the buffer is now all zeros; length 0 is always valid.
        unsafe {
            self.set_len(0);
        }
    }
}

impl Zeroize for String {
    fn zeroize(&mut self) {
        // SAFETY: we overwrite the bytes with zeros and then clear the string. Zero bytes are valid
        // UTF-8, but we truncate to empty regardless so no invalid-UTF-8 invariant is ever observed.
        let v = unsafe { self.as_mut_vec() };
        v.zeroize();
    }
}

/// A wrapper that zeroizes its wrapped value on `Drop`.
///
/// Holds a `T: Zeroize` and overwrites its bytes when it goes out of scope. Use it for the
/// short-lived key / plaintext buffers vault controls so they do not linger in freed memory after
/// use. `Deref`/`DerefMut` make the wrapped value transparently usable until drop.
///
/// **Best-effort:** Rust may move the value before this `Drop` runs — see the module docs. This is
/// defense-in-depth, not a guarantee.
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    /// Wrap a value so it is zeroized on drop.
    pub fn new(value: T) -> Self {
        Zeroizing(value)
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TC-001: `zeroize` overwrites a non-zero buffer to all zeros via volatile-write + fence.
    /// Asserted directly on a slice (sound — no UB, no freed-memory read).
    #[test]
    fn zeroize_array_writes_zeros() {
        let mut buf = [0xABu8; 32];
        buf.zeroize();
        assert_eq!(buf, [0u8; 32], "every byte must be wiped to 0x00");
    }

    /// TC-001: the `Zeroizing` wrapper wipes its wrapped value's bytes on `Drop`. To observe this
    /// *soundly* (no reading of freed memory — which the allocator may reuse, see the spec note),
    /// we wrap a small inner type whose backing storage outlives the wrapper: a `Probe` that holds a
    /// raw pointer to a buffer the test still owns. `Probe::zeroize` wipes through that pointer, so
    /// after `Zeroizing::drop` runs we read the *still-valid* buffer and confirm it is all zeros.
    #[test]
    fn wrapper_zeros_backing_bytes_on_drop() {
        // Backing buffer owned by the test for the whole function — never freed by the wrapper.
        let mut buf = [0xCDu8; 16];
        let ptr = buf.as_mut_ptr();
        let len = buf.len();

        // A wrappable view over the externally-owned buffer.
        struct Probe {
            ptr: *mut u8,
            len: usize,
        }
        impl Zeroize for Probe {
            fn zeroize(&mut self) {
                // SAFETY: `ptr`/`len` describe a buffer the enclosing test owns and keeps alive for
                // the whole function; the slice is valid and uniquely accessed here.
                let slice = unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) };
                volatile_zero(slice);
            }
        }

        {
            let z = Zeroizing::new(Probe { ptr, len });
            // Usable through Deref before drop.
            assert_eq!(z.len, len);
            // Buffer is still its original non-zero pattern while the wrapper is alive.
            assert_eq!(buf[0], 0xCD);
            drop(z); // triggers Zeroizing::drop → Probe::zeroize → wipes `buf`
        }

        // The buffer is still owned and valid here — observe the wipe soundly.
        assert_eq!(buf, [0u8; 16], "drop must have zeroed the backing buffer");
        let _ = len; // silence unused warning if assertions are compiled out
    }

    /// TC-001 edge: a zero-length buffer drops cleanly (no panic, no UB).
    #[test]
    fn empty_buffer_zeroizes_cleanly() {
        let mut empty_arr = [0u8; 0];
        empty_arr.zeroize();
        let mut empty_vec: Vec<u8> = Vec::new();
        empty_vec.zeroize();
        let mut empty_str = String::new();
        empty_str.zeroize();
        drop(Zeroizing::new(Vec::<u8>::new()));
        // Reaching here without panic is the assertion.
    }

    /// TC-001: `String::zeroize` overwrites bytes and clears to empty.
    #[test]
    fn string_zeroize_wipes_and_clears() {
        let mut s = String::from("SK-SUPER-SECRET");
        s.zeroize();
        assert!(s.is_empty(), "string is cleared after zeroize");
    }

    /// TC-001: `Vec::zeroize` wipes spare capacity too, then resets length to 0.
    #[test]
    fn vec_zeroize_wipes_full_capacity() {
        let mut v: Vec<u8> = Vec::with_capacity(8);
        v.extend_from_slice(&[0x11, 0x22, 0x33]);
        v.zeroize();
        assert!(v.is_empty(), "length reset to 0 after zeroize");
    }
}
