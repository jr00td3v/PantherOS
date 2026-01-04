//! Secure Memory Zeroization
//!
//! Implements secure zeroization of sensitive data to prevent:
//! - Cold boot attacks (reading memory after power loss)
//! - Memory disclosure via vulnerabilities
//! - Secrets remaining in freed memory
//!
//! # Design
//! - `Zeroize` trait for types that can be securely cleared
//! - `SecureWrapper<T>` RAII type that zeros on drop
//! - Volatile writes prevent compiler optimization of zeroing

use core::ptr;
use core::sync::atomic::{compiler_fence, Ordering};

/// Trait for types that can be securely zeroed.
///
/// Implementations must ensure that all secret data is overwritten
/// with zeros in a way that cannot be optimized away.
pub trait Zeroize {
    /// Overwrite this value with zeros.
    ///
    /// This operation is guaranteed to not be optimized away.
    fn zeroize(&mut self);
}

/// Zeroize implementation for byte slices.
impl Zeroize for [u8] {
    fn zeroize(&mut self) {
        // Use volatile_set_memory to prevent optimization
        // SAFETY: We have a valid mutable reference to the slice
        unsafe {
            volatile_set_memory(self.as_mut_ptr(), 0, self.len());
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Zeroize implementation for fixed-size byte arrays.
impl<const N: usize> Zeroize for [u8; N] {
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

/// Zeroize implementation for u64.
impl Zeroize for u64 {
    fn zeroize(&mut self) {
        unsafe {
            ptr::write_volatile(self, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Zeroize implementation for u32.
impl Zeroize for u32 {
    fn zeroize(&mut self) {
        unsafe {
            ptr::write_volatile(self, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// Zeroize implementation for usize.
impl Zeroize for usize {
    fn zeroize(&mut self) {
        unsafe {
            ptr::write_volatile(self, 0);
        }
        compiler_fence(Ordering::SeqCst);
    }
}

/// A wrapper that securely zeroizes its contents on drop.
///
/// Use this to wrap sensitive data like:
/// - Cryptographic keys
/// - Passwords
/// - Session tokens
///
/// # Example
/// ```no_run
/// let secret = SecureWrapper::new([0x42u8; 32]);
/// // Use secret.inner()...
/// // When `secret` goes out of scope, it's automatically zeroed
/// ```
///
/// # Security Properties
/// - Contents are zeroed using volatile writes
/// - Zeroing cannot be optimized away
/// - Drop is called even on panic (in most cases)
#[derive(Debug)]
pub struct SecureWrapper<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> SecureWrapper<T> {
    /// Create a new secure wrapper around sensitive data.
    #[inline]
    pub fn new(value: T) -> Self {
        Self { inner: value }
    }

    /// Get an immutable reference to the inner value.
    #[inline]
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Get a mutable reference to the inner value.
    #[inline]
    pub fn inner_mut(&mut self) -> &mut T {
        &mut self.inner
    }

    /// Consume the wrapper and return the inner value.
    ///
    /// **WARNING**: The returned value will NOT be automatically zeroed.
    /// Use this only when transferring ownership to another secure context.
    #[inline]
    pub fn into_inner(self) -> T {
        // Prevent drop from being called
        let inner = unsafe { ptr::read(&self.inner) };
        core::mem::forget(self);
        inner
    }
}

impl<T: Zeroize> Drop for SecureWrapper<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<T: Zeroize + Default> Default for SecureWrapper<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: Zeroize + Clone> Clone for SecureWrapper<T> {
    fn clone(&self) -> Self {
        Self::new(self.inner.clone())
    }
}

/// Volatile memset that cannot be optimized away.
///
/// # Safety
/// - `dst` must be valid for writes of `count` bytes
/// - `dst` must be properly aligned
#[inline]
unsafe fn volatile_set_memory(dst: *mut u8, val: u8, count: usize) {
    for i in 0..count {
        // SAFETY: Caller guarantees dst is valid for count bytes
        unsafe {
            ptr::write_volatile(dst.add(i), val);
        }
    }
}

/// A type alias for a secure 256-bit key.
pub type SecureKey256 = SecureWrapper<[u8; 32]>;

/// A type alias for a secure 128-bit key.
pub type SecureKey128 = SecureWrapper<[u8; 16]>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zeroize_slice() {
        let mut data = [0x42u8; 16];
        data.zeroize();
        assert!(data.iter().all(|&b| b == 0));
    }

    #[test]
    fn test_secure_wrapper_drop() {
        let mut wrapper = SecureWrapper::new([0x42u8; 32]);
        // Modify to ensure it's not optimized
        wrapper.inner_mut()[0] = 0xFF;
        // After drop, memory should be zeroed
        // (We can't easily test this without unsafe access)
    }
}
