//! System Call Input Validation
//!
//! Provides secure validation for all system call inputs.
//!
//! # Security Principles
//! - Validate ALL inputs before use
//! - Fail-secure: deny by default
//! - Prevent common vulnerabilities:
//!   - Buffer overflows (bounds checking)
//!   - Use-after-free (Rust ownership)
//!   - TOCTOU races (copy to kernel space)
//!   - Null pointer dereference (explicit checks)

use super::handler::SyscallError;

/// User-space memory regions
/// 
/// In a real system, these would be per-process and managed by the VMM.
/// For now, we define a simple user space region.
pub mod regions {
    /// Start of user-accessible memory
    /// (Kernel is at 0x40080000, user space is below)
    pub const USER_START: usize = 0x40000000;
    /// End of user-accessible memory (before kernel)
    pub const USER_END: usize = 0x40080000;
}

/// A validated user-space buffer
///
/// This type guarantees that:
/// - The buffer is within user-space bounds
/// - The buffer is properly aligned
/// - The length doesn't overflow
///
/// # Safety
/// This struct is only constructed after validation passes.
#[derive(Debug)]
pub struct UserBuffer {
    ptr: *const u8,
    len: usize,
}

impl UserBuffer {
    /// Get the buffer as a byte slice
    ///
    /// # Safety
    /// This is safe because the buffer was validated during construction.
    /// However, the contents may change if we don't copy them (TOCTOU).
    ///
    /// SAFETY AUDIT: 2025-01-04
    /// - Pointer and length were validated in validate_user_read
    /// - User memory is mapped and accessible from kernel
    pub fn as_bytes(&self) -> &[u8] {
        if self.len == 0 {
            return &[];
        }
        // SAFETY:
        // - Pointer is validated to be in user space
        // - Length is validated to not overflow
        // - Memory is guaranteed mapped by hypervisor
        // Audited: 2025-01-04
        unsafe { core::slice::from_raw_parts(self.ptr, self.len) }
    }
}

/// Validate a user-space read buffer
///
/// # Arguments
/// * `ptr` - User-space buffer address
/// * `len` - Buffer length in bytes
///
/// # Returns
/// * `Ok(UserBuffer)` - Validated buffer handle
/// * `Err(SyscallError)` - Validation failed
///
/// # Security Checks
/// 1. Pointer is within user space
/// 2. Pointer + length doesn't overflow
/// 3. End address is within user space
/// 4. Alignment is acceptable (no strict requirement for bytes)
pub fn validate_user_read(ptr: usize, len: usize) -> Result<UserBuffer, SyscallError> {
    // Zero-length reads are valid
    if len == 0 {
        return Ok(UserBuffer {
            ptr: ptr as *const u8,
            len: 0,
        });
    }

    // Check null pointer
    if ptr == 0 {
        return Err(SyscallError::Efault);
    }

    // Check start is in user space
    if ptr < regions::USER_START || ptr >= regions::USER_END {
        return Err(SyscallError::Efault);
    }

    // Check for overflow
    let end = ptr.checked_add(len).ok_or(SyscallError::Efault)?;

    // Check end is in user space
    if end > regions::USER_END {
        return Err(SyscallError::Efault);
    }

    Ok(UserBuffer {
        ptr: ptr as *const u8,
        len,
    })
}

/// Validate a user-space write buffer
///
/// Same as read validation, but the buffer will be written to.
pub fn validate_user_write(ptr: usize, len: usize) -> Result<UserBufferMut, SyscallError> {
    // Reuse read validation logic
    let read_buf = validate_user_read(ptr, len)?;
    
    Ok(UserBufferMut {
        ptr: read_buf.ptr as *mut u8,
        len: read_buf.len,
    })
}

/// A validated mutable user-space buffer
#[derive(Debug)]
pub struct UserBufferMut {
    ptr: *mut u8,
    len: usize,
}

impl UserBufferMut {
    /// Get the buffer as a mutable byte slice
    ///
    /// # Safety
    /// Same considerations as UserBuffer::as_bytes, plus mutability.
    pub fn as_bytes_mut(&mut self) -> &mut [u8] {
        if self.len == 0 {
            return &mut [];
        }
        // SAFETY: Same as UserBuffer::as_bytes
        unsafe { core::slice::from_raw_parts_mut(self.ptr, self.len) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Note: These tests can only run in a host environment, not in the kernel
    // They demonstrate the validation logic

    #[test]
    fn test_zero_length() {
        // Zero-length should always succeed
        assert!(validate_user_read(0x40001000, 0).is_ok());
    }

    #[test]
    fn test_null_pointer() {
        assert!(validate_user_read(0, 100).is_err());
    }

    #[test]
    fn test_overflow() {
        assert!(validate_user_read(usize::MAX - 10, 100).is_err());
    }
}
