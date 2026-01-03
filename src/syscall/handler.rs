//! System Call Handler
//!
//! Dispatches system calls and implements individual syscall handlers.
//!
//! # Security Considerations
//! - All syscall numbers are validated against the whitelist
//! - Unknown syscalls return ENOSYS
//! - Parameters are validated before use

use crate::exception::ExceptionContext;
use crate::{kprintln, kprint};

use super::validate::{self, UserBuffer};

/// System call numbers
pub mod numbers {
    pub const SYS_EXIT: usize = 0;
    pub const SYS_WRITE: usize = 1;
}

/// System call error codes
#[repr(i64)]
#[derive(Debug, Clone, Copy)]
pub enum SyscallError {
    /// Invalid system call number
    Enosys = -38,
    /// Bad file descriptor
    Ebadf = -9,
    /// Bad address (invalid pointer)
    Efault = -14,
    /// Invalid argument
    Einval = -22,
}

/// Dispatch a system call
///
/// # Arguments
/// * `syscall_num` - System call number (from x8)
/// * `ctx` - Exception context with arguments (x0-x5)
///
/// # Returns
/// Result value to be placed in x0
///
/// # Security
/// - Unknown syscall numbers are rejected with ENOSYS
/// - Each handler validates its own arguments
pub fn dispatch(syscall_num: usize, ctx: &mut ExceptionContext) -> i64 {
    match syscall_num {
        numbers::SYS_EXIT => sys_exit(ctx.gpr[0] as i32),
        numbers::SYS_WRITE => sys_write(
            ctx.gpr[0] as i32,  // fd
            ctx.gpr[1] as usize, // buf
            ctx.gpr[2] as usize, // len
        ),
        _ => {
            kprintln!("[SYSCALL] Unknown syscall: {}", syscall_num);
            SyscallError::Enosys as i64
        }
    }
}

/// Exit system call
///
/// Terminates the current process with the given status code.
///
/// # Arguments
/// * `status` - Exit status code
///
/// # Security
/// No validation needed - any status code is acceptable
fn sys_exit(status: i32) -> i64 {
    kprintln!("[SYSCALL] exit({})", status);
    kprintln!("[PROCESS] Process exited with status {}", status);

    // In a real kernel, we'd terminate the process and schedule another
    // For now, halt the system
    loop {
        // SAFETY: WFI is always safe
        unsafe {
            core::arch::asm!("wfi", options(nostack, nomem));
        }
    }
}

/// Write system call
///
/// Writes data from a user buffer to a file descriptor.
///
/// # Arguments
/// * `fd` - File descriptor (currently only 1 = stdout, 2 = stderr)
/// * `buf` - User-space buffer address
/// * `len` - Number of bytes to write
///
/// # Returns
/// Number of bytes written on success, negative error code on failure
///
/// # Security
/// - File descriptor is validated (only stdout/stderr supported)
/// - Buffer pointer is validated to be in user space
/// - Length is bounds-checked
fn sys_write(fd: i32, buf: usize, len: usize) -> i64 {
    // Validate file descriptor
    if fd != 1 && fd != 2 {
        kprintln!("[SYSCALL] write: invalid fd {}", fd);
        return SyscallError::Ebadf as i64;
    }

    // Validate buffer
    let user_buf = match validate::validate_user_read(buf, len) {
        Ok(buf) => buf,
        Err(e) => {
            kprintln!("[SYSCALL] write: buffer validation failed: {:?}", e);
            return e as i64;
        }
    };

    // Perform the write
    for &byte in user_buf.as_bytes() {
        kprint!("{}", byte as char);
    }

    len as i64
}
