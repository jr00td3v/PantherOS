//! System Call Interface
//!
//! Provides a secure system call interface for user-mode applications.
//!
//! # Security Model
//! - Whitelist approach: only explicitly implemented syscalls are allowed
//! - All parameters are validated before use
//! - Invalid inputs return errors, never panic
//! - Rate limiting for expensive operations (planned)
//!
//! # Current Syscalls
//! - 0: exit(status) - terminate the current process
//! - 1: write(fd, buf, len) - write to a file descriptor

mod handler;
mod validate;

pub use handler::dispatch;
pub use validate::UserBuffer;
