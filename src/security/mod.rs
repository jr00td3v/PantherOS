//! Security Primitives Module
//!
//! Provides confidential computing patterns for PantherOS:
//! - Secret zeroization on drop
//! - Secure memory handling
//!
//! # Security Properties
//! - Secrets are always zeroed when no longer needed
//! - Memory is cleared using volatile writes to prevent optimization

pub mod zeroize;

pub use zeroize::{SecureWrapper, Zeroize};
