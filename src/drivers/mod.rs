//! Device drivers for PantherOS
//!
//! All drivers follow these security principles:
//! - Minimal unsafe code, well-documented
//! - Input validation on all public interfaces
//! - No panics on invalid input (return errors)

pub mod uart;
