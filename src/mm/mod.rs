//! Memory management module for PantherOS
//!
//! Provides:
//! - Kernel heap allocation
//! - Physical page management (planned)
//! - Virtual memory abstractions (planned)
//!
//! # Security Principles
//! - All allocations are bounds-checked
//! - Memory initialization is guaranteed
//! - Unsafe code is minimal and audited

mod allocator;

pub use allocator::{heap_size, init_heap};
