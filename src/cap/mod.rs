//! Capability-Based Security System
//!
//! Implements an object-capability model inspired by seL4.
//!
//! # Design
//! - Each process has a CSpace (Capability Space)
//! - Capabilities are unforgeable tokens that grant access to objects
//! - Capabilities can be derived (minted) with reduced rights
//!
//! # Security Properties
//! - Capabilities cannot be forged or guessed
//! - Rights can only be reduced, never increased
//! - Revocation is supported via generation numbers

pub mod capability;
pub mod cspace;

pub use capability::{Capability, CapabilityType, Rights};
pub use cspace::{CSpace, CapSlot};
