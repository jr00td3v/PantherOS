//! Capability Space (CSpace)
//!
//! A CSpace is a data structure that holds capabilities for a process.
//! It provides indexed access to capabilities via "slots".
//!
//! # Design
//! - Fixed-size array of capability slots
//! - Slots are addressed by CapSlot indices
//! - Operations: lookup, insert, delete, derive

use super::capability::{Capability, CapabilityType, Rights};

/// Number of slots in a CSpace.
/// Using 64 for now to keep it simple.
pub const CSPACE_SIZE: usize = 64;

/// A slot index in a CSpace.
///
/// This is a newtype to prevent using arbitrary integers as slot indices.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct CapSlot(u32);

impl CapSlot {
    /// Create a new slot index.
    ///
    /// Returns None if the index is out of range.
    #[inline]
    pub const fn new(index: u32) -> Option<Self> {
        if (index as usize) < CSPACE_SIZE {
            Some(Self(index))
        } else {
            None
        }
    }

    /// Create a slot index without bounds checking.
    ///
    /// # Safety
    /// The caller must ensure `index < CSPACE_SIZE`.
    #[inline]
    pub const unsafe fn new_unchecked(index: u32) -> Self {
        Self(index)
    }

    /// Get the index value.
    #[inline]
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    /// Reserved slot for null capability.
    pub const NULL: Self = Self(0);

    /// Reserved slot for reply capability.
    pub const REPLY: Self = Self(1);

    /// Reserved slot for caller capability.
    pub const CALLER: Self = Self(2);

    /// First user-available slot.
    pub const FIRST_USER: Self = Self(3);
}

/// Error type for CSpace operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSpaceError {
    /// The slot index is out of range.
    InvalidSlot,
    /// The slot is already occupied.
    SlotOccupied,
    /// The slot is empty.
    SlotEmpty,
    /// Insufficient rights for the operation.
    InsufficientRights,
    /// The capability type doesn't match.
    TypeMismatch,
}

impl core::fmt::Display for CSpaceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidSlot => write!(f, "invalid slot index"),
            Self::SlotOccupied => write!(f, "slot already occupied"),
            Self::SlotEmpty => write!(f, "slot is empty"),
            Self::InsufficientRights => write!(f, "insufficient rights"),
            Self::TypeMismatch => write!(f, "capability type mismatch"),
        }
    }
}

/// A raw capability slot that can hold any capability type.
///
/// This is used internally in CSpace since we need to store
/// capabilities of different types in the same array.
#[derive(Clone, Copy)]
pub struct RawCapability {
    /// Type of capability.
    pub cap_type: CapabilityType,
    /// Pointer to the kernel object.
    pub object_ptr: usize,
    /// Rights bitmap.
    pub rights: Rights,
    /// Badge value.
    pub badge: u64,
    /// Generation for revocation.
    pub generation: u32,
}

impl RawCapability {
    /// Create an empty (null) raw capability.
    pub const fn null() -> Self {
        Self {
            cap_type: CapabilityType::Null,
            object_ptr: 0,
            rights: Rights::NONE,
            badge: 0,
            generation: 0,
        }
    }

    /// Check if this is a null capability.
    #[inline]
    pub const fn is_null(&self) -> bool {
        matches!(self.cap_type, CapabilityType::Null)
    }

    /// Check if this capability is valid.
    #[inline]
    pub const fn is_valid(&self) -> bool {
        !self.is_null()
    }
}

impl Default for RawCapability {
    fn default() -> Self {
        Self::null()
    }
}

impl core::fmt::Debug for RawCapability {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_null() {
            write!(f, "RawCap(null)")
        } else {
            write!(
                f,
                "RawCap({:?}, rights={:?}, badge={})",
                self.cap_type, self.rights, self.badge
            )
        }
    }
}

/// Capability Space for a process.
///
/// Contains all capabilities accessible to a process.
/// Capabilities are accessed via slot indices.
#[derive(Debug)]
pub struct CSpace {
    /// Array of capability slots.
    slots: [RawCapability; CSPACE_SIZE],
}

impl CSpace {
    /// Create a new empty CSpace.
    pub const fn new() -> Self {
        const NULL: RawCapability = RawCapability::null();
        Self {
            slots: [NULL; CSPACE_SIZE],
        }
    }

    /// Look up a capability in a slot.
    ///
    /// Returns the raw capability if the slot is valid and non-empty.
    #[inline]
    pub fn lookup(&self, slot: CapSlot) -> Result<&RawCapability, CSpaceError> {
        let cap = &self.slots[slot.index()];
        if cap.is_null() {
            Err(CSpaceError::SlotEmpty)
        } else {
            Ok(cap)
        }
    }

    /// Look up a capability with type checking.
    pub fn lookup_typed(
        &self,
        slot: CapSlot,
        expected_type: CapabilityType,
    ) -> Result<&RawCapability, CSpaceError> {
        let cap = self.lookup(slot)?;
        if cap.cap_type != expected_type {
            return Err(CSpaceError::TypeMismatch);
        }
        Ok(cap)
    }

    /// Insert a capability into a slot.
    ///
    /// Fails if the slot is already occupied.
    pub fn insert(&mut self, slot: CapSlot, cap: RawCapability) -> Result<(), CSpaceError> {
        if !self.slots[slot.index()].is_null() {
            return Err(CSpaceError::SlotOccupied);
        }
        self.slots[slot.index()] = cap;
        Ok(())
    }

    /// Replace a capability in a slot.
    ///
    /// Returns the old capability.
    pub fn replace(&mut self, slot: CapSlot, cap: RawCapability) -> RawCapability {
        core::mem::replace(&mut self.slots[slot.index()], cap)
    }

    /// Delete a capability from a slot.
    ///
    /// Returns the deleted capability, or error if slot is empty.
    pub fn delete(&mut self, slot: CapSlot) -> Result<RawCapability, CSpaceError> {
        if self.slots[slot.index()].is_null() {
            return Err(CSpaceError::SlotEmpty);
        }
        Ok(core::mem::replace(
            &mut self.slots[slot.index()],
            RawCapability::null(),
        ))
    }

    /// Find a free slot.
    ///
    /// Returns the first empty slot >= start_from.
    pub fn find_free(&self, start_from: CapSlot) -> Option<CapSlot> {
        for i in start_from.index()..CSPACE_SIZE {
            if self.slots[i].is_null() {
                return Some(CapSlot(i as u32));
            }
        }
        None
    }

    /// Derive a capability to a new slot with reduced rights.
    pub fn derive(
        &mut self,
        src_slot: CapSlot,
        dst_slot: CapSlot,
        new_rights: Rights,
        new_badge: u64,
    ) -> Result<(), CSpaceError> {
        // Check source capability
        let src = self.lookup(src_slot)?;

        // Must have grant right to derive
        if !src.rights.contains(Rights::GRANT) {
            return Err(CSpaceError::InsufficientRights);
        }

        // New rights must be a subset
        if !src.rights.contains(new_rights) {
            return Err(CSpaceError::InsufficientRights);
        }

        // Check destination is free
        if !self.slots[dst_slot.index()].is_null() {
            return Err(CSpaceError::SlotOccupied);
        }

        // Create derived capability
        let derived = RawCapability {
            cap_type: src.cap_type,
            object_ptr: src.object_ptr,
            rights: new_rights,
            badge: new_badge,
            generation: src.generation,
        };

        self.slots[dst_slot.index()] = derived;
        Ok(())
    }

    /// Check if a slot has a capability with the required rights.
    pub fn check_rights(&self, slot: CapSlot, required: Rights) -> Result<(), CSpaceError> {
        let cap = self.lookup(slot)?;
        if cap.rights.contains(required) {
            Ok(())
        } else {
            Err(CSpaceError::InsufficientRights)
        }
    }
}

impl Default for CSpace {
    fn default() -> Self {
        Self::new()
    }
}
