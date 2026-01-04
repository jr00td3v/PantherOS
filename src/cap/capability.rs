//! Capability Types and Rights
//!
//! Defines the core capability primitives for the object-capability model.
//!
//! # Capability Structure
//! ```text
//! ┌──────────────────────────────────────────────────────────┐
//! │                    Capability<T>                         │
//! ├──────────────────────────────────────────────────────────┤
//! │  object: ObjectRef<T>    - Reference to kernel object    │
//! │  rights: Rights          - Permitted operations          │
//! │  badge: u64              - Optional identifier           │
//! │  generation: u32         - For revocation checking       │
//! └──────────────────────────────────────────────────────────┘
//! ```

use core::marker::PhantomData;

/// Rights that can be granted by a capability.
///
/// Rights are a bitmask that controls what operations are permitted.
/// When deriving a capability, rights can only be reduced, never increased.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Rights(u32);

impl Rights {
    /// No rights (empty capability).
    pub const NONE: Self = Self(0);

    /// Read permission.
    pub const READ: Self = Self(1 << 0);

    /// Write permission.
    pub const WRITE: Self = Self(1 << 1);

    /// Execute permission (for code pages).
    pub const EXECUTE: Self = Self(1 << 2);

    /// Grant permission (can derive capabilities).
    pub const GRANT: Self = Self(1 << 3);

    /// Revoke permission (can revoke derived capabilities).
    pub const REVOKE: Self = Self(1 << 4);

    /// All rights combined.
    pub const ALL: Self = Self(0x1F);

    /// Read and write.
    pub const READ_WRITE: Self = Self(Self::READ.0 | Self::WRITE.0);

    /// Create rights from raw bits.
    #[inline]
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits & Self::ALL.0)
    }

    /// Get the raw bits.
    #[inline]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Check if these rights include all of the specified rights.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Combine two right sets (union).
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Intersect two right sets.
    #[inline]
    pub const fn intersect(self, other: Self) -> Self {
        Self(self.0 & other.0)
    }

    /// Remove rights.
    #[inline]
    pub const fn remove(self, other: Self) -> Self {
        Self(self.0 & !other.0)
    }

    /// Check if empty (no rights).
    #[inline]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// Types of kernel objects that can be referenced by capabilities.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum CapabilityType {
    /// Invalid/null capability.
    Null = 0,

    /// Endpoint for IPC.
    Endpoint = 1,

    /// Notification object.
    Notification = 2,

    /// Reply capability (one-shot).
    Reply = 3,

    /// CNode (capability space node).
    CNode = 4,

    /// Thread control block.
    Thread = 5,

    /// Virtual address space.
    VSpace = 6,

    /// Memory frame (physical page).
    Frame = 7,

    /// Page table (for mapping).
    PageTable = 8,

    /// IRQ handler.
    IRQ = 9,

    /// Untyped memory (for retyping).
    Untyped = 10,
}

/// A capability: an unforgeable token granting access to a kernel object.
///
/// # Type Parameters
/// * `T` - The type of kernel object this capability references
///
/// # Security Properties
/// - Cannot be constructed without kernel involvement
/// - Rights can only be reduced via `derive()`
/// - Generation enables revocation checking
#[derive(Debug)]
pub struct Capability<T> {
    /// Type of the referenced object.
    cap_type: CapabilityType,

    /// Pointer to the kernel object (only valid in kernel space).
    object_ptr: usize,

    /// Rights granted by this capability.
    rights: Rights,

    /// Badge for identifying the capability holder.
    badge: u64,

    /// Generation number for revocation.
    generation: u32,

    /// Phantom data for the type parameter.
    _phantom: PhantomData<T>,
}

impl<T> Capability<T> {
    /// Create a null (invalid) capability.
    pub const fn null() -> Self {
        Self {
            cap_type: CapabilityType::Null,
            object_ptr: 0,
            rights: Rights::NONE,
            badge: 0,
            generation: 0,
            _phantom: PhantomData,
        }
    }

    /// Create a new capability.
    ///
    /// # Safety
    /// This must only be called by the kernel when creating new capabilities.
    /// The object pointer must be valid.
    pub(crate) const unsafe fn new(
        cap_type: CapabilityType,
        object_ptr: usize,
        rights: Rights,
        badge: u64,
        generation: u32,
    ) -> Self {
        Self {
            cap_type,
            object_ptr,
            rights,
            badge,
            generation,
            _phantom: PhantomData,
        }
    }

    /// Check if this is a null capability.
    #[inline]
    pub const fn is_null(&self) -> bool {
        matches!(self.cap_type, CapabilityType::Null)
    }

    /// Check if this capability is valid (not null).
    #[inline]
    pub const fn is_valid(&self) -> bool {
        !self.is_null()
    }

    /// Get the capability type.
    #[inline]
    pub const fn cap_type(&self) -> CapabilityType {
        self.cap_type
    }

    /// Get the rights granted by this capability.
    #[inline]
    pub const fn rights(&self) -> Rights {
        self.rights
    }

    /// Get the badge.
    #[inline]
    pub const fn badge(&self) -> u64 {
        self.badge
    }

    /// Get the generation number.
    #[inline]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Check if this capability has the specified rights.
    #[inline]
    pub const fn has_rights(&self, required: Rights) -> bool {
        self.rights.contains(required)
    }

    /// Derive a new capability with reduced rights.
    ///
    /// # Arguments
    /// * `new_rights` - Rights for the derived capability (must be subset)
    /// * `new_badge` - Badge for the derived capability
    ///
    /// # Returns
    /// A new capability with reduced rights, or None if:
    /// - This capability doesn't have GRANT right
    /// - The requested rights exceed current rights
    pub fn derive(&self, new_rights: Rights, new_badge: u64) -> Option<Self> {
        // Must have grant right to derive
        if !self.has_rights(Rights::GRANT) {
            return None;
        }

        // New rights must be a subset of current rights
        if !self.rights.contains(new_rights) {
            return None;
        }

        Some(Self {
            cap_type: self.cap_type,
            object_ptr: self.object_ptr,
            rights: new_rights,
            badge: new_badge,
            generation: self.generation,
            _phantom: PhantomData,
        })
    }

    /// Get the object pointer.
    ///
    /// # Safety
    /// The caller must ensure the object is still valid and the capability
    /// has the necessary rights for the intended operation.
    #[inline]
    pub(crate) unsafe fn object_ptr(&self) -> *const T {
        self.object_ptr as *const T
    }
}

impl<T> Clone for Capability<T> {
    fn clone(&self) -> Self {
        Self {
            cap_type: self.cap_type,
            object_ptr: self.object_ptr,
            rights: self.rights,
            badge: self.badge,
            generation: self.generation,
            _phantom: PhantomData,
        }
    }
}

impl<T> Copy for Capability<T> {}

impl<T> Default for Capability<T> {
    fn default() -> Self {
        Self::null()
    }
}

/// Marker types for kernel objects.
pub mod objects {
    /// Endpoint for inter-process communication.
    #[derive(Debug)]
    pub struct Endpoint;

    /// Notification object for signaling.
    #[derive(Debug)]
    pub struct Notification;

    /// Memory frame (physical page).
    #[derive(Debug)]
    pub struct Frame;

    /// Thread control block.
    #[derive(Debug)]
    pub struct Thread;

    /// Address space (page table root).
    #[derive(Debug)]
    pub struct VSpace;
}

/// Type alias for common capability types.
pub type EndpointCap = Capability<objects::Endpoint>;
pub type NotificationCap = Capability<objects::Notification>;
pub type FrameCap = Capability<objects::Frame>;
pub type ThreadCap = Capability<objects::Thread>;
pub type VSpaceCap = Capability<objects::VSpace>;
