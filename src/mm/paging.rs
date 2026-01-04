//! ARM64 Page Table Management
//!
//! Implements 4-level page tables for the ARM64 VMSA (Virtual Memory System Architecture).
//!
//! # Page Table Structure (4KB granule)
//! - L0 (PGD): 512 entries, each covers 512GB
//! - L1 (PUD): 512 entries, each covers 1GB
//! - L2 (PMD): 512 entries, each covers 2MB
//! - L3 (PTE): 512 entries, each covers 4KB
//!
//! # Security Properties
//! - Page flags are strictly typed to prevent invalid combinations
//! - Kernel pages are marked with PXN/UXN as appropriate
//! - User pages cannot have kernel-only permissions

use core::ops::{Index, IndexMut};

use super::address::{PhysAddr, VirtAddr, PAGE_SIZE, ENTRIES_PER_TABLE};

/// Page table entry flags for ARM64.
///
/// These flags control memory attributes, access permissions, and execution rights.
/// The layout follows the ARMv8-A architecture reference manual.
#[derive(Clone, Copy, PartialEq, Eq)]
#[repr(transparent)]
pub struct PageFlags(u64);

impl PageFlags {
    // Descriptor type bits [1:0]
    /// Entry is invalid/not present.
    pub const INVALID: Self = Self(0);
    /// Block descriptor (L1/L2 only) - maps a large page.
    pub const BLOCK: Self = Self(0b01);
    /// Table descriptor (L0/L1/L2) - points to next level table.
    pub const TABLE: Self = Self(0b11);
    /// Page descriptor (L3 only) - maps a 4KB page.
    pub const PAGE: Self = Self(0b11);

    // Lower attributes [11:2]
    /// Attribute Index [4:2] - selects MAIR entry.
    pub const ATTR_NORMAL: Self = Self(0 << 2);      // MAIR index 0: Normal memory
    pub const ATTR_DEVICE: Self = Self(1 << 2);      // MAIR index 1: Device memory
    pub const ATTR_NC: Self = Self(2 << 2);          // MAIR index 2: Non-cacheable

    /// Non-Secure bit [5] - for TrustZone.
    pub const NS: Self = Self(1 << 5);

    /// Access Permission bits [7:6]
    /// AP[2:1] controls read/write permissions.
    pub const AP_RW_EL1: Self = Self(0b00 << 6);     // EL1 R/W, EL0 no access
    pub const AP_RW_ALL: Self = Self(0b01 << 6);     // EL1 R/W, EL0 R/W
    pub const AP_RO_EL1: Self = Self(0b10 << 6);     // EL1 R/O, EL0 no access
    pub const AP_RO_ALL: Self = Self(0b11 << 6);     // EL1 R/O, EL0 R/O

    /// Shareability [9:8]
    pub const SH_NON: Self = Self(0b00 << 8);        // Non-shareable
    pub const SH_OUTER: Self = Self(0b10 << 8);      // Outer shareable
    pub const SH_INNER: Self = Self(0b11 << 8);      // Inner shareable

    /// Access Flag [10] - set by hardware on first access.
    pub const AF: Self = Self(1 << 10);

    /// Not Global [11] - use ASID for TLB matching.
    pub const NG: Self = Self(1 << 11);

    // Upper attributes [63:52]
    /// Contiguous hint [52] - for TLB optimization.
    pub const CONTIGUOUS: Self = Self(1 << 52);

    /// Privileged Execute Never [53] - no execution at EL1.
    pub const PXN: Self = Self(1 << 53);

    /// User Execute Never [54] - no execution at EL0.
    pub const UXN: Self = Self(1 << 54);

    // Software-defined bits [58:55] - available for OS use.
    /// Software bit 0.
    pub const SW0: Self = Self(1 << 55);
    /// Software bit 1.
    pub const SW1: Self = Self(1 << 56);
    /// Software bit 2.
    pub const SW2: Self = Self(1 << 57);
    /// Software bit 3.
    pub const SW3: Self = Self(1 << 58);

    // Common flag combinations for convenience

    /// Kernel code: readable, executable by kernel only.
    pub const KERNEL_CODE: Self = Self(
        Self::PAGE.0 | Self::AF.0 | Self::SH_INNER.0 |
        Self::ATTR_NORMAL.0 | Self::AP_RO_EL1.0 | Self::UXN.0
    );

    /// Kernel data: readable/writable, not executable.
    pub const KERNEL_DATA: Self = Self(
        Self::PAGE.0 | Self::AF.0 | Self::SH_INNER.0 |
        Self::ATTR_NORMAL.0 | Self::AP_RW_EL1.0 | Self::PXN.0 | Self::UXN.0
    );

    /// Kernel read-only data: readable, not executable.
    pub const KERNEL_RODATA: Self = Self(
        Self::PAGE.0 | Self::AF.0 | Self::SH_INNER.0 |
        Self::ATTR_NORMAL.0 | Self::AP_RO_EL1.0 | Self::PXN.0 | Self::UXN.0
    );

    /// Device memory (MMIO): non-cacheable, not executable.
    pub const KERNEL_DEVICE: Self = Self(
        Self::PAGE.0 | Self::AF.0 |
        Self::ATTR_DEVICE.0 | Self::AP_RW_EL1.0 | Self::PXN.0 | Self::UXN.0
    );

    /// User code: readable, executable by user.
    pub const USER_CODE: Self = Self(
        Self::PAGE.0 | Self::AF.0 | Self::SH_INNER.0 |
        Self::ATTR_NORMAL.0 | Self::AP_RO_ALL.0 | Self::PXN.0 | Self::NG.0
    );

    /// User data: readable/writable by user, not executable.
    pub const USER_DATA: Self = Self(
        Self::PAGE.0 | Self::AF.0 | Self::SH_INNER.0 |
        Self::ATTR_NORMAL.0 | Self::AP_RW_ALL.0 | Self::PXN.0 | Self::UXN.0 | Self::NG.0
    );

    /// Table entry pointing to next level.
    pub const TABLE_ENTRY: Self = Self(Self::TABLE.0 | Self::AF.0);

    /// Create empty flags (invalid entry).
    #[inline]
    pub const fn empty() -> Self {
        Self(0)
    }

    /// Get the raw bits.
    #[inline]
    pub const fn bits(self) -> u64 {
        self.0
    }

    /// Create from raw bits.
    ///
    /// # Safety
    /// The caller must ensure the bits represent a valid flag combination.
    #[inline]
    pub const unsafe fn from_bits_unchecked(bits: u64) -> Self {
        Self(bits)
    }

    /// Check if the entry is valid (present).
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 & 0b01 != 0
    }

    /// Check if this is a table entry (points to next level).
    #[inline]
    pub const fn is_table(self) -> bool {
        self.0 & 0b11 == 0b11 && self.0 & (Self::PXN.0 | Self::UXN.0) == 0
    }

    /// Check if this is a page/block entry (maps memory).
    #[inline]
    pub const fn is_page(self) -> bool {
        self.0 & 0b11 == 0b11
    }

    /// Combine two flag sets.
    #[inline]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Check if flags contain all of another set.
    #[inline]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }
}

impl core::fmt::Debug for PageFlags {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PageFlags({:#018x})", self.0)
    }
}

/// A single page table entry.
///
/// This is a 64-bit descriptor that either points to a next-level table
/// or maps a physical page/block to a virtual address.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct PageTableEntry(u64);

impl PageTableEntry {
    /// Address mask for page table entries (bits [47:12]).
    const ADDR_MASK: u64 = 0x0000_FFFF_FFFF_F000;

    /// Create an invalid (empty) entry.
    #[inline]
    pub const fn invalid() -> Self {
        Self(0)
    }

    /// Create a table entry pointing to the next level page table.
    #[inline]
    pub const fn table(next_table_phys: PhysAddr) -> Self {
        debug_assert!(next_table_phys.is_aligned());
        Self((next_table_phys.as_u64() & Self::ADDR_MASK) | PageFlags::TABLE_ENTRY.bits())
    }

    /// Create a page entry mapping a physical frame.
    #[inline]
    pub const fn page(phys: PhysAddr, flags: PageFlags) -> Self {
        debug_assert!(phys.is_aligned());
        Self((phys.as_u64() & Self::ADDR_MASK) | flags.bits())
    }

    /// Check if the entry is valid (present).
    #[inline]
    pub const fn is_valid(self) -> bool {
        self.0 & 0b01 != 0
    }

    /// Check if this is a table entry.
    #[inline]
    pub const fn is_table(self) -> bool {
        // Table entries have bits [1:0] = 0b11 and don't have PXN/UXN which
        // would make them page entries at L3
        self.is_valid() && (self.0 & 0b10 != 0)
    }

    /// Get the physical address from this entry.
    #[inline]
    pub const fn addr(self) -> PhysAddr {
        PhysAddr::new_unchecked((self.0 & Self::ADDR_MASK) as usize)
    }

    /// Get the flags from this entry.
    #[inline]
    pub const fn flags(self) -> PageFlags {
        // SAFETY: Flags are stored in the entry itself
        unsafe { PageFlags::from_bits_unchecked(self.0 & !Self::ADDR_MASK) }
    }

    /// Get the raw u64 value.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0
    }

    /// Clear the entry (make invalid).
    #[inline]
    pub fn clear(&mut self) {
        self.0 = 0;
    }
}

impl core::fmt::Debug for PageTableEntry {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_valid() {
            write!(f, "PTE(addr={}, flags={:?})", self.addr(), self.flags())
        } else {
            write!(f, "PTE(invalid)")
        }
    }
}

/// A page table (one level of the 4-level hierarchy).
///
/// Each page table is 4KB and contains 512 entries.
/// The table must be 4KB aligned in physical memory.
#[repr(C, align(4096))]
pub struct PageTable {
    entries: [PageTableEntry; ENTRIES_PER_TABLE],
}

impl PageTable {
    /// Create a new empty page table (all entries invalid).
    pub const fn new() -> Self {
        const INVALID: PageTableEntry = PageTableEntry::invalid();
        Self {
            entries: [INVALID; ENTRIES_PER_TABLE],
        }
    }

    /// Get a reference to an entry by index.
    #[inline]
    pub fn get(&self, index: usize) -> Option<&PageTableEntry> {
        self.entries.get(index)
    }

    /// Get a mutable reference to an entry by index.
    #[inline]
    pub fn get_mut(&mut self, index: usize) -> Option<&mut PageTableEntry> {
        self.entries.get_mut(index)
    }

    /// Iterate over all entries.
    pub fn iter(&self) -> impl Iterator<Item = &PageTableEntry> {
        self.entries.iter()
    }

    /// Iterate over all valid entries with their indices.
    pub fn iter_valid(&self) -> impl Iterator<Item = (usize, &PageTableEntry)> {
        self.entries.iter().enumerate().filter(|(_, e)| e.is_valid())
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        for entry in self.entries.iter_mut() {
            entry.clear();
        }
    }

    /// Get the physical address of this table.
    ///
    /// # Safety
    /// This assumes the table is properly placed in physical memory.
    /// The returned address is only valid if the table was allocated
    /// from the page frame allocator.
    pub fn phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self as *const _ as usize)
    }
}

impl Index<usize> for PageTable {
    type Output = PageTableEntry;

    #[inline]
    fn index(&self, index: usize) -> &Self::Output {
        &self.entries[index]
    }
}

impl IndexMut<usize> for PageTable {
    #[inline]
    fn index_mut(&mut self, index: usize) -> &mut Self::Output {
        &mut self.entries[index]
    }
}

impl Default for PageTable {
    fn default() -> Self {
        Self::new()
    }
}

/// Error type for page mapping operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MappingError {
    /// The virtual address is already mapped.
    AlreadyMapped,
    /// The virtual address is not mapped.
    NotMapped,
    /// No physical frames available for page tables.
    OutOfMemory,
    /// The address is not properly aligned.
    MisalignedAddress,
    /// Attempted to map kernel address with user flags.
    InvalidPermissions,
}

impl core::fmt::Display for MappingError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyMapped => write!(f, "virtual address already mapped"),
            Self::NotMapped => write!(f, "virtual address not mapped"),
            Self::OutOfMemory => write!(f, "out of memory for page tables"),
            Self::MisalignedAddress => write!(f, "address not properly aligned"),
            Self::InvalidPermissions => write!(f, "invalid permission combination"),
        }
    }
}
