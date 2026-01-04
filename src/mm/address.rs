//! Physical and Virtual Address Types
//!
//! Type-safe wrappers for memory addresses that prevent mixing
//! physical and virtual addresses at compile time.
//!
//! # Security Properties
//! - Physical addresses cannot be dereferenced directly
//! - Virtual addresses require explicit unsafe conversion to pointers
//! - Alignment is enforced at type level where needed

use core::fmt;

/// Page size (4 KiB)
pub const PAGE_SIZE: usize = 4096;
/// Page size mask
pub const PAGE_MASK: usize = PAGE_SIZE - 1;
/// Bits to shift for page number
pub const PAGE_SHIFT: usize = 12;

/// Number of entries per page table (512 for 4KB granule)
pub const ENTRIES_PER_TABLE: usize = 512;

/// Kernel virtual address base (higher-half)
/// Using the highest 256TB of the 48-bit address space
pub const KERNEL_VIRT_BASE: usize = 0xFFFF_0000_0000_0000;

/// Physical memory base for QEMU virt machine
pub const PHYS_MEM_BASE: usize = 0x4000_0000;

/// Kernel physical load address
pub const KERNEL_PHYS_BASE: usize = 0x4008_0000;

/// MMIO base for devices (UART, etc.)
pub const MMIO_BASE: usize = 0x0900_0000;

/// A physical memory address.
///
/// This is a newtype wrapper that prevents accidental mixing of
/// physical and virtual addresses. Physical addresses cannot be
/// directly dereferenced - they must be mapped to virtual addresses first.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct PhysAddr(usize);

impl PhysAddr {
    /// Create a new physical address.
    ///
    /// # Panics
    /// Panics in debug mode if the address uses more than 48 bits.
    #[inline]
    pub const fn new(addr: usize) -> Self {
        // ARM64 with 48-bit physical addressing
        debug_assert!(addr <= 0x0000_FFFF_FFFF_FFFF);
        Self(addr)
    }

    /// Create a physical address without validation (const-compatible).
    #[inline]
    pub const fn new_unchecked(addr: usize) -> Self {
        Self(addr)
    }

    /// Get the raw address value.
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Get the raw address as u64 (for page table entries).
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }

    /// Check if the address is page-aligned.
    #[inline]
    pub const fn is_aligned(self) -> bool {
        self.0 & PAGE_MASK == 0
    }

    /// Align the address down to the nearest page boundary.
    #[inline]
    pub const fn align_down(self) -> Self {
        Self(self.0 & !PAGE_MASK)
    }

    /// Align the address up to the nearest page boundary.
    #[inline]
    pub const fn align_up(self) -> Self {
        Self((self.0 + PAGE_MASK) & !PAGE_MASK)
    }

    /// Get the page frame number.
    #[inline]
    pub const fn page_frame_number(self) -> usize {
        self.0 >> PAGE_SHIFT
    }

    /// Create from a page frame number.
    #[inline]
    pub const fn from_page_frame_number(pfn: usize) -> Self {
        Self(pfn << PAGE_SHIFT)
    }

    /// Add an offset to this address.
    #[inline]
    pub const fn add(self, offset: usize) -> Self {
        Self(self.0 + offset)
    }
}

impl fmt::Debug for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "PhysAddr({:#018x})", self.0)
    }
}

impl fmt::Display for PhysAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

/// A virtual memory address.
///
/// This is a newtype wrapper that enforces the ARM64 canonical
/// address format (sign-extended from bit 47).
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct VirtAddr(usize);

impl VirtAddr {
    /// Create a new virtual address with canonical form validation.
    ///
    /// ARM64 requires that bits [63:48] are all copies of bit 47.
    #[inline]
    pub const fn new(addr: usize) -> Self {
        let canonical = Self::make_canonical(addr);
        Self(canonical)
    }

    /// Create a virtual address without validation.
    #[inline]
    pub const fn new_unchecked(addr: usize) -> Self {
        Self(addr)
    }

    /// Convert an address to canonical form.
    ///
    /// If bit 47 is set, bits 48-63 must all be 1.
    /// If bit 47 is clear, bits 48-63 must all be 0.
    #[inline]
    const fn make_canonical(addr: usize) -> usize {
        // Sign-extend from bit 47
        let bit47 = (addr >> 47) & 1;
        if bit47 == 1 {
            addr | 0xFFFF_0000_0000_0000
        } else {
            addr & 0x0000_FFFF_FFFF_FFFF
        }
    }

    /// Get the raw address value.
    #[inline]
    pub const fn as_usize(self) -> usize {
        self.0
    }

    /// Get the raw address as u64.
    #[inline]
    pub const fn as_u64(self) -> u64 {
        self.0 as u64
    }

    /// Check if the address is page-aligned.
    #[inline]
    pub const fn is_aligned(self) -> bool {
        self.0 & PAGE_MASK == 0
    }

    /// Align the address down to the nearest page boundary.
    #[inline]
    pub const fn align_down(self) -> Self {
        Self::new(self.0 & !PAGE_MASK)
    }

    /// Align the address up to the nearest page boundary.
    #[inline]
    pub const fn align_up(self) -> Self {
        Self::new((self.0 + PAGE_MASK) & !PAGE_MASK)
    }

    /// Get the page table indices for this address.
    ///
    /// Returns (L0, L1, L2, L3) indices for 4-level paging.
    #[inline]
    pub const fn page_table_indices(self) -> (usize, usize, usize, usize) {
        let addr = self.0;
        let l0 = (addr >> 39) & 0x1FF;
        let l1 = (addr >> 30) & 0x1FF;
        let l2 = (addr >> 21) & 0x1FF;
        let l3 = (addr >> 12) & 0x1FF;
        (l0, l1, l2, l3)
    }

    /// Get the page offset (lowest 12 bits).
    #[inline]
    pub const fn page_offset(self) -> usize {
        self.0 & PAGE_MASK
    }

    /// Add an offset to this address.
    #[inline]
    pub const fn add(self, offset: usize) -> Self {
        Self::new(self.0.wrapping_add(offset))
    }

    /// Check if this is a kernel address (higher-half).
    #[inline]
    pub const fn is_kernel(self) -> bool {
        self.0 >= KERNEL_VIRT_BASE
    }

    /// Check if this is a user address (lower-half).
    #[inline]
    pub const fn is_user(self) -> bool {
        self.0 < KERNEL_VIRT_BASE
    }

    /// Convert to a raw pointer.
    ///
    /// # Safety
    /// The caller must ensure the address is valid and properly mapped.
    #[inline]
    pub const unsafe fn as_ptr<T>(self) -> *const T {
        self.0 as *const T
    }

    /// Convert to a mutable raw pointer.
    ///
    /// # Safety
    /// The caller must ensure the address is valid, properly mapped,
    /// and that mutable access is safe.
    #[inline]
    pub const unsafe fn as_mut_ptr<T>(self) -> *mut T {
        self.0 as *mut T
    }
}

impl fmt::Debug for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "VirtAddr({:#018x})", self.0)
    }
}

impl fmt::Display for VirtAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#018x}", self.0)
    }
}

/// Convert a kernel virtual address to its corresponding physical address.
///
/// This only works for addresses in the direct-mapped kernel region.
#[inline]
pub const fn kernel_virt_to_phys(virt: VirtAddr) -> PhysAddr {
    debug_assert!(virt.is_kernel());
    PhysAddr::new_unchecked(virt.as_usize() - KERNEL_VIRT_BASE + PHYS_MEM_BASE)
}

/// Convert a physical address to its kernel virtual address.
///
/// This creates an address in the direct-mapped kernel region.
#[inline]
pub const fn phys_to_kernel_virt(phys: PhysAddr) -> VirtAddr {
    VirtAddr::new(phys.as_usize() - PHYS_MEM_BASE + KERNEL_VIRT_BASE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonical_address() {
        // User space address
        let user = VirtAddr::new(0x0000_0001_0000_0000);
        assert!(user.is_user());

        // Kernel space address (should be sign-extended)
        let kernel = VirtAddr::new(0xFFFF_0000_4008_0000);
        assert!(kernel.is_kernel());
    }

    #[test]
    fn test_page_alignment() {
        let addr = PhysAddr::new(0x4008_1234);
        assert!(!addr.is_aligned());
        assert_eq!(addr.align_down().as_usize(), 0x4008_1000);
        assert_eq!(addr.align_up().as_usize(), 0x4008_2000);
    }
}
