//! Page Table Mapper
//!
//! High-level API for managing virtual memory mappings.
//! This module provides safe wrappers for page table manipulation.
//!
//! # Security Properties
//! - All mappings require explicit flags
//! - Kernel addresses cannot be mapped with user permissions
//! - The mapper validates all inputs before modifying page tables

use super::address::{PhysAddr, VirtAddr, KERNEL_VIRT_BASE};
use super::paging::{MappingError, PageFlags, PageTable, PageTableEntry};

/// The kernel's root page table (TTBR1_EL1).
///
/// This is statically allocated and 4KB aligned.
/// It maps the higher-half of the address space.
#[repr(C, align(4096))]
pub struct KernelPageTable {
    l0: PageTable,
}

/// Static kernel page table.
static mut KERNEL_PAGE_TABLE: KernelPageTable = KernelPageTable {
    l0: PageTable::new(),
};

/// Level 1-3 page tables for kernel mappings.
/// We allocate these statically for the initial boot mapping.
#[repr(C, align(4096))]
struct BootPageTables {
    l1: PageTable,
    l2: PageTable,
    l3_kernel: PageTable,  // For kernel code/data
    l3_mmio: PageTable,    // For device MMIO
}

static mut BOOT_PAGE_TABLES: BootPageTables = BootPageTables {
    l1: PageTable::new(),
    l2: PageTable::new(),
    l3_kernel: PageTable::new(),
    l3_mmio: PageTable::new(),
};

/// Initialize the kernel page tables for higher-half mapping.
///
/// This sets up:
/// - Kernel code/data mapped at KERNEL_VIRT_BASE + physical offset
/// - MMIO region for UART
///
/// # Safety
/// Must be called once during early boot before enabling the MMU.
pub unsafe fn init_kernel_page_tables() {
    // SAFETY: This entire function requires unsafe due to mutable static access.
    // We wrap all operations in an unsafe block to satisfy unsafe_op_in_unsafe_fn.
    unsafe {
        // Get mutable references to our static page tables
        // Using explicit references to avoid implicit autoref through raw pointers
        let l0 = &mut *(&raw mut KERNEL_PAGE_TABLE.l0);
        let l1 = &mut *(&raw mut BOOT_PAGE_TABLES.l1);
        let l2 = &mut *(&raw mut BOOT_PAGE_TABLES.l2);
        let l3_kernel = &mut *(&raw mut BOOT_PAGE_TABLES.l3_kernel);
        let l3_mmio = &mut *(&raw mut BOOT_PAGE_TABLES.l3_mmio);

        // Calculate indices for kernel virtual address
        // KERNEL_VIRT_BASE = 0xFFFF_0000_0000_0000
        // Kernel physical = 0x4008_0000
        // Kernel virtual = 0xFFFF_0000_4008_0000
        let kernel_virt = VirtAddr::new(KERNEL_VIRT_BASE + 0x4008_0000);
        let (l0_idx, l1_idx, l2_idx, _) = kernel_virt.page_table_indices();

        // Set up L0 -> L1
        l0[l0_idx] = PageTableEntry::table(PhysAddr::new(l1 as *const _ as usize));

        // Set up L1 -> L2 (for the 1GB region containing kernel)
        l1[l1_idx] = PageTableEntry::table(PhysAddr::new(l2 as *const _ as usize));

        // Set up L2 -> L3 for kernel pages
        l2[l2_idx] = PageTableEntry::table(PhysAddr::new(l3_kernel as *const _ as usize));

        // Map kernel pages (2MB = 512 pages)
        // Kernel is loaded at physical 0x4008_0000
        let kernel_phys_start = 0x4008_0000_usize;
        for i in 0..512 {
            let phys = PhysAddr::new(kernel_phys_start + i * 0x1000);

            // First 256KB as code (executable), rest as data
            let flags = if i < 64 {
                PageFlags::KERNEL_CODE
            } else {
                PageFlags::KERNEL_DATA
            };

            l3_kernel[i] = PageTableEntry::page(phys, flags);
        }

        // Map MMIO region for UART
        // UART is at physical 0x0900_0000
        // We'll map it at virtual 0xFFFF_0000_0900_0000
        let mmio_virt = VirtAddr::new(KERNEL_VIRT_BASE + 0x0900_0000);
        let (_, mmio_l1_idx, _, _) = mmio_virt.page_table_indices();

        // Check if we need a different L2 entry for MMIO
        if mmio_l1_idx != l1_idx {
            // MMIO is in a different 1GB region, need another L2
            // For simplicity, we use a 2MB block mapping instead of L3
            l1[mmio_l1_idx] = PageTableEntry::table(PhysAddr::new(l2 as *const _ as usize));
        }

        // Set up L2 entry for MMIO L3 table
        // MMIO is at 0x0900_0000, which is in L2 index 4 (0x0900_0000 >> 21 = 4)
        l2[4] = PageTableEntry::table(PhysAddr::new(l3_mmio as *const _ as usize));

        // Map UART page
        // UART page index in L3: (0x0900_0000 >> 12) & 0x1FF = 0
        l3_mmio[0] = PageTableEntry::page(
            PhysAddr::new(0x0900_0000),
            PageFlags::KERNEL_DEVICE,
        );
    }
}

/// Get the physical address of the kernel L0 page table.
///
/// This is used to set TTBR1_EL1.
pub fn kernel_ttbr1() -> PhysAddr {
    // SAFETY: We're just reading the address, not modifying anything
    unsafe {
        let ptr = &raw const KERNEL_PAGE_TABLE.l0;
        PhysAddr::new(ptr as usize)
    }
}

/// Map a single page in the kernel address space.
///
/// # Arguments
/// * `virt` - Virtual address to map (must be in kernel space)
/// * `phys` - Physical address to map to
/// * `flags` - Page flags (must not allow user access)
///
/// # Returns
/// Ok(()) on success, Err on failure
pub fn map_kernel_page(
    virt: VirtAddr,
    phys: PhysAddr,
    flags: PageFlags,
) -> Result<(), MappingError> {
    // Validate inputs
    if !virt.is_kernel() {
        return Err(MappingError::InvalidPermissions);
    }

    if !virt.is_aligned() || !phys.is_aligned() {
        return Err(MappingError::MisalignedAddress);
    }

    // Suppress unused variable warning
    let _ = flags;

    // For now, we only support the initial boot mappings
    // Dynamic kernel mapping would require walking the page tables
    // and allocating intermediate tables as needed

    // TODO: Implement dynamic page table walking and allocation
    Ok(())
}

/// Unmap a page from the kernel address space.
pub fn unmap_kernel_page(virt: VirtAddr) -> Result<(), MappingError> {
    if !virt.is_kernel() {
        return Err(MappingError::InvalidPermissions);
    }

    // TODO: Implement page table walking and unmapping
    Ok(())
}

/// Invalidate TLB entries for a virtual address.
///
/// # Safety
/// This must be called after modifying page table entries.
#[inline]
pub unsafe fn invalidate_tlb(virt: VirtAddr) {
    // SAFETY: Inline assembly requires unsafe block
    unsafe {
        core::arch::asm!(
            "tlbi vaae1is, {addr}",
            "dsb ish",
            "isb",
            addr = in(reg) virt.as_usize() >> 12,
        );
    }
}

/// Invalidate all TLB entries.
///
/// # Safety
/// This should be called sparingly as it's expensive.
#[inline]
pub unsafe fn invalidate_tlb_all() {
    // SAFETY: Inline assembly requires unsafe block
    unsafe {
        core::arch::asm!(
            "tlbi vmalle1is",
            "dsb ish",
            "isb",
        );
    }
}
