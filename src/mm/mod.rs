//! Memory Management Module for PantherOS
//!
//! Provides:
//! - Physical and virtual address types
//! - Page table management (ARM64 VMSA)
//! - Physical frame allocation
//! - Kernel heap allocation
//!
//! # Security Principles
//! - Type-safe address handling prevents mixing physical/virtual
//! - Page flags are strictly typed to prevent invalid combinations
//! - All allocations are zeroed before returning
//! - Unsafe code is minimal and audited

pub mod address;
pub mod allocator;
pub mod frame;
pub mod mapper;
pub mod paging;

pub use address::{PhysAddr, VirtAddr, PAGE_SIZE, KERNEL_VIRT_BASE};
pub use allocator::{heap_size, init_heap};
pub use frame::{alloc_frame, free_frame, init_frame_allocator, PhysFrame};
pub use mapper::{init_kernel_page_tables, kernel_ttbr1, map_kernel_page};
pub use paging::{MappingError, PageFlags, PageTable, PageTableEntry};

/// Initialize all memory management subsystems.
///
/// This must be called early in the boot process.
///
/// # Safety
/// Must be called once before any memory operations.
pub unsafe fn init() {
    // Initialize the frame allocator with available memory
    // QEMU virt machine has RAM from 0x4000_0000
    // We reserve the first 2MB for kernel and start allocating after
    let mem_start = PhysAddr::new(0x4020_0000);
    let mem_end = PhysAddr::new(0x4800_0000); // 128MB total

    init_frame_allocator(mem_start, mem_end);

    // Initialize kernel page tables
    // SAFETY: We are in early boot, MMU is off (or strict checking is disabled).
    unsafe {
        init_kernel_page_tables();
    }

    // Initialize the kernel heap
    // SAFETY: Heap memory region is valid.
    unsafe {
        init_heap();
    }
}

/// Memory region descriptor.
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub name: &'static str,
}

impl MemoryRegion {
    pub const fn size(&self) -> usize {
        self.end.as_usize() - self.start.as_usize()
    }
}
