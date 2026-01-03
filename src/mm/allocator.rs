//! Kernel Heap Allocator
//!
//! Uses `linked_list_allocator` for heap management.
//!
//! # Memory Layout
//! The heap region is defined by linker symbols:
//! - `__heap_start`: Beginning of heap
//! - `__heap_end`: End of available RAM
//!
//! # Security Considerations
//! - Heap is initialized once during boot
//! - All allocations go through Rust's global allocator
//! - linked_list_allocator provides bounds checking

use core::alloc::Layout;
use linked_list_allocator::LockedHeap;

/// Global heap allocator instance
#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Maximum heap size (64 KiB for now, conservative for testing)
const HEAP_SIZE: usize = 64 * 1024;

/// Static heap memory region
/// This avoids relying on linker symbols which can be tricky
static mut HEAP_MEMORY: [u8; HEAP_SIZE] = [0; HEAP_SIZE];

/// Initialize the kernel heap
///
/// # Safety
/// This function must be called exactly once during kernel initialization,
/// before any heap allocations are made.
///
/// SAFETY AUDIT: 2025-01-04
/// - Called once from kernel_main after UART init
/// - HEAP_MEMORY is a static, valid memory region
/// - linked_list_allocator handles internal safety
pub fn init_heap() {
    // SAFETY: 
    // - HEAP_MEMORY is a valid static array
    // - This function is only called once during boot
    // - No other code accesses HEAP_MEMORY directly
    // Audited: 2025-01-04
    unsafe {
        let heap_start = HEAP_MEMORY.as_mut_ptr();
        ALLOCATOR.lock().init(heap_start, HEAP_SIZE);
    }
}

/// Get the size of the kernel heap
pub fn heap_size() -> usize {
    HEAP_SIZE
}

/// Allocation error handler
///
/// Called when heap allocation fails. In a security-focused kernel,
/// we should:
/// 1. Log the failure
/// 2. Attempt graceful degradation
/// 3. Never expose internal state
#[alloc_error_handler]
fn alloc_error_handler(layout: Layout) -> ! {
    panic!(
        "Heap allocation failed: size={}, align={}",
        layout.size(),
        layout.align()
    );
}
