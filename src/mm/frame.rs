//! Physical Frame Allocator
//!
//! Manages physical memory pages (frames) using a bitmap allocator.
//!
//! # Design
//! - Each bit in the bitmap represents one 4KB frame
//! - Bit = 0: frame is free
//! - Bit = 1: frame is allocated
//!
//! # Security Properties
//! - All allocated frames are zeroed before returning
//! - Double-free is detected and causes a panic
//! - The allocator is protected by a spinlock

use spin::Mutex;

use super::address::{PhysAddr, PAGE_SIZE, PAGE_SHIFT};

/// Size of the frame bitmap in bytes.
/// This covers 64MB of physical memory (enough for early boot).
/// 64MB / 4KB = 16384 frames = 2048 bytes = 16384 bits
const BITMAP_SIZE: usize = 2048;

/// Number of frames we can track.
const MAX_FRAMES: usize = BITMAP_SIZE * 8;

/// Starting physical address for allocatable frames.
/// We skip the first 2MB to avoid kernel code/data.
const FRAME_START: usize = 0x4020_0000;

/// Frame allocator state.
struct FrameAllocatorInner {
    /// Bitmap tracking allocated frames (1 = allocated, 0 = free).
    bitmap: [u8; BITMAP_SIZE],
    /// Number of free frames remaining.
    free_count: usize,
    /// Total frames under management.
    total_frames: usize,
    /// Whether the allocator has been initialized.
    initialized: bool,
}

impl FrameAllocatorInner {
    const fn new() -> Self {
        Self {
            bitmap: [0; BITMAP_SIZE],
            free_count: 0,
            total_frames: 0,
            initialized: false,
        }
    }

    /// Initialize the frame allocator.
    fn init(&mut self, mem_start: PhysAddr, mem_end: PhysAddr) {
        if self.initialized {
            return;
        }

        let start_frame = (mem_start.as_usize().max(FRAME_START) - FRAME_START) >> PAGE_SHIFT;
        let end_frame = ((mem_end.as_usize() - FRAME_START) >> PAGE_SHIFT).min(MAX_FRAMES);

        if end_frame <= start_frame {
            panic!("Invalid memory range for frame allocator");
        }

        self.total_frames = end_frame - start_frame;
        self.free_count = self.total_frames;

        // Mark all frames as free initially (bitmap is already zeroed)
        // But mark frames before our usable range as allocated
        for i in 0..start_frame {
            self.set_bit(i, true);
        }

        self.initialized = true;
    }

    /// Set a bit in the bitmap.
    #[inline]
    fn set_bit(&mut self, frame: usize, allocated: bool) {
        let byte_idx = frame / 8;
        let bit_idx = frame % 8;

        if byte_idx >= BITMAP_SIZE {
            return;
        }

        if allocated {
            self.bitmap[byte_idx] |= 1 << bit_idx;
        } else {
            self.bitmap[byte_idx] &= !(1 << bit_idx);
        }
    }

    /// Check if a frame is allocated.
    #[inline]
    fn is_allocated(&self, frame: usize) -> bool {
        let byte_idx = frame / 8;
        let bit_idx = frame % 8;

        if byte_idx >= BITMAP_SIZE {
            return true; // Out of range = allocated
        }

        (self.bitmap[byte_idx] >> bit_idx) & 1 == 1
    }

    /// Allocate a single frame.
    fn alloc(&mut self) -> Option<PhysAddr> {
        if !self.initialized || self.free_count == 0 {
            return None;
        }

        // Linear search for a free frame
        // TODO: Optimize with free list or buddy allocator
        for byte_idx in 0..BITMAP_SIZE {
            if self.bitmap[byte_idx] != 0xFF {
                // Found a byte with at least one free bit
                for bit_idx in 0..8 {
                    let frame = byte_idx * 8 + bit_idx;
                    if frame >= MAX_FRAMES {
                        break;
                    }

                    if !self.is_allocated(frame) {
                        self.set_bit(frame, true);
                        self.free_count -= 1;

                        let addr = PhysAddr::new(FRAME_START + (frame << PAGE_SHIFT));
                        return Some(addr);
                    }
                }
            }
        }

        None
    }

    /// Free a previously allocated frame.
    fn free(&mut self, addr: PhysAddr) {
        if !self.initialized {
            return;
        }

        if !addr.is_aligned() {
            panic!("Attempted to free unaligned address: {:?}", addr);
        }

        let frame = (addr.as_usize() - FRAME_START) >> PAGE_SHIFT;

        if frame >= MAX_FRAMES {
            panic!("Attempted to free frame outside managed range: {:?}", addr);
        }

        if !self.is_allocated(frame) {
            panic!("Double free detected for frame: {:?}", addr);
        }

        self.set_bit(frame, false);
        self.free_count += 1;
    }

    /// Get the number of free frames.
    fn free_frames(&self) -> usize {
        self.free_count
    }
}

/// Global frame allocator instance.
static FRAME_ALLOCATOR: Mutex<FrameAllocatorInner> = Mutex::new(FrameAllocatorInner::new());

/// Initialize the frame allocator with the given memory range.
///
/// # Arguments
/// * `mem_start` - Start of usable physical memory
/// * `mem_end` - End of usable physical memory
pub fn init_frame_allocator(mem_start: PhysAddr, mem_end: PhysAddr) {
    FRAME_ALLOCATOR.lock().init(mem_start, mem_end);
}

/// Allocate a single physical frame.
///
/// Returns `None` if no frames are available.
/// The returned frame is zeroed.
pub fn alloc_frame() -> Option<PhysAddr> {
    let addr = FRAME_ALLOCATOR.lock().alloc()?;

    // Zero the frame for security
    // SAFETY: The frame was just allocated so we have exclusive access.
    // The address is valid and aligned.
    unsafe {
        unsafe { core::ptr::write_bytes(addr.as_usize() as *mut u8, 0, PAGE_SIZE) };
    }

    Some(addr)
}

/// Allocate a zeroed physical frame, returning an error instead of None.
pub fn alloc_frame_zeroed() -> Result<PhysAddr, super::paging::MappingError> {
    alloc_frame().ok_or(super::paging::MappingError::OutOfMemory)
}

/// Free a physical frame.
///
/// # Panics
/// Panics if:
/// - The address is not page-aligned
/// - The frame was not allocated (double-free)
/// - The frame is outside the managed range
pub fn free_frame(addr: PhysAddr) {
    FRAME_ALLOCATOR.lock().free(addr);
}

/// Get the number of free frames remaining.
pub fn free_frame_count() -> usize {
    FRAME_ALLOCATOR.lock().free_frames()
}

/// A RAII guard for a physical frame that automatically frees it on drop.
///
/// This provides automatic cleanup even in error paths.
#[derive(Debug)]
pub struct PhysFrame {
    addr: PhysAddr,
}

impl PhysFrame {
    /// Allocate a new physical frame.
    pub fn alloc() -> Option<Self> {
        alloc_frame().map(|addr| Self { addr })
    }

    /// Allocate a new physical frame, returning an error on failure.
    pub fn alloc_or_err() -> Result<Self, super::paging::MappingError> {
        alloc_frame_zeroed().map(|addr| Self { addr })
    }

    /// Get the physical address of this frame.
    #[inline]
    pub fn addr(&self) -> PhysAddr {
        self.addr
    }

    /// Consume the frame without freeing it.
    ///
    /// Use this when transferring ownership to a page table.
    #[inline]
    pub fn into_addr(self) -> PhysAddr {
        let addr = self.addr;
        core::mem::forget(self);
        addr
    }
}

impl Drop for PhysFrame {
    fn drop(&mut self) {
        free_frame(self.addr);
    }
}
