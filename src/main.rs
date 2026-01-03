//! PantherOS - Minimal Security-Focused ARM64 Kernel
//!
//! A paravirtualized Rust kernel targeting QEMU/UTM on Apple Silicon.
//!
//! # Security Features
//! - Memory safety via Rust's ownership model
//! - Clear privilege boundaries (EL0/EL1)
//! - Validated system call interface
//! - Auditable unsafe code patterns
//!
//! # Architecture
//! - Target: AArch64 (ARM64)
//! - Hypervisor: QEMU virt machine
//! - Boot: Direct kernel boot (no bootloader)

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]
#![deny(unsafe_op_in_unsafe_fn)]

extern crate alloc;

mod drivers;
mod exception;
mod mm;
mod syscall;

use core::arch::global_asm;
use core::panic::PanicInfo;

use drivers::uart::UART;

// Include boot assembly
global_asm!(include_str!("boot.S"));

/// Kernel version string
const VERSION: &str = "0.1.0";

/// Kernel entry point called from boot.S
///
/// # Safety
/// This function is called once from assembly after basic CPU setup.
/// Stack and BSS are already initialized.
#[no_mangle]
pub extern "C" fn kernel_main() -> ! {
    // Initialize UART for console output first
    // SAFETY: UART address is guaranteed valid by QEMU virt machine spec
    // Audited: 2025-01-04
    unsafe {
        UART.lock().init();
    }

    // Print boot banner
    kprintln!();
    kprintln!("PantherOS v{} - Security-Focused ARM64 Kernel", VERSION);
    kprintln!("================================================");
    kprintln!();

    kprintln!("[BOOT] Initializing kernel...");
    kprintln!("[BOOT] UART initialized");

    // Initialize heap allocator
    mm::init_heap();
    let heap_size = mm::heap_size() / 1024;
    kprintln!("[BOOT] Heap initialized ({} KiB)", heap_size);

    // Initialize exception handling
    exception::init();

    // Main boot message
    kprintln!();
    kprintln!("Hello from PantherOS!");
    kprintln!();
    kprintln!("[BOOT] Kernel initialization complete");

    // Halt the CPU
    kprintln!("[BOOT] Halting CPU...");
    halt();
}

/// Halt the CPU in a low-power state
fn halt() -> ! {
    loop {
        // SAFETY: WFI is always safe to execute
        // Audited: 2025-01-04
        unsafe {
            core::arch::asm!("wfi");
        }
    }
}

/// Panic handler - called on unrecoverable errors
///
/// # Security Note
/// In a production kernel, this should:
/// 1. Log the panic to secure storage
/// 2. Attempt graceful shutdown
/// 3. Never expose internal state to untrusted code
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    kprintln!();
    kprintln!("!!! KERNEL PANIC !!!");
    kprintln!();

    if let Some(location) = info.location() {
        kprintln!(
            "Location: {}:{}:{}",
            location.file(),
            location.line(),
            location.column()
        );
    }

    kprintln!("Message: {}", info.message());

    kprintln!();
    kprintln!("System halted.");

    halt();
}
