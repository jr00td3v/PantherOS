//! ARM64 Exception Handling
//!
//! Implements the exception vector table and handlers for ARM64.
//!
//! # Exception Levels
//! - EL0: User applications
//! - EL1: Kernel (where we run)
//! - EL2: Hypervisor (QEMU)
//!
//! # Exception Types
//! - Synchronous: SVC (syscalls), data aborts, instruction aborts
//! - IRQ: Interrupt requests
//! - FIQ: Fast interrupt requests
//! - SError: System errors
//!
//! # Security Considerations
//! - All exceptions from lower EL (user mode) are handled securely
//! - Register state is preserved and restored
//! - Invalid exception sources cause immediate halt

use core::arch::asm;

use crate::{kprintln, syscall};

/// Exception context saved on the stack
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ExceptionContext {
    /// General purpose registers x0-x30
    pub gpr: [u64; 31],
    /// Exception Link Register (return address)
    pub elr: u64,
    /// Saved Program Status Register
    pub spsr: u64,
    /// Exception Syndrome Register
    pub esr: u64,
    /// Fault Address Register
    pub far: u64,
}

/// Exception class extracted from ESR_EL1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ExceptionClass {
    Unknown = 0x00,
    SvcAarch64 = 0x15,
    InstructionAbortLowerEl = 0x20,
    InstructionAbortSameEl = 0x21,
    DataAbortLowerEl = 0x24,
    DataAbortSameEl = 0x25,
    Other = 0xFF,
}

impl From<u64> for ExceptionClass {
    fn from(esr: u64) -> Self {
        let ec = ((esr >> 26) & 0x3F) as u8;
        match ec {
            0x00 => ExceptionClass::Unknown,
            0x15 => ExceptionClass::SvcAarch64,
            0x20 => ExceptionClass::InstructionAbortLowerEl,
            0x21 => ExceptionClass::InstructionAbortSameEl,
            0x24 => ExceptionClass::DataAbortLowerEl,
            0x25 => ExceptionClass::DataAbortSameEl,
            _ => ExceptionClass::Other,
        }
    }
}

/// Initialize exception handling
///
/// Sets up the exception vector table register (VBAR_EL1).
///
/// # Safety
/// Must be called once during kernel initialization.
/// The exception vectors must be properly aligned (2KB).
///
/// SAFETY AUDIT: 2025-01-04
/// - Vector table is defined in boot.S with proper alignment
/// - This function is only called once from kernel_main
pub fn init() {
    extern "C" {
        static __exception_vectors: u8;
    }

    // SAFETY: 
    // - __exception_vectors is defined in boot.S with 2KB alignment
    // - Writing to VBAR_EL1 is valid at EL1
    // Audited: 2025-01-04
    unsafe {
        let vector_addr = &__exception_vectors as *const u8 as u64;
        asm!(
            "msr vbar_el1, {v}",
            "isb",
            v = in(reg) vector_addr,
            options(nostack, preserves_flags)
        );
    }

    kprintln!("[BOOT] Exception vectors installed");
}

/// Handle synchronous exception from lower EL (user mode)
///
/// This is the main entry point for syscalls (SVC instruction).
///
/// # Safety
/// Called from assembly exception handler with valid context pointer.
#[no_mangle]
pub extern "C" fn handle_sync_exception_lower_el(ctx: &mut ExceptionContext) {
    let ec = ExceptionClass::from(ctx.esr);

    match ec {
        ExceptionClass::SvcAarch64 => {
            // System call handler
            let syscall_num = ctx.gpr[8] as usize; // x8 = syscall number
            let result = syscall::dispatch(syscall_num, ctx);
            ctx.gpr[0] = result as u64; // Return value in x0
        }
        ExceptionClass::DataAbortLowerEl | ExceptionClass::InstructionAbortLowerEl => {
            kprintln!("[EXCEPTION] User mode abort at 0x{:016x}", ctx.far);
            kprintln!("[EXCEPTION] ESR: 0x{:016x}", ctx.esr);
            kprintln!("[EXCEPTION] Terminating process...");
            // TODO: Terminate the process instead of halting
            halt();
        }
        _ => {
            kprintln!("[EXCEPTION] Unhandled exception from user mode");
            kprintln!("[EXCEPTION] EC: {:?}, ESR: 0x{:016x}", ec, ctx.esr);
            halt();
        }
    }
}

/// Handle synchronous exception from current EL (kernel mode)
///
/// This should rarely happen in normal operation.
#[no_mangle]
pub extern "C" fn handle_sync_exception_same_el(ctx: &ExceptionContext) {
    let ec = ExceptionClass::from(ctx.esr);

    kprintln!("!!! KERNEL EXCEPTION !!!");
    kprintln!("Exception Class: {:?}", ec);
    kprintln!("ESR: 0x{:016x}", ctx.esr);
    kprintln!("ELR: 0x{:016x}", ctx.elr);
    kprintln!("FAR: 0x{:016x}", ctx.far);

    halt();
}

/// Handle IRQ from lower EL
#[no_mangle]
pub extern "C" fn handle_irq_lower_el(_ctx: &mut ExceptionContext) {
    kprintln!("[IRQ] IRQ from user mode (not implemented)");
    // TODO: Implement interrupt handling
}

/// Handle IRQ from current EL
#[no_mangle]
pub extern "C" fn handle_irq_same_el(_ctx: &ExceptionContext) {
    kprintln!("[IRQ] IRQ from kernel mode (not implemented)");
    // TODO: Implement interrupt handling
}

/// Halt the CPU
fn halt() -> ! {
    loop {
        // SAFETY: WFI is always safe
        unsafe {
            asm!("wfi", options(nostack, nomem));
        }
    }
}
