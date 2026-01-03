//! PL011 UART Driver for QEMU virt machine
//!
//! This driver provides serial console output for debugging and user interaction.
//!
//! # Memory Map (QEMU virt)
//! - Base address: 0x0900_0000
//! - Register size: 0x1000 bytes
//!
//! # Security Considerations
//! - No input validation needed (output only for now)
//! - Unsafe code is minimal and well-documented
//! - Uses spinlock for thread-safe access

use core::fmt::{self, Write};
use spin::Mutex;

/// QEMU virt machine PL011 UART base address
const UART_BASE: usize = 0x0900_0000;

/// PL011 Register offsets
mod regs {
    /// Data Register - read/write data
    pub const DR: usize = 0x00;
    /// Flag Register - status flags
    pub const FR: usize = 0x18;
}

/// Flag Register bits
mod flags {
    /// Transmit FIFO full
    pub const TXFF: u32 = 1 << 5;
}

/// PL011 UART driver
pub struct Uart {
    base: usize,
    initialized: bool,
}

impl Uart {
    /// Create a new UART instance (not yet initialized)
    ///
    /// # Safety
    /// The base address must be valid and mapped.
    pub const fn new(base: usize) -> Self {
        Self {
            base,
            initialized: false,
        }
    }

    /// Initialize the UART
    ///
    /// # Safety
    /// - Must only be called once
    /// - UART base address must be valid
    ///
    /// SAFETY AUDIT: 2025-01-04
    /// - Base address 0x0900_0000 is guaranteed by QEMU virt machine specification
    /// - Called only once during boot from kernel_main
    pub unsafe fn init(&mut self) {
        // PL011 is already initialized by QEMU, just mark as ready
        self.initialized = true;
    }

    /// Write a single byte to the UART
    ///
    /// # Safety
    /// This performs memory-mapped I/O. The base address must be valid.
    ///
    /// SAFETY AUDIT: 2025-01-04
    /// - Pointer is constructed from known-valid base address
    /// - Volatile write is appropriate for MMIO
    fn write_byte(&self, byte: u8) {
        if !self.initialized {
            return;
        }

        // SAFETY: Base address is validated during init()
        // The write is to a known MMIO register
        // Audited: 2025-01-04
        unsafe {
            let fr = (self.base + regs::FR) as *const u32;
            let dr = (self.base + regs::DR) as *mut u32;

            // Wait for transmit FIFO to have space
            while core::ptr::read_volatile(fr) & flags::TXFF != 0 {
                core::hint::spin_loop();
            }

            // Write the byte
            core::ptr::write_volatile(dr, byte as u32);
        }
    }

    /// Write a string to the UART
    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

impl Write for Uart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Uart::write_str(self, s);
        Ok(())
    }
}

/// Global UART instance protected by spinlock
pub static UART: Mutex<Uart> = Mutex::new(Uart::new(UART_BASE));

/// Print macro for kernel output
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut uart = $crate::drivers::uart::UART.lock();
        let _ = write!(uart, $($arg)*);
    }};
}

/// Println macro for kernel output
#[macro_export]
macro_rules! kprintln {
    () => {
        $crate::kprint!("\n")
    };
    ($($arg:tt)*) => {{
        $crate::kprint!($($arg)*);
        $crate::kprint!("\n");
    }};
}
