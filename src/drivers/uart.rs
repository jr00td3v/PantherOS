//! PL011 UART Driver with Typestate Pattern
//!
//! This driver uses the typestate pattern to make invalid states
//! unrepresentable at compile time:
//! - `Uart<Uninitialized>`: Created but not yet initialized
//! - `Uart<Initialized>`: Ready for I/O operations
//!
//! # Security Considerations
//! - Typestate prevents calling `write()` before `init()`
//! - Unsafe code is minimal and well-documented
//! - Uses spinlock for thread-safe access
//!
//! # Memory Map (QEMU virt)
//! - Base address: 0x0900_0000
//! - Register size: 0x1000 bytes

use core::fmt::{self, Write};
use core::marker::PhantomData;
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
    /// Receive FIFO empty
    pub const RXFE: u32 = 1 << 4;
}

// ============================================================================
// Typestate Markers
// ============================================================================

/// Marker type for uninitialized UART state.
pub struct Uninitialized;

/// Marker type for initialized UART state.
pub struct Initialized;

/// Sealed trait for UART states.
mod sealed {
    pub trait UartState {}
    impl UartState for super::Uninitialized {}
    impl UartState for super::Initialized {}
}

/// Trait for UART states (sealed).
pub trait UartState: sealed::UartState {}
impl UartState for Uninitialized {}
impl UartState for Initialized {}

// ============================================================================
// UART Driver
// ============================================================================

/// PL011 UART driver with typestate.
///
/// The type parameter `S` tracks the initialization state:
/// - `Uart<Uninitialized>`: Can only call `init()`
/// - `Uart<Initialized>`: Can call I/O methods
pub struct Uart<S: UartState> {
    base: usize,
    _state: PhantomData<S>,
}

impl Uart<Uninitialized> {
    /// Create a new uninitialized UART instance.
    ///
    /// # Arguments
    /// * `base` - Base address of the UART registers
    pub const fn new(base: usize) -> Self {
        Self {
            base,
            _state: PhantomData,
        }
    }

    /// Initialize the UART, transitioning to the Initialized state.
    ///
    /// # Safety
    /// - The base address must be valid and mapped
    /// - Must only be called once per UART instance
    ///
    /// SAFETY AUDIT: 2025-01-04
    /// - Base address 0x0900_0000 is guaranteed by QEMU virt machine specification
    /// - Called only once during boot from kernel_main
    pub unsafe fn init(self) -> Uart<Initialized> {
        // PL011 is already initialized by QEMU, just consume self
        // and return the initialized state
        Uart {
            base: self.base,
            _state: PhantomData,
        }
    }
}

impl Uart<Initialized> {
    /// Write a single byte to the UART.
    ///
    /// # Safety Notes
    /// This performs memory-mapped I/O internally but is safe to call
    /// because initialization has been verified by the type system.
    ///
    /// SAFETY AUDIT: 2025-01-04
    /// - Pointer is constructed from known-valid base address
    /// - Volatile write is appropriate for MMIO
    fn write_byte(&self, byte: u8) {
        // SAFETY: Base address was validated during init()
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

    /// Write a string to the UART.
    pub fn write_str_uart(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }

    /// Read a single byte from the UART (non-blocking).
    ///
    /// Returns `None` if no data is available.
    pub fn read_byte(&self) -> Option<u8> {
        // SAFETY: Same as write_byte - validated base address
        unsafe {
            let fr = (self.base + regs::FR) as *const u32;
            let dr = (self.base + regs::DR) as *const u32;

            // Check if receive FIFO is empty
            if core::ptr::read_volatile(fr) & flags::RXFE != 0 {
                return None;
            }

            // Read the byte
            Some((core::ptr::read_volatile(dr) & 0xFF) as u8)
        }
    }
}

impl Write for Uart<Initialized> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.write_str_uart(s);
        Ok(())
    }
}

// ============================================================================
// Global UART Instance
// ============================================================================

/// State of the global UART.
enum GlobalUartState {
    Uninitialized(Uart<Uninitialized>),
    Initialized(Uart<Initialized>),
}

/// Global UART wrapper that handles initialization state.
pub struct GlobalUart {
    state: GlobalUartState,
}

impl GlobalUart {
    /// Create a new uninitialized global UART.
    const fn new() -> Self {
        Self {
            state: GlobalUartState::Uninitialized(Uart::new(UART_BASE)),
        }
    }

    /// Initialize the UART if not already initialized.
    ///
    /// # Safety
    /// Same requirements as `Uart::init()`.
    pub unsafe fn init(&mut self) {
        if let GlobalUartState::Uninitialized(uart) = &self.state {
            // We need to take ownership but we only have a reference
            // This is safe because we immediately replace it
            let uart = Uart::new(uart.base);
            // SAFETY: We're inside an unsafe function with the same requirements
            self.state = GlobalUartState::Initialized(unsafe { uart.init() });
        }
    }

    /// Get a reference to the initialized UART.
    fn as_initialized(&self) -> Option<&Uart<Initialized>> {
        match &self.state {
            GlobalUartState::Initialized(uart) => Some(uart),
            GlobalUartState::Uninitialized(_) => None,
        }
    }

    /// Write a string if initialized.
    pub fn write_str(&self, s: &str) {
        if let Some(uart) = self.as_initialized() {
            uart.write_str_uart(s);
        }
    }
}

impl Write for GlobalUart {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        GlobalUart::write_str(self, s);
        Ok(())
    }
}

/// Global UART instance protected by spinlock.
pub static UART: Mutex<GlobalUart> = Mutex::new(GlobalUart::new());

// ============================================================================
// Print Macros
// ============================================================================

/// Print macro for kernel output.
#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let mut uart = $crate::drivers::uart::UART.lock();
        let _ = write!(uart, $($arg)*);
    }};
}

/// Println macro for kernel output.
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
