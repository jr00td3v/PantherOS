# PantherOS

**A minimal, security-focused ARM64 kernel written in Rust**

PantherOS is a paravirtualized kernel designed for QEMU/UTM on Apple Silicon (M4). It demonstrates secure kernel design patterns using Rust's memory safety guarantees.

## Features

### Security Model
- **Memory Safety**: Rust's ownership model prevents use-after-free and buffer overflows
- **Privilege Separation**: Clear EL0 (user) / EL1 (kernel) boundaries
- **Validated Syscalls**: All system call parameters are validated before use
- **Audited Unsafe Code**: Every `unsafe` block is documented with safety invariants

### Current Implementation
- ✅ ARM64 boot sequence with exception vectors
- ✅ PL011 UART console driver
- ✅ Kernel heap allocator (64 KiB)
- ✅ Exception handling framework
- ✅ System call infrastructure (`exit`, `write`)
- ✅ Input validation module

## Quick Start

### Prerequisites

```bash
# Install Rust nightly (for build-std)
rustup install nightly
rustup component add rust-src --toolchain nightly

# Install QEMU (macOS)
brew install qemu
```

### Build

```bash
# Clone and build
git clone <repository>
cd testos
cargo build --release
```

### Run in QEMU

```bash
qemu-system-aarch64 \
  -machine virt \
  -cpu cortex-a72 \
  -m 128M \
  -nographic \
  -kernel target/aarch64-unknown-none/release/pantheros
```

### Expected Output

```
PantherOS v0.1.0 - Security-Focused ARM64 Kernel
================================================

[BOOT] Initializing kernel...
[BOOT] UART initialized
[BOOT] Heap initialized (64 KiB)
[BOOT] Exception vectors installed

Hello from secure kernel!

[BOOT] Kernel initialization complete
[BOOT] Halting CPU...
```

Press `Ctrl+A` then `X` to exit QEMU.

## Project Structure

```
testos/
├── .cargo/config.toml    # ARM64 target configuration
├── Cargo.toml            # Dependencies
├── linker.ld             # Memory layout
├── rust-toolchain.toml   # Nightly toolchain
├── src/
│   ├── main.rs           # Kernel entry point
│   ├── boot.S            # ARM64 assembly boot code
│   ├── exception.rs      # Exception handling
│   ├── drivers/
│   │   ├── mod.rs
│   │   └── uart.rs       # PL011 UART driver
│   ├── mm/
│   │   ├── mod.rs
│   │   └── allocator.rs  # Heap allocator
│   └── syscall/
│       ├── mod.rs
│       ├── handler.rs    # Syscall dispatcher
│       └── validate.rs   # Input validation
└── docs/
    ├── SECURITY.md       # Threat model
    └── ARCHITECTURE.md   # System design
```

## System Calls

| Number | Name    | Arguments                  | Description                |
|--------|---------|----------------------------|----------------------------|
| 0      | exit    | x0: status                 | Terminate process          |
| 1      | write   | x0: fd, x1: buf, x2: len   | Write to file descriptor   |

### Calling Convention
- Syscall number in `x8`
- Arguments in `x0` - `x5`
- Return value in `x0`
- Use `svc #0` instruction

## Security Documentation

- [SECURITY.md](docs/SECURITY.md) - Threat model and security assumptions
- [ARCHITECTURE.md](docs/ARCHITECTURE.md) - System architecture and design decisions

## Development

### Code Style

```rust
// All unsafe blocks must be documented
/// SAFETY: <explanation of why this is safe>
/// Audited: YYYY-MM-DD
unsafe {
    // Minimal unsafe code here
}
```

### Adding a New Syscall

1. Add syscall number to `syscall/handler.rs`
2. Implement handler function with validation
3. Add to dispatch match statement
4. Document in this README

## License

MIT License - See LICENSE file for details.

## Acknowledgments

- [Writing an OS in Rust](https://os.phil-opp.com/) by Philipp Oppermann
- [ARM Architecture Reference Manual](https://developer.arm.com/documentation)
- The Rust community for excellent `no_std` ecosystem
