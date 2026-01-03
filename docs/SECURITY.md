# Security Model

PantherOS is designed with security as the primary goal. This document outlines the threat model, security assumptions, and mitigation strategies.

## Threat Model

### Assets to Protect
1. **Kernel Integrity** - Kernel code and data must not be modified by user processes
2. **Memory Isolation** - User processes cannot access kernel memory
3. **Privilege Boundaries** - Syscall interface is the only way to transition to kernel mode
4. **System Stability** - User input cannot crash the kernel

### Threat Actors
1. **Malicious User Process** - Attempts to escalate privileges or access unauthorized resources
2. **Buggy User Process** - Accidental memory corruption or invalid syscall parameters
3. **Network Attacker** - (Future) Malformed network packets

## Security Measures

### 1. Memory Safety (Rust Guarantees)

| Vulnerability Class    | Mitigation                           |
|------------------------|--------------------------------------|
| Buffer Overflow        | Bounds checking on all array access  |
| Use-After-Free         | Ownership model prevents dangling    |
| Double Free            | Ownership model prevents             |
| Null Pointer Deref     | `Option<T>` for nullable values      |
| Data Races             | Borrow checker prevents              |

### 2. Privilege Separation

```
┌─────────────────────────────────────────┐
│          User Space (EL0)               │
│  - Cannot access kernel memory          │
│  - Cannot execute privileged instrs     │
│  - Must use SVC for kernel services     │
└─────────────────────────────────────────┘
                    │ SVC #0
                    ▼
┌─────────────────────────────────────────┐
│          Kernel Space (EL1)             │
│  - Full memory access                   │
│  - Privileged instructions              │
│  - Validates ALL user input             │
└─────────────────────────────────────────┘
```

### 3. System Call Validation

All syscall parameters are validated before use:

```rust
fn sys_write(fd: i32, buf: usize, len: usize) -> i64 {
    // 1. Validate file descriptor
    if fd != 1 && fd != 2 {
        return Err(EBADF);
    }
    
    // 2. Validate buffer pointer
    if !is_user_address(buf) {
        return Err(EFAULT);
    }
    
    // 3. Validate length (no overflow)
    if buf.checked_add(len).is_none() {
        return Err(EFAULT);
    }
    
    // 4. Check bounds
    if !is_user_range(buf, len) {
        return Err(EFAULT);
    }
    
    // Now safe to use
}
```

### 4. Unsafe Code Audit

All unsafe blocks follow this pattern:

```rust
/// SAFETY:
/// - Why this operation is safe
/// - What invariants must hold
/// Audited: 2025-01-04
unsafe {
    // Minimal code here
}
```

## Security Assumptions

### What We Trust
1. **Hypervisor (QEMU)** - Correctly implements memory isolation and CPU virtualization
2. **Rust Compiler** - Generates correct code that upholds safety guarantees
3. **Hardware** - CPU correctly enforces privilege levels

### What We Don't Trust
1. **User Processes** - All input is validated
2. **User Memory** - Can change at any time (TOCTOU awareness)

## Explicit Non-Goals

| Attack Class           | Why Not Addressed                    |
|------------------------|--------------------------------------|
| Spectre/Meltdown       | Requires microarchitectural fixes    |
| Physical Attacks       | VM controlled by user                |
| Supply Chain           | Dependency auditing is separate      |
| Side Channels          | Requires constant-time crypto        |

## Audit Checklist

Before each release:

- [ ] All `unsafe` blocks have SAFETY comments
- [ ] All syscalls validate ALL parameters
- [ ] No `unwrap()` or `expect()` in kernel code
- [ ] No panics possible from user input
- [ ] Clippy passes with no warnings
- [ ] MIRI passes on testable modules

## Reporting Security Issues

Please report security vulnerabilities via private channels. Do not open public issues for security bugs.
