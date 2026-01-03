/*
 * PantherOS ARM64 Boot Assembly
 * 
 * Entry point for the kernel. Sets up the environment and jumps to Rust.
 * 
 * SAFETY NOTES:
 * - Assumes we're running at EL1 (hypervisor has set this up)
 * - Assumes RAM is available at 0x40080000
 * - Stack symbols provided by linker script
 */

.section .text._start
.global _start

_start:
    /* Disable interrupts while we set up */
    msr daifset, #0xf

    /* Get current exception level (should be EL1) */
    mrs x0, CurrentEL
    lsr x0, x0, #2
    cmp x0, #1
    b.ne .hang          /* Hang if not EL1 */

    /* Set up stack pointer using linker-provided symbol */
    ldr x0, =__stack_top
    mov sp, x0

    /* Zero the BSS section */
    ldr x0, =__bss_start
    ldr x1, =__bss_end
.bss_zero_loop:
    cmp x0, x1
    b.ge .bss_zero_done
    str xzr, [x0], #8
    b .bss_zero_loop
.bss_zero_done:

    /* Jump to Rust kernel_main */
    bl kernel_main

    /* If kernel_main returns, halt the CPU */
.hang:
    wfi
    b .hang

/*
 * Exception Vector Table
 * 
 * ARM64 requires a 2KB aligned exception vector table.
 * Each entry is 128 bytes (32 instructions), but we use less
 * and branch to our handler code.
 * 
 * There are 16 entries total:
 * - 4 for current EL with SP0
 * - 4 for current EL with SPx  
 * - 4 for lower EL using AArch64
 * - 4 for lower EL using AArch32
 * 
 * Each group has: Synchronous, IRQ, FIQ, SError
 */
.section .text.vectors
.balign 2048
.global __exception_vectors
__exception_vectors:

/* ============================================ */
/* Current EL with SP0 (not used, we use SPx)   */
/* ============================================ */
.balign 128
current_el_sp0_sync:
    b .hang

.balign 128
current_el_sp0_irq:
    b .hang

.balign 128
current_el_sp0_fiq:
    b .hang

.balign 128
current_el_sp0_serror:
    b .hang

/* ============================================ */
/* Current EL with SPx (kernel mode exceptions) */
/* ============================================ */
.balign 128
current_el_spx_sync:
    /* Save context and call handler */
    sub sp, sp, #(34 * 8)
    stp x0, x1, [sp, #(0 * 8)]
    stp x2, x3, [sp, #(2 * 8)]
    stp x4, x5, [sp, #(4 * 8)]
    stp x6, x7, [sp, #(6 * 8)]
    stp x8, x9, [sp, #(8 * 8)]
    stp x10, x11, [sp, #(10 * 8)]
    stp x12, x13, [sp, #(12 * 8)]
    stp x14, x15, [sp, #(14 * 8)]
    stp x16, x17, [sp, #(16 * 8)]
    stp x18, x19, [sp, #(18 * 8)]
    stp x20, x21, [sp, #(20 * 8)]
    stp x22, x23, [sp, #(22 * 8)]
    stp x24, x25, [sp, #(24 * 8)]
    stp x26, x27, [sp, #(26 * 8)]
    stp x28, x29, [sp, #(28 * 8)]
    str x30, [sp, #(30 * 8)]
    
    mrs x0, elr_el1
    mrs x1, spsr_el1
    mrs x2, esr_el1
    mrs x3, far_el1
    stp x0, x1, [sp, #(31 * 8)]
    stp x2, x3, [sp, #(33 * 8)]
    
    mov x0, sp
    bl handle_sync_exception_same_el
    b .hang  /* Should not return */

.balign 128
current_el_spx_irq:
    b .hang

.balign 128
current_el_spx_fiq:
    b .hang

.balign 128
current_el_spx_serror:
    b .hang

/* ============================================ */
/* Lower EL using AArch64 (user mode syscalls)  */
/* ============================================ */
.balign 128
lower_el_aarch64_sync:
    /* Save full context for syscalls */
    sub sp, sp, #(35 * 8)
    
    /* Save general purpose registers x0-x30 */
    stp x0, x1, [sp, #(0 * 8)]
    stp x2, x3, [sp, #(2 * 8)]
    stp x4, x5, [sp, #(4 * 8)]
    stp x6, x7, [sp, #(6 * 8)]
    stp x8, x9, [sp, #(8 * 8)]
    stp x10, x11, [sp, #(10 * 8)]
    stp x12, x13, [sp, #(12 * 8)]
    stp x14, x15, [sp, #(14 * 8)]
    stp x16, x17, [sp, #(16 * 8)]
    stp x18, x19, [sp, #(18 * 8)]
    stp x20, x21, [sp, #(20 * 8)]
    stp x22, x23, [sp, #(22 * 8)]
    stp x24, x25, [sp, #(24 * 8)]
    stp x26, x27, [sp, #(26 * 8)]
    stp x28, x29, [sp, #(28 * 8)]
    str x30, [sp, #(30 * 8)]
    
    /* Save special registers */
    mrs x0, elr_el1
    mrs x1, spsr_el1
    mrs x2, esr_el1
    mrs x3, far_el1
    stp x0, x1, [sp, #(31 * 8)]
    stp x2, x3, [sp, #(33 * 8)]
    
    /* Call Rust handler with context pointer */
    mov x0, sp
    bl handle_sync_exception_lower_el
    
    /* Restore special registers */
    ldp x0, x1, [sp, #(31 * 8)]
    msr elr_el1, x0
    msr spsr_el1, x1
    
    /* Restore general purpose registers */
    ldp x0, x1, [sp, #(0 * 8)]
    ldp x2, x3, [sp, #(2 * 8)]
    ldp x4, x5, [sp, #(4 * 8)]
    ldp x6, x7, [sp, #(6 * 8)]
    ldp x8, x9, [sp, #(8 * 8)]
    ldp x10, x11, [sp, #(10 * 8)]
    ldp x12, x13, [sp, #(12 * 8)]
    ldp x14, x15, [sp, #(14 * 8)]
    ldp x16, x17, [sp, #(16 * 8)]
    ldp x18, x19, [sp, #(18 * 8)]
    ldp x20, x21, [sp, #(20 * 8)]
    ldp x22, x23, [sp, #(22 * 8)]
    ldp x24, x25, [sp, #(24 * 8)]
    ldp x26, x27, [sp, #(26 * 8)]
    ldp x28, x29, [sp, #(28 * 8)]
    ldr x30, [sp, #(30 * 8)]
    
    add sp, sp, #(35 * 8)
    eret

.balign 128
lower_el_aarch64_irq:
    /* Save minimal context for IRQ */
    sub sp, sp, #(35 * 8)
    stp x0, x1, [sp, #(0 * 8)]
    stp x2, x3, [sp, #(2 * 8)]
    stp x4, x5, [sp, #(4 * 8)]
    stp x6, x7, [sp, #(6 * 8)]
    stp x8, x9, [sp, #(8 * 8)]
    stp x10, x11, [sp, #(10 * 8)]
    stp x12, x13, [sp, #(12 * 8)]
    stp x14, x15, [sp, #(14 * 8)]
    stp x16, x17, [sp, #(16 * 8)]
    stp x18, x19, [sp, #(18 * 8)]
    stp x20, x21, [sp, #(20 * 8)]
    stp x22, x23, [sp, #(22 * 8)]
    stp x24, x25, [sp, #(24 * 8)]
    stp x26, x27, [sp, #(26 * 8)]
    stp x28, x29, [sp, #(28 * 8)]
    str x30, [sp, #(30 * 8)]
    
    mrs x0, elr_el1
    mrs x1, spsr_el1
    mrs x2, esr_el1
    mrs x3, far_el1
    stp x0, x1, [sp, #(31 * 8)]
    stp x2, x3, [sp, #(33 * 8)]
    
    mov x0, sp
    bl handle_irq_lower_el
    
    ldp x0, x1, [sp, #(31 * 8)]
    msr elr_el1, x0
    msr spsr_el1, x1
    
    ldp x0, x1, [sp, #(0 * 8)]
    ldp x2, x3, [sp, #(2 * 8)]
    ldp x4, x5, [sp, #(4 * 8)]
    ldp x6, x7, [sp, #(6 * 8)]
    ldp x8, x9, [sp, #(8 * 8)]
    ldp x10, x11, [sp, #(10 * 8)]
    ldp x12, x13, [sp, #(12 * 8)]
    ldp x14, x15, [sp, #(14 * 8)]
    ldp x16, x17, [sp, #(16 * 8)]
    ldp x18, x19, [sp, #(18 * 8)]
    ldp x20, x21, [sp, #(20 * 8)]
    ldp x22, x23, [sp, #(22 * 8)]
    ldp x24, x25, [sp, #(24 * 8)]
    ldp x26, x27, [sp, #(26 * 8)]
    ldp x28, x29, [sp, #(28 * 8)]
    ldr x30, [sp, #(30 * 8)]
    
    add sp, sp, #(35 * 8)
    eret

.balign 128
lower_el_aarch64_fiq:
    b .hang

.balign 128
lower_el_aarch64_serror:
    b .hang

/* ============================================ */
/* Lower EL using AArch32 (not supported)       */
/* ============================================ */
.balign 128
lower_el_aarch32_sync:
    b .hang

.balign 128
lower_el_aarch32_irq:
    b .hang

.balign 128
lower_el_aarch32_fiq:
    b .hang

.balign 128
lower_el_aarch32_serror:
    b .hang
