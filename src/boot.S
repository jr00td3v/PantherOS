/*
 * PantherOS ARM64 Boot Assembly
 * 
 * Phase 1: The Fortress Foundation
 * - Establishes 4-level paging (Identity + Higher Half)
 * - Enables MMU with strict memory protections
 * - Transitions to high-half virtual address space
 * 
 * Memory Map:
 * - Physical RAM: 0x4000_0000
 * - Kernel Load: 0x4008_0000
 * - Kernel Virtual: 0xFFFF_0000_4008_0000 (via Linker)
 */

/* Constants */
.equ KERNEL_VIRT_BASE, 0xFFFF000000000000
.equ PHYS_OFFSET, 0x40080000
.equ RAM_BASE, 0x40000000

/* Page Table Entry Flags */
.equ PTE_VALID,     1
.equ PTE_TABLE,     3
.equ PTE_BLOCK,     1
.equ PTE_AF,        (1 << 10)
.equ PTE_ISH,       (3 << 8)
.equ PTE_ATTR_NORMAL, (0 << 2)
.equ PTE_ATTR_DEVICE, (1 << 2)
.equ PTE_RW_EL1,    (0 << 6)
.equ PTE_UXN,       (1 << 54)
.equ PTE_PXN,       (1 << 53)

.section .text._start
.global _start

_start:
    /* Disable interrupts */
    msr daifset, #0xf

    /* Check EL1 */
    mrs x0, CurrentEL
    lsr x0, x0, #2
    cmp x0, #1
    b.ne .hang

    /* 
     * Setup Page Tables (Physical Addressing)
     * We use a static region in BSS for boot tables
     */
    
    /* Clear BSS (including page tables) */
    ldr x0, =__bss_start
    ldr x1, =__bss_end
    
    /* Calculate physical addresses for clearing */
    /* Since we are linked high, symbols are high addresses */
    /* We must subtract KERNEL_VIRT_BASE to get physical */
    mov x2, #0xFFFF
    lsl x2, x2, #48
    sub x0, x0, x2  /* x0 = phys(__bss_start) */
    sub x1, x1, x2  /* x1 = phys(__bss_end) */

.clear_bss_loop:
    cmp x0, x1
    b.ge .setup_paging
    str xzr, [x0], #8
    b .clear_bss_loop

.setup_paging:
    /* Get physical address of boot_l0 table */
    ldr x0, =boot_l0
    sub x0, x0, x2  /* x0 = phys(boot_l0) */

    /* Get physical address of boot_l1 */
    ldr x1, =boot_l1
    sub x1, x1, x2  /* x1 = phys(boot_l1) */

    /* Link L0[0] -> L1 (Identity map coverage) */
    /* Entry = phys(boot_l1) | PTE_TABLE | PTE_VALID */
    orr x3, x1, #3
    str x3, [x0]

    /* Link L0[511] -> L1 (High map coverage) */
    /* 511 * 8 = 4088 */
    str x3, [x0, #4088]

    /* Setup L1 entries */
    
    /* L1[0]: 0GB..1GB (Device Memory for MMIO/UART/Flash) */
    /* 0x0000_0000 | Device | AF | Valid | Block */
    mov x3, #0
    mov x4, #PTE_AF
    orr x3, x3, x4
    mov x4, #PTE_ATTR_DEVICE
    orr x3, x3, x4
    orr x3, x3, #1   /* Block Entry */
    
    /* Store in L1[0] */
    str x3, [x1]

    /* L1[1]: 1GB..2GB (Normal Memory for Kernel/RAM) */
    /* 0x4000_0000 | Normal | Inner Shareable | AF | Valid | Block */
    mov x3, #0x4000
    lsl x3, x3, #16  /* x3 = 0x40000000 */
    
    mov x4, #PTE_AF
    orr x3, x3, x4
    mov x4, #PTE_ISH
    orr x3, x3, x4
    mov x4, #PTE_ATTR_NORMAL
    orr x3, x3, x4
    orr x3, x3, #1   /* Block Entry */
    
    /* Store in L1[1] (Index 1 * 8 = 8) */
    str x3, [x1, #8]

    /* Initialize MAIR_EL1 */
    /* Attr0 = Normal (0xFF), Attr1 = Device (0x04) */
    mov x0, #0xFF       /* Attr0 = Normal */
    mov x1, #0x04       /* Attr1 = Device-nGnRE */
    lsl x1, x1, #8
    orr x0, x0, x1
    msr mair_el1, x0

    /* Initialize TCR_EL1 */
    /* T0SZ=16 (48-bit), T1SZ=16 (48-bit), TG0=4K, TG1=4K, IPS=40bit */
    mov x0, #16
    /* T0SZ = 16 (0-5) */
    
    /* T1SZ = 16 (16-21) */
    mov x1, #16
    lsl x1, x1, #16
    orr x0, x0, x1
    
    /* TG0 = 00 (4KB) */
    /* TG1 = 10 (4KB) -> bits 30-31 = 2 */
    mov x1, #2
    lsl x1, x1, #30
    orr x0, x0, x1
    
    /* IPS = 40 bits (010) -> bits 32-34 = 2 */
    mov x1, #2
    lsl x1, x1, #32
    orr x0, x0, x1
    
    msr tcr_el1, x0

    /* Set TTBR0_EL1 and TTBR1_EL1 */
    ldr x0, =boot_l0
    sub x0, x0, x2  /* Phys address */
    msr ttbr0_el1, x0
    msr ttbr1_el1, x0
    isb

    /* Enable MMU */
    mrs x0, sctlr_el1
    orr x0, x0, #1      /* M=1 (Enable MMU) */
    orr x0, x0, #(1<<2) /* C=1 (Enable D-Cache) */
    orr x0, x0, #(1<<12) /* I=1 (Enable I-Cache) */
    msr sctlr_el1, x0
    isb

    /* MMU IS ON - Jump to High Virtual Address */
    ldr x8, =_high_start
    br x8

_high_start:
    /* Now running at 0xFFFF... */
    
    /* Setup Virtual Stack */
    ldr x0, =__stack_top
    mov sp, x0

    /* Call Rust kernel_main */
    bl kernel_main

.hang:
    wfi
    b .hang

/* 
 * Exception Vectors
 * Must be 2KB aligned. We copy the handlers from previous implementation.
 */
.section .text.vectors
.balign 2048
.global __exception_vectors
__exception_vectors:

/* Current EL with SP0 */
.balign 128
    b .hang
.balign 128
    b .hang
.balign 128
    b .hang
.balign 128
    b .hang

/* Current EL with SPx */
.balign 128
current_el_spx_sync:
    sub sp, sp, #(34 * 8)
    stp x0, x1, [sp, #(0*8)]
    stp x2, x3, [sp, #(2*8)]
    stp x4, x5, [sp, #(4*8)]
    stp x6, x7, [sp, #(6*8)]
    stp x8, x9, [sp, #(8*8)]
    stp x10, x11, [sp, #(10*8)]
    stp x12, x13, [sp, #(12*8)]
    stp x14, x15, [sp, #(14*8)]
    stp x16, x17, [sp, #(16*8)]
    stp x18, x19, [sp, #(18*8)]
    stp x20, x21, [sp, #(20*8)]
    stp x22, x23, [sp, #(22*8)]
    stp x24, x25, [sp, #(24*8)]
    stp x26, x27, [sp, #(26*8)]
    stp x28, x29, [sp, #(28*8)]
    str x30, [sp, #(30*8)]
    
    mrs x0, elr_el1
    mrs x1, spsr_el1
    mrs x2, esr_el1
    mrs x3, far_el1
    stp x0, x1, [sp, #(31*8)]
    stp x2, x3, [sp, #(33*8)]
    
    mov x0, sp
    bl handle_sync_exception_same_el
    b .hang

.balign 128
current_el_spx_irq:
    b .hang
.balign 128
    b .hang
.balign 128
    b .hang

/* Lower EL AArch64 */
.balign 128
lower_el_aarch64_sync:
    sub sp, sp, #(35 * 8)
    stp x0, x1, [sp, #(0*8)]
    stp x2, x3, [sp, #(2*8)]
    stp x4, x5, [sp, #(4*8)]
    stp x6, x7, [sp, #(6*8)]
    stp x8, x9, [sp, #(8*8)]
    stp x10, x11, [sp, #(10*8)]
    stp x12, x13, [sp, #(12*8)]
    stp x14, x15, [sp, #(14*8)]
    stp x16, x17, [sp, #(16*8)]
    stp x18, x19, [sp, #(18*8)]
    stp x20, x21, [sp, #(20*8)]
    stp x22, x23, [sp, #(22*8)]
    stp x24, x25, [sp, #(24*8)]
    stp x26, x27, [sp, #(26*8)]
    stp x28, x29, [sp, #(28*8)]
    str x30, [sp, #(30*8)]
    
    mrs x0, elr_el1
    mrs x1, spsr_el1
    mrs x2, esr_el1
    mrs x3, far_el1
    stp x0, x1, [sp, #(31*8)]
    stp x2, x3, [sp, #(33*8)]
    
    mov x0, sp
    bl handle_sync_exception_lower_el
    
    ldp x0, x1, [sp, #(31*8)]
    msr elr_el1, x0
    msr spsr_el1, x1
    
    ldp x0, x1, [sp, #(0*8)]
    ldp x2, x3, [sp, #(2*8)]
    ldp x4, x5, [sp, #(4*8)]
    ldp x6, x7, [sp, #(6*8)]
    ldp x8, x9, [sp, #(8*8)]
    ldp x10, x11, [sp, #(10*8)]
    ldp x12, x13, [sp, #(12*8)]
    ldp x14, x15, [sp, #(14*8)]
    ldp x16, x17, [sp, #(16*8)]
    ldp x18, x19, [sp, #(18*8)]
    ldp x20, x21, [sp, #(20*8)]
    ldp x22, x23, [sp, #(22*8)]
    ldp x24, x25, [sp, #(24*8)]
    ldp x26, x27, [sp, #(26*8)]
    ldp x28, x29, [sp, #(28*8)]
    ldr x30, [sp, #(30*8)]
    
    add sp, sp, #(35*8)
    eret

.balign 128
lower_el_aarch64_irq:
    b .hang
.balign 128
    b .hang
.balign 128
    b .hang

/* Lower EL AArch32 */
.balign 128
    b .hang
.balign 128
    b .hang
.balign 128
    b .hang
.balign 128
    b .hang

/* Boot Page Tables */
.section .bss
.balign 4096
boot_l0:
    .space 4096
boot_l1:
    .space 4096
