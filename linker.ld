/*
 * PantherOS Linker Script
 * Target: QEMU virt machine (ARM64)
 * 
 * Memory Layout:
 * - RAM starts at 0x40000000 for QEMU virt
 * - Kernel loaded at 0x40080000 (standard Linux kernel load address)
 * - Stack grows downward from end of kernel
 */

ENTRY(_start)

MEMORY
{
    /* QEMU virt machine RAM: 0x40000000 - 0x80000000 (1GB default) */
    RAM (rwx) : ORIGIN = 0x40080000, LENGTH = 128M
}

SECTIONS
{
    . = ORIGIN(RAM);

    /* Code section */
    .text : ALIGN(4K)
    {
        __text_start = .;
        *(.text._start)     /* Entry point first */
        *(.text .text.*)
        __text_end = .;
    } > RAM

    /* Read-only data */
    .rodata : ALIGN(4K)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    } > RAM

    /* Initialized data */
    .data : ALIGN(4K)
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    } > RAM

    /* Uninitialized data (BSS) */
    .bss : ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    } > RAM

    /* Stack (16KB, 16-byte aligned for ARM64 ABI) */
    . = ALIGN(16);
    __stack_bottom = .;
    . += 16K;
    __stack_top = .;

    /* Heap starts after stack */
    . = ALIGN(4K);
    __heap_start = .;
    __heap_end = ORIGIN(RAM) + LENGTH(RAM);

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}

/* Export symbols for Rust code */
PROVIDE(__kernel_start = ORIGIN(RAM));
PROVIDE(__kernel_end = __heap_start);
