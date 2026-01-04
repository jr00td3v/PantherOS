/*
 * PantherOS Linker Script
 * Target: QEMU virt machine (ARM64)
 * 
 * Memory Layout:
 * - Physical RAM starts at 0x40000000
 * - Kernel Load Address (LMA) at 0x40080000
 * - Kernel Virtual Address (VMA) at 0xFFFF000040080000
 * - High-half offset: 0xFFFF000000000000
 */

ENTRY(_start)

/* Constants */
KERNEL_OFFSET = 0xFFFF000000000000;
PHYS_BASE = 0x40080000;

SECTIONS
{
    /* Set current location counter to VMA */
    . = PHYS_BASE + KERNEL_OFFSET;

    /* Code section */
    .text : AT(ADDR(.text) - KERNEL_OFFSET) ALIGN(4K)
    {
        __text_start = .;
        *(.text._start)     /* Entry point first */
        *(.text .text.*)
        __text_end = .;
    }

    /* Read-only data */
    .rodata : AT(ADDR(.rodata) - KERNEL_OFFSET) ALIGN(4K)
    {
        __rodata_start = .;
        *(.rodata .rodata.*)
        __rodata_end = .;
    }

    /* Initialized data */
    .data : AT(ADDR(.data) - KERNEL_OFFSET) ALIGN(4K)
    {
        __data_start = .;
        *(.data .data.*)
        __data_end = .;
    }

    /* Uninitialized data (BSS) */
    .bss : AT(ADDR(.bss) - KERNEL_OFFSET) ALIGN(4K)
    {
        __bss_start = .;
        *(.bss .bss.*)
        *(COMMON)
        __bss_end = .;
    }

    /* Stack */
    . = ALIGN(16);
    __stack_bottom = .;
    . += 16K;
    __stack_top = .;

    /* Heap */
    . = ALIGN(4K);
    __heap_start = .;
    /* 128MB total RAM limit relative to virtual base */
    __heap_end = PHYS_BASE + KERNEL_OFFSET + 128M;

    /* Discard unwanted sections */
    /DISCARD/ :
    {
        *(.comment)
        *(.note*)
        *(.eh_frame*)
    }
}

/* Export symbols */
PROVIDE(__kernel_virtual_start = PHYS_BASE + KERNEL_OFFSET);
PROVIDE(__kernel_physical_start = PHYS_BASE);
