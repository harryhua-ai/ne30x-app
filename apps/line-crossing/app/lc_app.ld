/*
 * lc_app.ld — Line Crossing App linker script (v2 native image).
 *
 * Mirrors the pinned experiment Host loader layout (same as hello-app):
 *   ne301 experiment/app-host-poc@a5b4bf3 Appli/STM32N657L0HXQ_LRUN.ld
 *   APP ORIGIN 0x93E00000 LENGTH 2M; the whole image (32-byte NEA1 header +
 *   payload) is loaded at ORIGIN, the header is stripped by memmove, and
 *   control enters at ORIGIN+entry_offset (Thumb).
 *
 * The app runs on the Host caller's stack: no _estack, no startup code, and
 * NO initialized data (the loader never initializes .data — link-time guard).
 */
ENTRY(app_entry)

MEMORY
{
  APP (rx) : ORIGIN = 0x93E00000, LENGTH = 2M
}

SECTIONS
{
  .text :
  {
    . = ALIGN(4);
    *(.text*)
    *(.rodata*)
    . = ALIGN(4);
  } > APP

  .data :
  {
    . = ALIGN(4);
    *(.data*)
    . = ALIGN(4);
  } > APP

  .bss (NOLOAD) :
  {
    . = ALIGN(4);
    *(.bss*)
    *(COMMON)
    . = ALIGN(4);
  } > APP

  /DISCARD/ :
  {
    *(.comment)
    *(.note*)
    *(.init_array*)
    *(.fin_array*)
  }
}

/* The Host loader never initializes .data: initialized mutable globals are
 * forbidden (link-time guard, keeps the freestanding claim honest). */
ASSERT(SIZEOF(.data) == 0,
       "line-crossing-app must not define initialized data (.data); the host loader does not initialize it")
