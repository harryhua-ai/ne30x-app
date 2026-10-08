/*
 * hello-app linker script — NE301 app-host execution region.
 *
 * Matches the pinned experiment Host loader layout:
 *   ne301 experiment/app-host-poc@a5b4bf3dd25931d612680aff200e4e0ac8d8e64e
 *   - Appli/STM32N657L0HXQ_LRUN.ld: APP_HOST_RAM ORIGIN 0x93E00000 LENGTH 2M
 * The whole image (32-byte header + payload) is loaded at ORIGIN, the header
 * is stripped by memmove, and control enters at ORIGIN+entry_offset (Thumb).
 *
 * The app runs on the host caller's stack: no _estack, no startup code,
 * no .data initialization support (enforced by the ASSERT below).
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

/* The host loader never initializes .data: initialized mutable globals are
 * forbidden in hello-app (link-time guard, keeps the PoC honest). */
ASSERT(SIZEOF(.data) == 0,
       "hello-app must not define initialized data (.data); the host loader does not initialize it")
