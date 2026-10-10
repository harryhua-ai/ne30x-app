
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

ASSERT(SIZEOF(.data) == 0,
       "line-crossing-app must not define initialized data (.data); the host loader does not initialize it")
