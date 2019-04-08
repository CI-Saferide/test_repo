SECTIONS
{
	. = 0x8000;
	.text : { *(.text) }
	.bss : { *(.bss) }
	.data : { *(.data) }
	.rodata : { *(.rodata) }
}
