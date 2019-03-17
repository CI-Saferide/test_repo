SECTIONS
{
	. = 0x0;
	.text : { *(.text) }
	. = 0xc000;
	.bss : { *(.bss) }
	.data : { *(.data) }
}

