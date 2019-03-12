SECTIONS
{
	. = 0x0;
	.text : { *(.text) }
	. = 0xb000;
	.bss : { *(.bss) }
	.data : { *(.data) }
}

