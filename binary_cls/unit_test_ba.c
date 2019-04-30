#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include "bitops.h"
#include "printf.h"

int main(int argc, char **argv)
{
	bit_array_t ba, bb, bc, bd;
	int i;

#ifdef CLS_DEBUG
	cls_register_printf(printf);
#endif

	ba_clear(&ba);
	ba_clear(&bb);
	ba_clear(&bc);
	ba_clear(&bd);

	ba_set_bit(0, &ba);
	ba_set_bit(1, &bb);

	ba_and(&bc, &bb, &ba);
#ifdef CLS_DEBUG
	printf("bits set: ");
	ba_print_set_bits(&bc);
#endif

	ba_set_bit(0, &ba);
	ba_set_bit(1, &ba);
	ba_set_bit(31, &ba);
	ba_set_bit(32, &ba);
	ba_set_bit(33, &ba);
	ba_set_bit(510, &ba);
	ba_set_bit(511, &ba);
	ba_set_bit(512, &ba);
	ba_set_bit(513, &ba);
	ba_set_bit(4095, &ba);
	ba_set_bit(4094, &ba);

#ifdef CLS_DEBUG
	printf("bits set: ");
	ba_print_set_bits(&ba);
#endif

	ba_set_bit(0, &bb);
	ba_set_bit(1, &bb);
	ba_set_bit(30, &bb);
	ba_set_bit(32, &bb);
	ba_set_bit(33, &bb);
	ba_set_bit(34, &bb);
	ba_set_bit(257, &bb);
	ba_set_bit(510, &bb);
	ba_set_bit(511, &bb);
	ba_set_bit(513, &bb);
	ba_set_bit(4093, &bb);
	ba_set_bit(4094, &bb);

#ifdef CLS_DEBUG
	printf("bits set: ");
	ba_print_set_bits(&bb);
#endif

	ba_and(&bc, &bb, &ba);

#ifdef CLS_DEBUG
	printf("bits set: ");
	ba_print_set_bits(&bc);
#endif
	ba_clear(&bc);
	ba_or(&bc, &bb, &ba);

#ifdef CLS_DEBUG
	printf("bits set: ");
	ba_print_set_bits(&bc);
#endif

	ba_clear(&bc);
	ba_set_bit(0, &bc);
	ba_set_bit(1, &bc);
	ba_set_bit(30, &bc);
	ba_set_bit(34, &bc);
	ba_set_bit(257, &bc);
	ba_set_bit(511, &bc);
	ba_set_bit(4094, &bc);
	ba_and_or(&bd, &bc, &bb, &ba);

#ifdef CLS_DEBUG
	printf("bits set: ");
	ba_print_set_bits(&bd);
#endif

	ba_clear(&bc);
	for (i=(MAX_RULES-1); i>=0; i--) {
		ba_set_bit(i, &bc);
		if (ba_ffs(&bc) != i)
			printf("error\n");
	}
	return 0;

}

