#ifndef __BITOPS_H__
#define __BITOPS_H__

#include <asm/bitsperlong.h>
#include <stddef.h>
#include <stdbool.h>
#include "aux.h"

#define MAX_RULES 	4096
#define BITS_IN_SUMMARY 	64

typedef struct __attribute__((aligned(8))) {
	unsigned long 		bitmap[MAX_RULES/__BITS_PER_LONG]; /* 4096 bits */
	unsigned long long	summary; /* 64 bit, each bit represent 64 bit in bitmap */
	bool 			empty;
} bit_array_t;

#define ba_set(arr) \
	vs_memset(((bit_array_t*)arr)->bitmap, 0xFF, sizeof(((bit_array_t*)arr)->bitmap)); \
	((bit_array_t*)arr)->summary = (unsigned long long)(-1); \
	((bit_array_t*)arr)->empty = false;

#define ba_clear(arr) \
	vs_memset(((bit_array_t*)arr)->bitmap, 0, sizeof(((bit_array_t*)arr)->bitmap)); \
	((bit_array_t*)arr)->summary = 0; \
	((bit_array_t*)arr)->empty = true;

#define ba_is_empty(arr) \
	((bit_array_t*)arr)->empty

unsigned int ba_ffs(bit_array_t *arr);
void ba_set_bit(unsigned short bit, bit_array_t *arr);
void ba_clear_bit(unsigned short bit, bit_array_t *arr);
bool ba_is_set(unsigned short bit, bit_array_t *arr);
void ba_and(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2);
void ba_or(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2);
void ba_and_or(bit_array_t *dst, bit_array_t *and1, bit_array_t *or1, bit_array_t *or2);
#ifdef CLS_DEBUG
void ba_print_set_bits(bit_array_t *arr);
#endif
#endif /* __BITOPS_H__ */
