#ifndef __BITOPS_H__
#define __BITOPS_H__

#include <asm/bitsperlong.h>
#include <stddef.h>
#include <stdbool.h>

#define min(x, y) ((x < y) ? x : y)
#define max(x, y) ((x >= y) ? x : y)

#define MAX_RULES 	4096

typedef struct {
	bool 		empty;
	unsigned long 	bitmap[MAX_RULES/__BITS_PER_LONG]; /* 4096 bits */
} bit_array_t;

unsigned long find_first_bit(const unsigned long *addr, unsigned long size);
unsigned long find_next_bit(const unsigned long *addr, unsigned long size, unsigned long offset);
unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size);

#define for_each_set_bit(bit, addr, size) \
	for ((bit) = find_first_bit((addr), (size));            \
		(bit) < (size);                                    \
		(bit) = find_next_bit((addr), (size), (bit) + 1))

#define ba_for_each_set_bit(bit, arr) \
	for_each_set_bit(bit, ((bit_array_t*)arr)->bitmap, MAX_RULES)

#define ba_ffs(arr) \
	find_first_bit(((bit_array_t*)arr)->bitmap, MAX_RULES);


void ba_set_bit(unsigned short bit, bit_array_t *arr);
void ba_clear_bit(unsigned short bit, bit_array_t *arr);
bool ba_is_set(unsigned short bit, bit_array_t *arr);
bool ba_is_empty(bit_array_t *arr);
void ba_clear(bit_array_t *arr);
void ba_set(bit_array_t *arr);
void ba_and(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2);
void ba_or(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2);
void ba_and_or(bit_array_t *dst, bit_array_t *and1, bit_array_t *or1, bit_array_t *or2);

#endif /* __BITOPS_H__ */
