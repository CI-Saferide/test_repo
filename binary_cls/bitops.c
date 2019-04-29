#include <stdbool.h>
#include "bitops.h"
#include "aux.h"
#include "classifier.h"

#define BIT_MASK(nr) 	(1UL<<((nr)%__BITS_PER_LONG))
#define BIT_WORD(nr) 	((nr)/__BITS_PER_LONG)

static inline void set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	__sync_or_and_fetch(p, mask);
}

static inline void clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = BIT_MASK(nr);
	unsigned long *p = ((unsigned long *)addr) + BIT_WORD(nr);

	__sync_and_and_fetch(p, ~mask);
}

static inline int test_bit(unsigned int nr, const volatile unsigned long *addr)
{
        return ((1UL << (nr % __BITS_PER_LONG)) &
                (((unsigned long *)addr)[nr / __BITS_PER_LONG])) != 0;
}

/* this function return the index of the first set bit in unsigned long long
 * [0 ... (63)] or 64 if no bit is set */
static inline int __ffs64(unsigned long long word)
{
	/* __builtin_ctzll/__builtin_ctzl GCC doc state that:
	 * "If x is 0, the result is undefined." so we need to check
	 * word value before */
#if __BITS_PER_LONG == 64
	if (!word)
		return BITS_IN_SUMMARY;
	return min(__builtin_ctzll(word), BITS_IN_SUMMARY);
#else
	unsigned int index = BITS_IN_SUMMARY;

	/* search the lower 32 bits */
	if ((unsigned long)(word))
		index = __builtin_ctzl((unsigned long)(word));
	else if ((unsigned long)(word >> __BITS_PER_LONG))
		index = __builtin_ctzl((unsigned long)(word >> __BITS_PER_LONG)) + __BITS_PER_LONG;

	return index;
#endif
}

/* this function return the index of the first set bit in bit_array_t
 * [0 ... 4095] or 4096 if no bit is set */
unsigned int ba_ffs(bit_array_t *arr)
{
	unsigned int index, ffs;
	unsigned long long *address;

	if (arr->empty)
		return MAX_RULES;

	index = __ffs64(arr->summary);
	if (index == BITS_IN_SUMMARY)
		return MAX_RULES;

	address = (unsigned long long*)&arr->bitmap[index * (sizeof(unsigned long long)/sizeof(unsigned long))];

	ffs = __ffs64(*address);
	if (ffs == BITS_IN_SUMMARY) {
		cls_err("summary 0x%016llx but address 0x%016llx (ffs %u)\n",
				arr->summary, *address, ffs);
		return MAX_RULES;
	}

	return min((index * BITS_IN_SUMMARY) + ffs, MAX_RULES);
}

/* set a specific bit in bit_array_t */
void ba_set_bit(unsigned short bit, bit_array_t *arr)
{
	if (bit < MAX_RULES) {
		set_bit(bit, arr->bitmap);
		set_bit(bit/BITS_IN_SUMMARY, (unsigned long*)&arr->summary);
		arr->empty = false;
	}
}

/* clear a specific bit in bit_array_t */
void ba_clear_bit(unsigned short bit, bit_array_t *arr)
{
	unsigned int index;
#if __BITS_PER_LONG != 64
	unsigned long *address;
#endif

	if (bit < MAX_RULES) {
		clear_bit(bit, arr->bitmap);

		index = bit/BITS_IN_SUMMARY;
#if __BITS_PER_LONG == 64
		if (!arr->bitmap[index])
			clear_bit(index, (unsigned long*)&arr->summary);
#else
		address = &arr->bitmap[index * 2];
		if (!*address && !*(address+1))
			clear_bit(index, (unsigned long*)&arr->summary);
#endif
		if (!arr->summary)
			arr->empty = true;
	}
}

/* check if bit is set in bit_array */
bool ba_is_set(unsigned short bit, bit_array_t *arr)
{
	if (bit < MAX_RULES) {
		if (arr->empty == true)
			return false;

		return test_bit(bit, arr->bitmap);
	}

	return false;
}

/* dst = src1 & src2 */
void ba_and(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2)
{
	unsigned int index;

	dst->summary = 0;

	for (index = 0; index < (MAX_RULES/__BITS_PER_LONG); index++) {
		dst->bitmap[index] = (src1->bitmap[index] & src2->bitmap[index]);
		if (dst->bitmap[index])
#if __BITS_PER_LONG == 64
			set_bit(index, (unsigned long*)&dst->summary);
#else
			set_bit(index/2, (unsigned long*)&dst->summary);
#endif
	}

	dst->empty = dst->summary?false:true;
}

/* dst = src1 | src2 */
void ba_or(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2)
{
	unsigned int index;

	for (index = 0; index < (MAX_RULES/__BITS_PER_LONG); index++)
		dst->bitmap[index] = src1->bitmap[index] | src2->bitmap[index];

	dst->summary = (src1->summary | src2->summary);
	dst->empty = (src1->empty & src2->empty);
}

/* dst = (src1 & (src2 | src3)) */
void ba_and_or(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2, bit_array_t *src3)
{
	unsigned int index;

	dst->summary = 0;

	for (index = 0; index < (MAX_RULES/__BITS_PER_LONG); index++) {
		dst->bitmap[index] = (src1->bitmap[index] & (src2->bitmap[index] | src3->bitmap[index]));
		if (dst->bitmap[index]) {
#if __BITS_PER_LONG == 64
			set_bit(index, (unsigned long*)&dst->summary);
#else
			set_bit(index/2, (unsigned long*)&dst->summary);
#endif
		}
	}

	dst->empty = dst->summary?false:true;
}

#ifdef CLS_DEBUG
void ba_print_set_bits(bit_array_t *arr)
{
	unsigned short index;

	for (index=0; index<MAX_RULES; index++)
		if (ba_is_set(index, arr))
			cls_printf("%u ", index);

	cls_printf("\n", index);
}
#endif
