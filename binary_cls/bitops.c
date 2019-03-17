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

static inline int test_bit(int nr, const volatile unsigned long *addr)
{
	return 1UL & (addr[BIT_WORD(nr)] >> (nr & (__BITS_PER_LONG-1)));
}

static inline unsigned long __ffs(unsigned long word)
{
	return __builtin_ctzl(word);
}

unsigned int ba_ffs(bit_array_t *arr)
{
	unsigned int index;
#if __BITS_PER_LONG != 64
	unsigned long *address;
#endif

	if (arr->empty)
		return MAX_RULES;

#if __BITS_PER_LONG == 64
	index = min(__ffs(arr->summary), __BITS_PER_LONG);
	if (index == __BITS_PER_LONG)
		return MAX_RULES;

	return min(index * __BITS_PER_LONG + __ffs(arr->bitmap[index]), MAX_RULES);
#else
	if (((unsigned long)arr->summary) == 0UL) {
		/* search the upper 32 bits */
		index = min(__ffs((unsigned long)(arr->summary >> __BITS_PER_LONG)), __BITS_PER_LONG);
		if (index == __BITS_PER_LONG)
			return MAX_RULES;

		/* add to index 32 if we found in the upper bit */
		index += __BITS_PER_LONG;
	} else {
		/* search the lower 32 bits */
		index = min(__ffs((unsigned long)arr->summary), __BITS_PER_LONG);
		if (index == __BITS_PER_LONG)
			return MAX_RULES;
	}

	address = arr->bitmap[index * 2];
	if (*address)
		/* search the lower 32 bits */
		return min((index * __BITS_PER_LONG * 2) +__ffs(*address), MAX_RULES);
	else
		/* search the upper 32 bits */
		return min((index * __BITS_PER_LONG * 2) + __BITS_PER_LONG +__ffs(*(++address)), MAX_RULES);
#endif
}

void ba_set_bit(unsigned short bit, bit_array_t *arr)
{
	if (bit < MAX_RULES) {
		set_bit(bit, arr->bitmap);
		set_bit(bit/BITS_IN_SUMMARY, (unsigned long*)&arr->summary);
		arr->empty = false;
	}
}

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
		address = arr->bitmap[index * 2];
		if (!*address && !*(address+1))
			clear_bit(index, &arr->summary);
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

	for (index = 0; index < (MAX_RULES/__BITS_PER_LONG); index++)
		dst->bitmap[index] = (src1->bitmap[index] & src2->bitmap[index]);

	dst->summary = (src1->summary & src2->summary);
	dst->empty = (src1->empty | src2->empty);
}

/* dst = src1 | src2 */
void ba_or(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2)
{
	unsigned int index;

	for (index = 0; index < (MAX_RULES/__BITS_PER_LONG); index++)
		dst->bitmap[index] = src1->bitmap[index] | src2->bitmap[index];

	dst->summary = (src1->summary | src2->summary);
	dst->empty = (src1->empty && src2->empty);
}

/* dst = (src1 & (src2 | src3)) */
void ba_and_or(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2, bit_array_t *src3)
{
	unsigned long result = 0;
	unsigned int index;

	for (index = 0; index < (MAX_RULES/__BITS_PER_LONG); index++)
		result |= dst->bitmap[index] = (src1->bitmap[index] & (src2->bitmap[index] | src3->bitmap[index]));

	dst->summary = (src1->summary & (src2->summary | src3->summary));

	if (result)
		dst->empty = false;
	else
		dst->empty = true;
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

unsigned int ba_count_set_bits(bit_array_t *arr)
{
	unsigned short index;
	unsigned int res = 0;

	for (index=0; index<MAX_RULES; index++)
		if (ba_is_set(index, arr))
			res++;

	return res;
}
