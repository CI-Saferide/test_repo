#include <stdbool.h>
#include "bitops.h"
#include "aux.h"

#define BITS_PER_BYTE 8
#define BITMAP_FIRST_WORD_MASK(start) (~0UL << ((start) & (__BITS_PER_LONG - 1)))
#define __round_mask(x, y) ((__typeof__(x))((y)-1))
#define round_down(x, y) ((x) & ~__round_mask(x, y))
#define DIV_ROUND_UP(n,d) (((n) + (d) - 1) / (d))
#define BITS_TO_LONGS(nr) DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

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

static inline unsigned long __ffz(unsigned long word)
{
	return __ffs(~(word));
}

unsigned long find_first_bit(const unsigned long *addr, unsigned long size)
{
	unsigned long idx;

	for (idx = 0; idx * __BITS_PER_LONG < size; idx++) {
		if (addr[idx])
			return min(idx * __BITS_PER_LONG + __ffs(addr[idx]), size);
	}

	return size;
}

static inline unsigned long _find_next_bit(const unsigned long *addr,
	unsigned long nbits, unsigned long start, unsigned long invert)
{
	unsigned long tmp;

	if (start >= nbits)
		return nbits;

	tmp = addr[start / __BITS_PER_LONG] ^ invert;

	/* Handle 1st word. */
	tmp &= BITMAP_FIRST_WORD_MASK(start);
	start = round_down(start, __BITS_PER_LONG);

	while (!tmp) {
		start += __BITS_PER_LONG;
		if (start >= nbits)
			return nbits;

		tmp = addr[start / __BITS_PER_LONG] ^ invert;
	}

	return min(start + __ffs(tmp), nbits);
}

unsigned long find_next_bit(const unsigned long *addr, unsigned long size,
	unsigned long offset)
{
	return _find_next_bit(addr, size, offset, 0UL);
}

unsigned long find_first_zero_bit(const unsigned long *addr, unsigned long size)
{
        unsigned long idx;

        for (idx = 0; idx * __BITS_PER_LONG < size; idx++) {
                if (addr[idx] != ~0UL)
                        return min(idx * __BITS_PER_LONG + __ffz(addr[idx]), size);
        }

        return size;
}


#define BITMAP_LAST_WORD_MASK(nbits) (~0UL >> (-(nbits) & (__BITS_PER_LONG - 1)))

static int bitmap_and(unsigned long *dst, const unsigned long *src1,
	const unsigned long *src2, unsigned int nbits)
{
	unsigned int k;
	unsigned int lim = nbits/__BITS_PER_LONG;
	unsigned long result = 0;

	if (nbits <= __BITS_PER_LONG)
		return (*dst = *src1 & *src2 & BITMAP_LAST_WORD_MASK(nbits)) != 0;

	for (k = 0; k < lim; k++)
		result |= (dst[k] = src1[k] & src2[k]);

	if (nbits % __BITS_PER_LONG)
		result |= (dst[k] = src1[k] & src2[k] &
			BITMAP_LAST_WORD_MASK(nbits));

	return result != 0;
}

static void bitmap_or(unsigned long *dst, const unsigned long *src1,
	const unsigned long *src2, unsigned int nbits)
{
	unsigned int k;
	unsigned int nr = BITS_TO_LONGS(nbits);

	if (nbits <= __BITS_PER_LONG)
		*dst = *src1 | *src2;

	for (k = 0; k < nr; k++)
		dst[k] = src1[k] | src2[k];
}

/* dst = (and & (or1 | or2)) */
static int bitmap_and_or(unsigned long *dst, const unsigned long *and,
	const unsigned long *or1, const unsigned long *or2,
	unsigned int nbits)
{
	unsigned int k;
	unsigned int lim = nbits/__BITS_PER_LONG;
	unsigned long result = 0;

	if (nbits <= __BITS_PER_LONG)
		return (*dst = *and & (*or1 | *or2) & BITMAP_LAST_WORD_MASK(nbits)) != 0;

	for (k = 0; k < lim; k++)
		result |= (dst[k] = and[k] & (or1[k] | or2[k]));

	if (nbits % __BITS_PER_LONG)
		result |= (dst[k] = (and[k] & (or1[k] | or2[k])) &
			BITMAP_LAST_WORD_MASK(nbits));

	return result != 0;
}

void ba_set_bit(unsigned short bit, bit_array_t *arr)
{
	if (bit < MAX_RULES) {
		set_bit(bit, arr->bitmap);
		arr->empty = false;
	}
}

void ba_clear_bit(unsigned short bit, bit_array_t *arr)
{
	if (bit < MAX_RULES) {
		clear_bit(bit, arr->bitmap);

		if (find_first_bit(arr->bitmap, MAX_RULES) == MAX_RULES)
			arr->empty = true;
	}
}

bool ba_is_set(unsigned short bit, bit_array_t *arr)
{
	if (bit < MAX_RULES) {
		if (arr->empty == true)
			return false;

		return test_bit(bit, arr->bitmap);
	}

	return false;
}

bool ba_is_empty(bit_array_t *arr)
{
	return arr->empty;
}

void ba_clear(bit_array_t *arr)
{
	vs_memset(arr->bitmap, 0, sizeof(arr->bitmap));
	arr->empty = true;
}

void ba_set(bit_array_t *arr)
{
	vs_memset(arr->bitmap, 0xFF, sizeof(arr->bitmap));
	arr->empty = false;
}

void ba_and(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2)
{
	if (bitmap_and(dst->bitmap, src1->bitmap, src2->bitmap, MAX_RULES))
		dst->empty = false;
	else
		dst->empty = true;
}

void ba_or(bit_array_t *dst, bit_array_t *src1, bit_array_t *src2)
{
	bitmap_or(dst->bitmap, src1->bitmap, src2->bitmap, MAX_RULES);
	dst->empty = (src1->empty && src2->empty);
}

/* dst = (and & (or1 | or2)) */
void ba_and_or(bit_array_t *dst, bit_array_t *and, bit_array_t *or1, bit_array_t *or2)
{
	if (bitmap_and_or(dst->bitmap, and->bitmap, or1->bitmap,
			or2->bitmap, MAX_RULES))
		dst->empty = false;
	else
		dst->empty = true;
}
