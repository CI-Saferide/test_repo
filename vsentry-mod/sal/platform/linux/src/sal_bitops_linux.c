/* file: sal_bitops_linux.c
 * purpose: *** linux implementation  ***
 * 			this file encapsulates all bit operations
 * 			including data structures for 4K bits
*/

#include <linux/bitops.h>
#include "sal_bitops.h"

void sal_set_bit (SR_U8 bit, void *addr)
{
	/* there are no guarantees that set_bit function will not be 
	 * reordered on non x86 architectures 
	 */
	set_bit (bit, (unsigned long*) addr);
}

void sal_clear_bit (SR_U8 bit, void *addr)
{
	clear_bit (bit, (unsigned long*)addr);
}

SR_BOOL sal_test_and_set_bit (SR_U8 bit, void *addr)
{
	return (test_and_set_bit(bit, (unsigned long*)addr));
}

SR_BOOL sal_test_and_clear_bit (SR_U8 bit, void *addr)
{
	return (test_and_clear_bit(bit, (unsigned long*)addr));
}

SR_BOOL sal_test_bit (SR_U8 bit, void *addr)
{
	return (test_bit(bit, (unsigned long*)addr));
}

/* function:     sal_fls64
 * description:  find last set bit in word
 * return value: -1 if word is zero, last set bit number otherwise
 */
SR_8 sal_fls64 (SR_U64 addr)
{
#ifdef ARCH_64
	/* fls64(value) returns 0 if value is 0 or the position of the last
	 * set bit if value is nonzero. The last (most significant) bit is
	 * at position 64. 
	 */
	if (!addr)
		return (-1);
	return (fls64(addr)-1);
#else
	return (-1); /* currently not in use, no support is 32bit yet */
#endif /* ARCH_64 */
}

SR_8 sal_ffs64 (SR_U64 *addr)
{
#ifndef ARCH_64	
	SR_8	ffs32;
	SR_U32	upper;
	SR_U32	lower;
#endif /* ARCH_64 */

	if (!(*addr))
		return (-1);
#ifdef ARCH_64
	return __ffs64(*addr);
#else
	lower = (*addr)&0xffffffff;
	ffs32 = ffs(lower);
	if (ffs32)
		return (ffs32-1);
	else {
		upper = (*addr) >> 32;
		ffs32 = ffs(upper);
		return (ffs32+32-1);
	}
#endif /* ARCH_64 */
}


