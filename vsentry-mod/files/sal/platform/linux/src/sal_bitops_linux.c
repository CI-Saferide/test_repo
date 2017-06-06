/* file: sal_bitops_linux.c
 * purpose: *** linux implementation  ***
 * 			this file encapsulates all bit operations
 * 			including 32/64 bits awarnece
 * 			including data structures <refine it...>
*/

#include <linux/bitops.h>
#include "sal_bitops.h"

#ifdef PLATFORM_LINUX

void sal_set_bit32 (SR_U8 bit, SR_U32 *addr)
{
	/* there are no guarantees that set_bit function will not be 
	 * reordered on non x86 architectures 
	 */
	set_bit (bit, addr);
}

void sal_clear_bit32 (SR_U8 bit, SR_U32 *addr)
{
	clear_bit (bit, addr);
}

void sal_change_bit32 (SR_U8 bit, SR_U32 *addr)
{
	change_bit (bit, addr);
}

SR_BOOL sal_test_and_set_bit32 (SR_U8 bit, SR_U32 *addr)
{
	return (test_and_set_bit(bit, addr));
}

SR_BOOL sal_test_and_clear_bit32 (SR_U8 bit, SR_U32 *addr)
{
	return (test_and_clear_bit(bit, addr));
}

/* function:     sal_ffz32
 * description:  find first zero bit in word
 * return value: -1 if word is zero, first zero bit number otherwise
 */
SR_8 sal_ffz32 (SR_U32 addr)
{
	/* ffz is undefined if no zero exists */
	if (NULL == addr)
		return (-1);
	return ffz(addr);
}

/* function:     sal_ffs32
 * description:  find first set bit in word
 * return value: -1 if word is zero, first set bit number otherwise
 */
SR_8 sal_ffs32 (SR_U32 addr)
{
	/* ffs(value) returns 0 if value is 0 or the position of the 
	 * first set bit if value is nonzero. The first (least significant)
	 *  bit is at position 1.
	 */ 
	if (NULL == addr)
		return (-1);
	return (ffs(addr)-1);
}

/* function:     sal_fls32
 * description:  find last set bit in word
 * return value: -1 if word is zero, last set bit number otherwise
 */
SR_8 sal_fls32 (SR_U32 addr)
{
	/* fls(value) returns 0 if value is 0 or the position of the last
	 * set bit if value is nonzero. The last (most significant) bit is
	 * at position 32. 
	 */
	if (NULL == addr)
		return (-1);
	return (fls(addr)-1);
}

/* function:     sal_fls64
 * description:  find last set bit in word
 * return value: -1 if word is zero, last set bit number otherwise
 */
SR_8 sal_fls64 (SR_U64 addr)
{
	/* fls64(value) returns 0 if value is 0 or the position of the last
	 * set bit if value is nonzero. The last (most significant) bit is
	 * at position 64. 
	 */
	if (NULL == addr)
		return (-1);
	return (fls64(addr)-1);
}

#endif /* #ifdef PLATFORM_LINUX */

