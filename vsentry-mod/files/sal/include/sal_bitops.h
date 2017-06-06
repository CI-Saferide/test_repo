/* file: sal_bitops.h
 * purpose: this file encapsulates all bit operations
 * 			including 32/64 bits awarnece
 * 			including data structures <refine it...>
*/

#ifndef SAL_BITOPS_H
#define SAL_BITOPS_H

#include "sal_linux.h"

void sal_set_bit32 (SR_U8 bit, SR_U32 *addr);
void sal_clear_bit32 (SR_U8 bit, SR_U32 *addr);
void sal_change_bit32 (SR_U8 bit, SR_U32 *addr);
SR_BOOL sal_test_and_set_bit32 (SR_U8 bit, SR_U32 *addr);
SR_BOOL sal_test_and_clear_bit32 (SR_U8 bit, SR_U32 *addr);
SR_8 sal_ffz32 (SR_U32 addr);
SR_8 sal_ffs32 (SR_U32 addr);
SR_8 sal_fls32 (SR_U32 addr);
SR_8 sal_fls64 (SR_U64 addr);

#endif /* SAL_BITOPS_H*/
