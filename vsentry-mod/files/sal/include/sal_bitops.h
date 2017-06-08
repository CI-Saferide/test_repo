/* file: sal_bitops.h
 * purpose: this file encapsulates all bit operations
 * 			including data structures for 4K bits
*/

#ifndef SAL_BITOPS_H
#define SAL_BITOPS_H

#include "sal_linux.h"

/* 64 bit operations */
SR_8 sal_fls64 (SR_U64 addr);
SR_8 sal_ffs64 (SR_U64 *addr);

/* 32/64 bit operations */
void sal_set_bit (SR_U8 bit, void *addr);
void sal_clear_bit (SR_U8 bit, void *addr);
SR_BOOL sal_test_and_set_bit (SR_U8 bit, void *addr);
SR_BOOL sal_test_and_clear_bit (SR_U8 bit, void *addr);

typedef struct __bit_array {
   SR_U64		summary;
   SR_U64		level2[64];
}bit_array;

/* bit array opearions */
void sal_set_bit_array (SR_U16 bit, bit_array *arr);
void sal_clear_bit_array (SR_U16 bit, bit_array *arr);
SR_16 sal_ffs_array (bit_array *arr);
SR_16 sal_ffs_and_clear_array (bit_array *arr);
void sal_and_op_arrays (const bit_array *arr1, const bit_array *arr2, bit_array *result);
void sal_or_op_arrays (const bit_array *arr1, const bit_array *arr2, bit_array *result);

#endif /* SAL_BITOPS_H*/
