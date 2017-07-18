/* file: sal_bitops.h
 * purpose: this file encapsulates all bit operations
 * 			including data structures for 4K bits
*/

#ifndef SAL_BITOPS_H
#define SAL_BITOPS_H

#include "sr_types.h"

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
#define array_is_clear(ba) (!ba.summary)

void sal_set_bit_array (SR_U16 bit, bit_array *arr);
void sal_clear_bit_array (SR_U16 bit, bit_array *arr);
SR_16 sal_ffs_array (bit_array *arr);
SR_16 sal_ffs_and_clear_array (bit_array *arr);
SR_16 sal_ffs_and_clear_bitmask (SR_U64 *bitmask);
void sal_and_op_arrays (bit_array *arr1, bit_array *arr2, bit_array *result);
void sal_or_op_arrays (bit_array *arr1, bit_array *arr2, bit_array *result);
void sal_or_self_op_arrays (bit_array *base, bit_array *addon);
void sal_and_self_op_arrays (bit_array *base, bit_array *addon);
void sal_and_self_op_two_arrays (bit_array *base, bit_array *A, bit_array *B);
void sal_not_op_array (bit_array *arr);
SR_BOOL sal_bit_array_is_set (SR_U16 bit, bit_array *arr);


#endif /* SAL_BITOPS_H*/
