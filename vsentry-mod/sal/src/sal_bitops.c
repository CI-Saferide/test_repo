/* file: sal_bitops.c
 * purpose: this file implements the platform agnostic bit opearations
 *          the implementation enhances the basic implementation (with
 *			is platform specific)
*/

#include "sal_bitops.h"
#include "sal_module.h"
#include "sr_sal_common.h"


SR_BOOL sal_bit_array_is_set (SR_U16 bit, bit_array *arr)
{
	if (bit > 4095)
		return 0;
	if ((arr->summary & (1ULL<<(bit/64))) && (arr->level2[bit/64] & (1ULL<<(bit%64)))) {
		return 1;
	} else {
		return 0;
	}
}
void sal_set_bit_array (SR_U16 bit, bit_array *arr)
{
	SR_U8		pos_in_summary;
	if (bit > 4095)
		return;
	pos_in_summary = (bit/64);
	sal_set_bit(pos_in_summary, &arr->summary);
	sal_set_bit((bit%64), &arr->level2[pos_in_summary]);
}

void sal_clear_bit_array (SR_U16 bit, bit_array *arr)
{
	SR_U8		pos_in_summary;
	if (bit > 4095)
		return;
	pos_in_summary = (bit/64);
	sal_clear_bit((bit%64), &arr->level2[pos_in_summary]);
	if (!arr->level2[pos_in_summary])
		sal_clear_bit(pos_in_summary, &arr->summary);
}

SR_16 sal_ffs_array (bit_array *arr)
{
	SR_U8		summary_ffs;
	SR_U8		level2_ffs;
	
	/* check if whole structure is empty */
	if (!arr->summary)
		return (-1);
	summary_ffs = sal_ffs64(&arr->summary);
	level2_ffs = sal_ffs64(&arr->level2[summary_ffs]);
	return ((summary_ffs * 64) + level2_ffs);
}

void sal_not_op_array (bit_array *arr)
{
	SR_U8 index;
	arr->summary = 0;
	for (index=0; index < 64; index++) {
		arr->level2[index] = ~(arr->level2[index]);
		if (arr->level2[index]) {
			sal_set_bit(index, &arr->summary);
		}
	}
}

SR_16 sal_ffs_and_clear_array (bit_array *arr)
{
	SR_U8		summary_ffs;
	SR_U8		level2_ffs;
	
	/* check if whole structure is empty */
	if (!arr->summary)
		return (-1);
	summary_ffs = sal_ffs64(&arr->summary);
	level2_ffs = sal_ffs64(&arr->level2[summary_ffs]);
	sal_clear_bit(level2_ffs, &arr->level2[summary_ffs]);
	if (!(arr->level2[summary_ffs]))
		sal_clear_bit(summary_ffs, &arr->summary);
	return ((summary_ffs * 64) + level2_ffs);
}

SR_16 sal_ffs_and_clear_bitmask (SR_U64 *bitmask)
{
	SR_U8		first_set_bit;
	
	/* check if whole structure is empty */
	if (*bitmask == 0) {
		return (-1);
	} 
	first_set_bit = sal_ffs64(bitmask);
	sal_clear_bit(first_set_bit, bitmask);
	return first_set_bit;
}

//TODO: Avoid blind operation - perform level2 only for relevant bits
void sal_and_op_arrays (bit_array *arr1, bit_array *arr2, bit_array *result)
{
	SR_U8 index;
	result->summary = ((arr1->summary) & (arr2->summary));
	for (index=0; index < 64; index++) {
		result->level2[index] = ((arr1->level2[index]) & (arr2->level2[index]));
	}
}

void sal_or_op_arrays (bit_array *arr1, bit_array *arr2, bit_array *result)
{
	SR_U8 index;
	result->summary = ((arr1->summary) | (arr2->summary));
	for (index=0; index < 64; index++) {
		result->level2[index] = ((arr1->level2[index]) | (arr2->level2[index]));
	}
}

void sal_or_self_op_arrays (bit_array *base, bit_array *addon)
{
	SR_16 index;
	SR_U64 summary = addon->summary;
	base->summary |= addon->summary;
	while ((index = sal_ffs_and_clear_bitmask(&summary)) != -1) {
		base->level2[index] |= addon->level2[index];
	}
}

void sal_and_self_op_arrays (bit_array *base, bit_array *addon)
{
	SR_16	index;
	SR_U64 summary = base->summary | addon->summary;
	base->summary &= addon->summary;
	while ((index = sal_ffs_and_clear_bitmask(&summary)) != -1) {
		base->level2[index] &= addon->level2[index];
		if (!base->level2[index]) { // need to clean summary bit !!!
			base->summary &= (~((SR_U64)1<<index));
		}
	}
}

void sal_and_self_op_two_arrays (bit_array *base, bit_array *A, bit_array *B)
{
	SR_16	index;
	SR_U64 summary = base->summary & (A->summary | B->summary);
	base->summary = summary;
	while ((index = sal_ffs_and_clear_bitmask(&summary)) != -1) {
		base->level2[index] &= (A->level2[index]|B->level2[index]);
		if (!base->level2[index]) { // need to clean summary bit !!!
			base->summary &= (~((SR_U64)1<<index));
		}
	}
}

SR_BOOL sal_test_bit_array(SR_U16 bit, bit_array *arr)
{
	SR_U8		pos_in_summary;
	if (bit > 4095)
		return (-1);
	pos_in_summary = (bit/64);
	return (SR_BOOL)(sal_test_bit((bit%64), &arr->level2[pos_in_summary]));
}

void sal_print_bit_array(bit_array *arr)
 {
 	bit_array tmp;
 	SR_16 rule;
 
 	memcpy(&tmp, arr, sizeof (bit_array));
 
 	sal_kernel_print_info("sal_print_bit_array: Printing ruleset for array %p\n", arr);
 
 	while ((rule = sal_ffs_and_clear_array (&tmp)) != -1) {
                 sal_kernel_print_info("Rule #%d is set\n", rule);
 	}
 	sal_kernel_print_info("sal_print_bit_array: Done printing\n");
 }
