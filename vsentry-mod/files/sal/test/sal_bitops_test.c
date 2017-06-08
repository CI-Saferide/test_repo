/* file: sal_bitops_test.c
 * purpose: this file tests the bit operations functionality
*/

#ifdef UNIT_TEST

#include "sal_linux.h" //for sal_kernel_print_info
#include "sal_bitops.h"
#include "sal_bitops_test.h"

/* allocate buffers globaly as they exceed the function stack max buffer */
bit_array	test_arr ={0};
bit_array	test_arr2 ={0};
bit_array	test_arr3 ={0};
bit_array	test_arr4 ={0};
	
#define DELIMITER	4
void print_bool (SR_U8 bits, SR_U64 num)
{
	SR_U8   index;
	SR_U8   str_inx; 
	SR_U8   delimiter;
	SR_U64  tmp;
	index = bits-1;
	str_inx = 0;
	delimiter = (DELIMITER-1);
	SR_U8 str[80];
	switch (bits) {
		case 8:  tmp = 0x80; break;
		case 16: tmp = 0x8000; break;
		case 32: tmp = 0x80000000; break;
		case 64: tmp = 0x8000000000000000; break;
		default:
			sal_kernel_print_err ("[%s] printing %d bits is not supported\n", __FUNCTION__, bits);
			return;
	};
	while (index >= 0) {
		str[str_inx] = (num & tmp)? '1':'0';
		tmp = (tmp >> 1);
		if (index == 0 ) 
			break;
		index--;
		if (str_inx == delimiter)  {
			str_inx++;
			str[str_inx] = ' ';
			delimiter+= (DELIMITER+1);
		}
		str_inx++;
	}
	str[++str_inx] = 0;
	sal_kernel_print_info ("%s\n", str);
} 

void sal_bitops_test (SR_U32 test_num)
{
	SR_U64  	decimal64 = 0x0;
	SR_U32  	decimal = 0x0;
	SR_16  	ffs_result;
	//SR_U8		test;
	SR_8		result;
	SR_BOOL		bool_result;

	decimal = 0;
	decimal64 = 0;
	result = sal_fls64(decimal64);
	sal_kernel_print_info("last set bit is %d\n", result);
	decimal64 = 0x0345672580345600;
	print_bool (64, decimal64);
	result = sal_fls64(decimal64);
	sal_kernel_print_info("last set bit is %d\n", result);
	
	sal_kernel_print_info("----------------------------\n");
	decimal64 = 0;
	print_bool (64, decimal64);
	sal_set_bit(60, &decimal64);
	sal_set_bit(54, &decimal64);
	sal_set_bit(35, &decimal64);
	sal_set_bit(17, &decimal64);
	print_bool (64, decimal64);
	
	sal_kernel_print_info("----------------------------\n");
	decimal64 = 0xffffffffffffffff;
	print_bool (64, decimal64);
	sal_clear_bit(60, &decimal64);
	sal_clear_bit(54, &decimal64);
	sal_clear_bit(35, &decimal64);
	sal_clear_bit(17, &decimal64);
	print_bool (64, decimal64);
	
	sal_kernel_print_info("----------------------------\n");
	decimal64 = 0;
	sal_set_bit(60, &decimal64);
	sal_set_bit(54, &decimal64);
	sal_set_bit(35, &decimal64);
	sal_set_bit(17, &decimal64);
	sal_set_bit(3, &decimal64);
	print_bool (64, decimal64);
	result = sal_ffs64(&decimal64);
	sal_kernel_print_info("first set bit is %d\n", result);
	sal_clear_bit(3, &decimal64);
	result = sal_ffs64(&decimal64);
	sal_kernel_print_info("first set bit is %d\n", result);
	decimal64 = 0;
	result = sal_ffs64(&decimal64);
	sal_kernel_print_info("first set bit is %d\n", result);
	
	sal_kernel_print_info("----------------------------\n");
	sal_set_bit_array (64, &test_arr);
	sal_set_bit_array (70, &test_arr);
	sal_set_bit_array (127, &test_arr);
	sal_set_bit_array (191, &test_arr);
	sal_set_bit_array (4094, &test_arr);
	sal_kernel_print_info("summary register:\n");
	print_bool (64, test_arr.summary);
	for (decimal=0; decimal<64; decimal++) {
		sal_kernel_print_info("level2[%ld] register:\n", decimal);
		print_bool (64, test_arr.level2[decimal]);
	}
	
	sal_kernel_print_info("----------------------------\n");
	sal_clear_bit_array (64, &test_arr);
	sal_clear_bit_array (70, &test_arr);
	sal_clear_bit_array (127, &test_arr);
	print_bool (64, test_arr.summary);
	for (decimal=0; decimal<64; decimal++) {
		sal_kernel_print_info("level2[%ld] register:\n", decimal);
		print_bool (64, test_arr.level2[decimal]);
	}
	
	sal_kernel_print_info("----------------------------\n");
	sal_set_bit_array (728, &test_arr);
	ffs_result = sal_ffs_and_clear_array(&test_arr);	
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	ffs_result = sal_ffs_and_clear_array(&test_arr);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	ffs_result = sal_ffs_and_clear_array(&test_arr);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	ffs_result = sal_ffs_and_clear_array(&test_arr);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	
	sal_set_bit_array (32, &test_arr);
	sal_set_bit_array (43, &test_arr);
	sal_set_bit_array (3456, &test_arr);
	sal_set_bit_array (728, &test_arr);
	
	sal_set_bit_array (728, &test_arr2);
	sal_set_bit_array (375, &test_arr2);
	sal_set_bit_array (1234, &test_arr2);
	sal_set_bit_array (3478, &test_arr2);
	
	//sal_and_op_arrays (&test_arr, &test_arr2, &test_arr3);
	//ffs_result = sal_ffs_array(&test_arr);	
	//sal_kernel_print_info("[arr] first set bit is %d\n", ffs_result);
	//ffs_result = sal_ffs_array(&test_arr2);	
	//sal_kernel_print_info("[arr2] first set bit is %d\n", ffs_result);
	//ffs_result = sal_ffs_array(&test_arr3);	
	//sal_kernel_print_info("[arr3] first set bit is %d\n", ffs_result);

	sal_kernel_print_info("----------------------------\n");
	sal_kernel_print_info("after OR:\n");
	sal_or_op_arrays (&test_arr, &test_arr2, &test_arr3);
	ffs_result = sal_ffs_and_clear_array(&test_arr3);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	ffs_result = sal_ffs_and_clear_array(&test_arr3);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	ffs_result = sal_ffs_and_clear_array(&test_arr3);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	ffs_result = sal_ffs_and_clear_array(&test_arr3);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	ffs_result = sal_ffs_and_clear_array(&test_arr3);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	ffs_result = sal_ffs_and_clear_array(&test_arr3);
	sal_kernel_print_info("first set bit is %d\n", ffs_result);
	
	sal_not_op_array(&test_arr3);
	
	
	decimal64 = 3;
	print_bool (64, decimal64);
	bool_result = sal_test_and_set_bit(60, &decimal64);
	sal_kernel_print_info("bool_result =  %d\n", bool_result);
	bool_result = sal_test_and_set_bit(60, &decimal64);
	sal_kernel_print_info("bool_result =  %d\n", bool_result);
	print_bool (64, decimal64);
	
	bool_result = sal_test_and_clear_bit(60, &decimal64);
	sal_kernel_print_info("bool_result =  %d\n", bool_result);
	print_bool (64, decimal64);
	
	sal_set_bit_array (32, &test_arr4);
	sal_set_bit_array (4095, &test_arr4);
	test_arr4.level2[0] = 0xffffffffffffffff;
	
	sal_kernel_print_info("after NOT\n");
	sal_not_op_array(&test_arr4);
	sal_kernel_print_info("arr4 summary\n");
	print_bool (64, test_arr4.summary);
	for (decimal=0; decimal<64; decimal++) {
		sal_kernel_print_info("level2[%ld] register:\n", decimal);
		print_bool (64, test_arr4.level2[decimal]);
	}
	
}
#endif /* UNIT_TEST */
