/* file: sal_bitops_test.c
 * purpose: this file tests the bit operations functionality
*/

#ifdef UNIT_TEST

#include "sal_linux.h" //for sal_kernel_print_info
#include "sal_bitops.h"
#include "sal_bitops_test.h"

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
	SR_U64  decimal64 = 0x0;
	SR_U32  decimal = 0x0;
	SR_U8	test;
	SR_8	result;
	print_bool (32, decimal);
	sal_set_bit32(31, &decimal);
	sal_set_bit32(1, &decimal);
	print_bool (32, decimal);
	sal_clear_bit32(1, &decimal);
	print_bool (32, decimal);
	sal_change_bit32(30, &decimal);
	print_bool (32, decimal);
	test = sal_test_and_set_bit32(29, &decimal);
	sal_kernel_print_info("bit 29 equals %d\n", test);
	print_bool (32, decimal);
	
	test = sal_test_and_clear_bit32(29, &decimal);
	sal_kernel_print_info("bit 29 equals %d\n", test);
	print_bool (32, decimal);
	
	decimal = 0;
	result = sal_ffz32(decimal);
	sal_kernel_print_info("first zero bit is %d\n", result);
	decimal = 0xffffffff;
	sal_clear_bit32(17, &decimal);
	result = sal_ffz32(decimal);
	sal_kernel_print_info("first zero bit is %d\n", result);
	
	decimal = 0;
	result = sal_ffs32(decimal);
	sal_kernel_print_info("first set bit is %d\n", result);
	sal_set_bit32(26, &decimal);
	result = sal_ffs32(decimal);
	sal_kernel_print_info("first set bit is %d\n", result);
	
	decimal = 0;
	result = sal_fls32(decimal);
	sal_kernel_print_info("last set bit is %d\n", result);
	sal_set_bit32(26, &decimal);
	sal_set_bit32(22, &decimal);
	sal_set_bit32(14, &decimal);
	result = sal_fls32(decimal);
	sal_kernel_print_info("last set bit is %d\n", result);
	
	decimal64 = 0;
	result = sal_fls64(decimal64);
	sal_kernel_print_info("last set bit is %d\n", result);
	decimal64 = 0x0345672580345600;
	print_bool (64, decimal64);
	result = sal_fls64(decimal64);
	sal_kernel_print_info("last set bit is %d\n", result);
}
#endif /* UNIT_TEST */
