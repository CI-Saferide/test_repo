/* file: cls_helper.c
 * purpose: this file is used by all sysfs subjects for vsentry classifier
*/
#include "cls_helper.h"

SR_U32 get_exec_for_rule(struct sr_hash_table_t *table,SR_16 rule,SR_32 table_size,enum sr_rule_type type)
{
	SR_32 i;
	bit_array ba_res;
	struct sr_hash_ent_multy_t *curr, *next;
	
	if (table != NULL) {
		for(i = 0; i < table_size; i++) {
			if (table->buckets[i].head != NULL){
				curr = ( struct sr_hash_ent_multy_t *)table->buckets[i].head;					
				while (curr != NULL){			
					if(sal_test_bit_array(rule,&(curr->rules[type]))){
						return curr->key;
					}									
					next = (struct sr_hash_ent_multy_t *)curr->next;
					curr = next;
				}
			}
		}		
	}
	
	sal_or_self_op_arrays(&ba_res,sr_cls_exec_file_any(SR_FILE_RULES));
	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		return 0;
	}
	return -1;
}

SR_U32 get_uid_for_rule(struct sr_hash_table_t *table,SR_16 rule,SR_32 table_size,enum sr_rule_type type)
{
	SR_32 i;
	bit_array ba_res;
	struct sr_hash_ent_t *curr, *next;
	
	if (table != NULL) {
		for(i = 0; i < table_size; i++) {
			if (table->buckets[i].head != NULL){
				curr = table->buckets[i].head;					
				while (curr != NULL){
					if(sal_test_bit_array(rule,&curr->rules)){
						return curr->key;
					}
					next = curr->next;
					curr = next;
				}
			}
		}		
	}

	sal_or_self_op_arrays(&ba_res,sr_cls_uid_any(type));
	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		return 0;
	}	
	
	return -1;
}
