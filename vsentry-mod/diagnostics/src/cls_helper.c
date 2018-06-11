/* file: cls_helper.c
 * purpose: this file is used by all debugfs subjects for vsentry classifier
*/
#ifdef DEBUGFS_SUPPORT

#include "cls_helper.h"

unsigned char buf[SR_MAX_PATH];

/*
 * parameters:
 * count = user_buf size
 * ppos = start position in kernel_buf
 * len = number of Bytes to write
 * used_count = number of Bytes already written to user_buf
 */
size_t write_to_user(char __user *user_buf, size_t count, loff_t *ppos, size_t len,
		size_t *used_count)
{
	size_t rt;

	*ppos = 0; // always read from start of buf
	if (*used_count + len > count) {
		pr_debug("%s not enough space in user. call again\n",__func__);
		/* return used_count to update the amount written so far
		 * the func will be called again to write the rest
		 * pos is 0 so it will continue */
		return *used_count;
	}

	rt = simple_read_from_buffer(user_buf + *used_count, count, ppos, buf, len);
	if ((rt != len) || (*ppos != len))
		return rt;

	*used_count += len; // since it may be called several times
	return 0;
}

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

#endif /* DEBUGFS_SUPPORT */
