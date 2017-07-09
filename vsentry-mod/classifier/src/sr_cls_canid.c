#include "dispatcher.h"
#include "sal_linux.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_cls_canid.h"

#include <linux/time.h> // for unit testing

#define HT_canid_SIZE 32
struct sr_hash_table_t *sr_cls_canid_table;

int sr_cls_canid_init(void)
{
	sr_cls_canid_table = sr_hash_new_table(HT_canid_SIZE);
	if (!sr_cls_canid_table) {
		sal_kernel_print_alert("[%s]: Failed to allocate CAN MsgID table!\n", MODULE_NAME);
		return SR_ERROR;
	}
	sal_kernel_print_alert("[%s]: Successfully initialized CAN MsgID classifier!\n", MODULE_NAME);
	
	return SR_SUCCESS;
}

void sr_cls_canid_uninit(void)
{ 
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (sr_cls_canid_table != NULL) {
		pr_info("DELETEING MsgID elements!\n");
		for(i = 0; i < HT_canid_SIZE; i++) {
			if (sr_cls_canid_table->buckets[i].head != NULL){
				pr_info("hash_index[%d] - DELETEING\n",i);
				curr = sr_cls_canid_table->buckets[i].head;				
				while (curr != NULL){
					pr_info("\t\tCAN MsgID: %u\n",curr->key);
					sr_cls_print_canid_rules(curr->key);
					next = curr->next;
					SR_FREE(curr);
					curr= next;
				}
			}
		}
		
		if(sr_cls_canid_table->buckets != NULL){
			pr_info("DELETEING CAN MsgID table->bucket\n");
			SR_FREE(sr_cls_canid_table->buckets);
		}
		pr_info("DELETEING CAN MsgID table that orig size was: %u\n",sr_cls_canid_table->size);
		SR_FREE(sr_cls_canid_table);
	}
}

void sr_cls_canid_remove(SR_U32 canid)
{ 
	sr_hash_delete(sr_cls_canid_table, canid);
}

int sr_cls_canid_add_rule(SR_U32 canid, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent;
	
	ent=sr_hash_lookup(sr_cls_canid_table, canid);
	if (!ent) {		
		ent = SR_ZALLOC(sizeof(*ent)); // <-A MINE!!!
		if (!ent) {
			pr_info("Error: Failed to allocate memory\n");
			return SR_ERROR;
		} else {
			ent->ent_type = CAN_MID;
			ent->key = (SR_U32)canid;
			sr_hash_insert(sr_cls_canid_table,ent);
		}	
	}	
	sal_set_bit_array(rulenum, &ent->rules);
	pr_info("\t\trule# %u assigned to CAN MsgID: %u\n",rulenum,canid);	
	return SR_SUCCESS;
}
int sr_cls_canid_del_rule(SR_U32 canid, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_canid_table, canid);
	if (!ent) {
		pr_info("Error can't del rule# %u on CAN MsgID:%u - rule not found\n",rulenum,canid);
		return SR_ERROR;
	}
	sal_clear_bit_array(rulenum, &ent->rules);

	if (!ent->rules.summary) {
		sr_cls_canid_remove(canid);
	}
	pr_info("\t\trule# %u removed from CAN MsgID: %u\n",rulenum,canid);
	return SR_SUCCESS;
}

void print_table_canid(struct sr_hash_table_t *table)
{
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (sr_cls_canid_table != NULL) {
		pr_info("Printing CAN MsgID elements!\n");
		for(i = 0; i < HT_canid_SIZE; i++) {
			if (sr_cls_canid_table->buckets[i].head != NULL){
				pr_info("hash_index[%d]\n",i);
				curr = sr_cls_canid_table->buckets[i].head;				
				while (curr != NULL){
					pr_info("\t\tCAN MsgID: %u\n",curr->key);
					sr_cls_print_canid_rules(curr->key);
					next = curr->next;
					curr= next;
				}
			}
		}		
		if(sr_cls_canid_table->buckets != NULL){
			pr_info("Printed CAN MsgID table->bucket\n");
		}
		pr_info("Printed CAN MsgID table that orig size was: %u\n",sr_cls_canid_table->size);
	}	
}


struct sr_hash_ent_t *sr_cls_canid_find(SR_U32 canid)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_canid_table, canid);
	if (!ent) {
		pr_info("Error:%u CAN MsgID not found\n",canid);
		return NULL;
	}
	return ent;
}

void sr_cls_print_canid_rules(SR_U32 canid)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_canid_table, canid);
	bit_array rules;
	SR_16 rule;

	memset(&rules, 0, sizeof(rules));

	if (!ent) {
		pr_info("Error:%u CAN MsgID rule not found\n",canid);
		return;
	}
	sal_or_self_op_arrays(&rules, &ent->rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {
		sal_kernel_print_alert("\t\t\tRule #%d\n", rule);
	}
	
}

int myRandom_canid(int bottom, int top){ // for unit testing
	
	SR_U32 get_time;
	//int sec ,hr, min, tmp1,tmp2;
	SR_32 usec;
	struct timeval tv;

	do_gettimeofday(&tv);
	//get_time = tv.tv_sec;
	//sec = get_time % 60;
	//tmp1 = get_time / 60;
	//min = tmp1 % 60;
	//tmp2 = tmp1 / 60;
	//hr = tmp2 % 24;

	//printk("The time is hr:min:sec  ::  %d:%d:%dn",hr,min,sec);
	get_time = tv.tv_usec;
	usec = get_time % 9999;	
    return (usec % (top - bottom)) + bottom;
}

void sr_cls_canid_ut(void)
{
/*	
	SR_32 i;
	SR_32 rand;

	for(i=0;i<HT_canid_SIZE;i++){
		rand = myRandom_canid(0, SR_MAX_CANID);
		sr_cls_canid_add_rule(rand,myRandom_canid(0, 4096));
	}*/
	print_table_canid(sr_cls_canid_table);

	sr_cls_canid_add_rule(22,10);
	sr_cls_canid_add_rule(566,4);
	sr_cls_canid_add_rule(80,8);
	
	sr_cls_canid_find(444);
	sr_cls_canid_find(80);

	sr_cls_canid_add_rule(22,10);
	sr_cls_canid_add_rule(566,4);
	sr_cls_canid_add_rule(80,8);
	sr_cls_canid_add_rule(21,10);
	sr_cls_canid_add_rule(561,4);
	sr_cls_canid_add_rule(81,8);
	sr_cls_canid_add_rule(82,12);
	sr_cls_canid_add_rule(83,11);
	sr_cls_canid_add_rule(9,10);
	sr_cls_canid_add_rule(19,2000);

	print_table_canid(sr_cls_canid_table);
	
	sr_cls_canid_find(444);
	sr_cls_canid_find(80);
	
	sr_cls_canid_add_rule(0, 5);
	//print_table_canid(sr_cls_canid_table);
	sr_cls_canid_add_rule(0, 555);
	//print_table_canid(sr_cls_canid_table);
	sr_cls_canid_add_rule(200, 200);
	//print_table_canid(sr_cls_canid_table);

	sr_cls_canid_add_rule(192, 7);
	//print_table_canid(sr_cls_canid_table);
	sr_cls_canid_del_rule(100, 5);
	//print_table_canid(sr_cls_canid_table);
	sr_cls_canid_del_rule(100, 555);
	//print_table_canid(sr_cls_canid_table);
	
	//print_table_canid(sr_cls_canid_table);
	sr_cls_canid_add_rule(200, 200);	
	//print_table_canid(sr_cls_canid_table);
	sr_cls_canid_del_rule(200,200);
	sr_cls_canid_del_rule(919, 7);
	//print_table_canid(sr_cls_canid_table);
	pr_info("******************testing bucket collision******************\n");
	
	sr_cls_canid_add_rule(801,200);	
	sr_cls_canid_add_rule(808,11);
	sr_cls_canid_add_rule(80,10);
	sr_cls_canid_add_rule(801,2000);
		
	sr_cls_canid_add_rule(1, 7);
	sr_cls_canid_add_rule(820, 17);
	sr_cls_canid_add_rule(1639, 27);
	sr_cls_canid_add_rule(2458, 37);
	sr_cls_canid_add_rule(32778, 47);
	//print_table_canid(sr_cls_canid_table);
	sr_cls_canid_del_rule(1639, 27);
	print_table_canid(sr_cls_canid_table);

}
