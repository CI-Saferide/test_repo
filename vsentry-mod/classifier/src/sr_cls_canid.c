#include "dispatcher.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_cls_canid.h"
#include "sr_cls_canbus_common.h"
#include "sr_classifier.h"

#define HT_canid_SIZE 32
struct sr_hash_table_t *sr_cls_out_canid_table;
struct sr_hash_table_t *sr_cls_in_canid_table;
bit_array sr_cls_out_canid_any_rules;
bit_array sr_cls_in_canid_any_rules;


int sr_cls_canid_init(void)
{
	
	memset(&sr_cls_out_canid_any_rules, 0, sizeof(bit_array));
	memset(&sr_cls_in_canid_any_rules, 0, sizeof(bit_array));
	
	sr_cls_out_canid_table = sr_hash_new_table(HT_canid_SIZE);
	if (!sr_cls_out_canid_table) {
		sal_kernel_print_err("[%s]: Failed to allocate OUTBAND CAN MsgID table!\n", MODULE_NAME);
		return SR_ERROR;
	}
	
	sr_cls_in_canid_table = sr_hash_new_table(HT_canid_SIZE);
	if (!sr_cls_in_canid_table) {
		sal_kernel_print_err("[%s]: Failed to allocate INBOUND CAN MsgID table!\n", MODULE_NAME);
		return SR_ERROR;
	}
	
	sal_kernel_print_info("[%s]: Successfully initialized CAN MsgID classifier!\n", MODULE_NAME);
	
	return SR_SUCCESS;
}

void sr_cls_canid_empty_table(SR_BOOL is_lock)
{
		memset(&sr_cls_out_canid_any_rules, 0, sizeof(bit_array));
		memset(&sr_cls_in_canid_any_rules, 0, sizeof(bit_array));
        sr_hash_empty_table(sr_cls_out_canid_table, is_lock);
        sr_hash_empty_table(sr_cls_in_canid_table, is_lock);
}

void sr_cls_canid_uninit(void)
{ 
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (sr_cls_out_canid_table != NULL) {
		CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,"msg=DELETEING MsgID elements");
		for(i = 0; i < HT_canid_SIZE; i++) {
			if (sr_cls_out_canid_table->buckets[i].head != NULL){
				CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,"msg=hash_index[%d] - DELETEING",i);
				curr = sr_cls_out_canid_table->buckets[i].head;				
				while (curr != NULL){
					CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
						"msg=CAN MsgID: %x dir: %d",
						curr->key,SR_CAN_OUT);
					sr_cls_print_canid_rules(curr->key,SR_CAN_OUT);
					next = curr->next;
					SR_FREE(curr);
					curr= next;
				}
			}
		}
		
		if(sr_cls_out_canid_table->buckets != NULL){
			CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,"msg=DELETEING CAN MsgID table->bucket");
			SR_FREE(sr_cls_out_canid_table->buckets);
		}
		CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,",msg=DELETEING CAN MsgID table that orig size was: %u dir: %d",sr_cls_out_canid_table->size,SR_CAN_OUT);
		SR_FREE(sr_cls_out_canid_table);
	}
	
	if (sr_cls_in_canid_table != NULL) {
		CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,"msg=DELETEING MsgID elements!");
		for(i = 0; i < HT_canid_SIZE; i++) {
			if (sr_cls_in_canid_table->buckets[i].head != NULL){
				CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,"msg=hash_index[%d] - DELETEING",i);
				curr = sr_cls_in_canid_table->buckets[i].head;				
				while (curr != NULL){
					CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
						"msg=CAN MsgID=%x dir=%d",
						curr->key,SR_CAN_IN);
					sr_cls_print_canid_rules(curr->key,SR_CAN_IN);
					next = curr->next;
					SR_FREE(curr);
					curr= next;
				}
			}
		}
		
		if(sr_cls_in_canid_table->buckets != NULL){
			CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
				"msg=DELETEING CAN MsgID table->bucket");
			SR_FREE(sr_cls_in_canid_table->buckets);
		}
		CEF_log_debug(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
			"msg=DELETEING CAN MsgID table that orig size was: %u dir: %d",
			sr_cls_in_canid_table->size,SR_CAN_IN);
		SR_FREE(sr_cls_in_canid_table);
	}
}

struct sr_hash_table_t * get_cls_in_can_table(void){
	
	return sr_cls_in_canid_table;
}

struct sr_hash_table_t * get_cls_out_can_table(void){
	
	return sr_cls_out_canid_table;
}

bit_array *src_cls_out_canid_any(void)
{
	return &sr_cls_out_canid_any_rules;
}

bit_array *src_cls_in_canid_any(void)
{
	return &sr_cls_in_canid_any_rules;
}

void sr_cls_canid_remove(SR_32 canid, SR_8 dir)
{ 
	sr_hash_delete((dir==SR_CAN_OUT)?sr_cls_out_canid_table:sr_cls_in_canid_table, canid);
}

int sr_cls_canid_add_rule(SR_32 canid, SR_U32 rulenum, SR_8 dir)
{
	struct sr_hash_ent_t *ent;
	
	if(canid != MSGID_ANY) { 
               /////////////////////////////////////////////////////////////////////////
              /*The 0 msgID is a valid number in the canbus protocol. 
                * but need to check if its really being used in the Automotive industry
                * or we gonna need to change our * = 0 = ANY convention here...*/ 
                ////////////////////////////////////////////////////////////////////////
		ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table:sr_cls_in_canid_table, canid);
		if (!ent) {             
			ent = SR_ZALLOC(sizeof(*ent)); // <-A MINE!!!
			if (!ent) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"reason=Failed to allocate memory");
				return SR_ERROR;
			} else {
				ent->ent_type = CAN_MID;
				ent->key = (SR_U32)canid;
				sr_hash_insert((dir==SR_CAN_OUT)?sr_cls_out_canid_table:sr_cls_in_canid_table,ent);
			}       
		}       

		sal_set_bit_array(rulenum, &ent->rules);
	}else{
		sal_set_bit_array(rulenum,(dir==SR_CAN_IN)?&sr_cls_in_canid_any_rules:&sr_cls_out_canid_any_rules);
		
	}
	CEF_log_event(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
					"msg=rule %u assigned to CanID=%x deviceDirection=%d",
					rulenum,canid,(dir==SR_CAN_OUT)? SR_CAN_OUT :SR_CAN_IN);
	return SR_SUCCESS;
}

int sr_cls_canid_del_rule(SR_32 canid, SR_U32 rulenum, SR_8 dir)
{    
	if(canid != MSGID_ANY) { 
		struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table:sr_cls_in_canid_table, canid);         
		if (!ent) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"reason=Error can't del rule %u CanID=%x deviceDirection=%d - rule not found",
				rulenum,canid,(dir==SR_CAN_OUT)? SR_CAN_OUT : SR_CAN_IN);
			return SR_ERROR;
		}
		sal_clear_bit_array(rulenum, &ent->rules);
		if (!ent->rules.summary) {
			sr_cls_canid_remove(canid,dir);
		}
	}else{// "Any" rules
		sal_clear_bit_array(rulenum, (dir==SR_CAN_OUT)?&sr_cls_out_canid_any_rules:&sr_cls_in_canid_any_rules);
	}
	CEF_log_event(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
		"msg=rule %u removed from CanID=%x deviceDirection=%d",
		rulenum,canid,(dir==SR_CAN_OUT)? SR_CAN_OUT : SR_CAN_IN);
	return SR_SUCCESS;
}

#ifdef DEBUG
void print_table_canid(struct sr_hash_table_t *table)
{
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (sr_cls_out_canid_table != NULL) {
		sal_kernel_print_info("Printing CAN MsgID elements!\n");
		for(i = 0; i < HT_canid_SIZE; i++) {
			if (sr_cls_out_canid_table->buckets[i].head != NULL){
				sal_kernel_print_info("hash_index[%d]\n",i);
				curr = sr_cls_out_canid_table->buckets[i].head;				
				while (curr != NULL){
					sal_kernel_print_info("\t\tCAN MsgID: %x\n",curr->key);
					sr_cls_print_canid_rules(curr->key,SR_CAN_OUT);
					next = curr->next;
					curr= next;
				}
			}
		}		
		if(sr_cls_out_canid_table->buckets != NULL){
			sal_kernel_print_info("Printed CAN MsgID table->bucket\n");
		}
		sal_kernel_print_info("Printed CAN MsgID table that orig size was: %u\n",sr_cls_out_canid_table->size);
	}	
}
#endif

struct sr_hash_ent_t *sr_cls_canid_find(SR_32 canid, SR_8 dir)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table:sr_cls_in_canid_table, canid);
	if (!ent) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"reason=%x CAN MsgID not found",canid);
		return NULL;
	}
	return ent;
}

void sr_cls_print_canid_rules(SR_32 canid, SR_8 dir)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table:sr_cls_in_canid_table, canid);
	bit_array rules;
	SR_16 rule;

	sal_memset(&rules, 0, sizeof(rules));

	if (!ent) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"reason=%x CAN MsgID rule not found",
			canid);
		return;
	}
	sal_or_self_op_arrays(&rules, &ent->rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {
		CEF_log_event(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
		"msg=rule %d",
		rule);
	}
	
}

bit_array *sr_cls_match_canid(SR_32 canid, SR_8 dir)
{
	
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table:sr_cls_in_canid_table, canid);
	if (!ent) {
		return NULL;
	}
	return(&ent->rules);
}

SR_8 sr_cls_canid_msg_dispatch(struct sr_cls_canbus_msg *msg)
{
	int st;

	switch (msg->msg_type) {
		case SR_CLS_CANID_DEL_RULE:
			CEF_log_event(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
				"msg=Delete rule %d CanID=%x deviceDirection=%d",
				msg->rulenum, msg->canid, (msg->dir==SR_CAN_OUT)? SR_CAN_OUT : SR_CAN_IN);
			if ((st =  sr_cls_canid_del_rule(msg->canid, msg->rulenum,msg->dir)) != SR_SUCCESS)
			   return st;
			if ((st = sr_cls_exec_inode_del_rule(SR_CAN_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
			   return st;
			return sr_cls_uid_del_rule(SR_CAN_RULES, msg->uid, msg->rulenum);
		case SR_CLS_CANID_ADD_RULE:
			CEF_log_event(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
				"msg=add rule %d suser=%d CanID=%x deviceDirection=%d",
				msg->rulenum, msg->uid, msg->canid, (msg->dir==SR_CAN_OUT)? SR_CAN_OUT : SR_CAN_IN);
			if ((st = sr_cls_canid_add_rule(msg->canid, msg->rulenum,msg->dir)) != SR_SUCCESS)
			   return st;
			if ((st =  sr_cls_exec_inode_add_rule(SR_CAN_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
			   return st;
			return sr_cls_uid_add_rule(SR_CAN_RULES, msg->uid, msg->rulenum);
			break;
		default:
			break;
	}
	return SR_SUCCESS;
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
