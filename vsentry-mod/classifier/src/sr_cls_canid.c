#include "dispatcher.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_cls_canid.h"
#include "sr_cls_canbus_common.h"
#include "sr_classifier.h"

#define HT_canid_SIZE 32
struct sr_hash_table_t *sr_cls_out_canid_table[CAN_INTERFACES_MAX];
struct sr_hash_table_t *sr_cls_in_canid_table[CAN_INTERFACES_MAX];
bit_array sr_cls_out_canid_any_rules[CAN_INTERFACES_MAX];
bit_array sr_cls_in_canid_any_rules[CAN_INTERFACES_MAX];
static char *interfaces_name[CAN_INTERFACES_MAX];

int sr_cls_canid_init(void)
{
	SR_U32 i;
	char *if_name;

	for (i = 0; i < CAN_INTERFACES_MAX; i++) {
		memset(&sr_cls_out_canid_any_rules[i], 0, sizeof(bit_array));
		memset(&sr_cls_in_canid_any_rules[i], 0, sizeof(bit_array));
	
		sr_cls_out_canid_table[i] = sr_hash_new_table(HT_canid_SIZE);
		if (!sr_cls_out_canid_table[i]) {
			sal_kernel_print_err("[%s]: failed to allocate outbaund can mid table\n", MODULE_NAME);
			return SR_ERROR;
		}
	
		sr_cls_in_canid_table[i] = sr_hash_new_table(HT_canid_SIZE);
		if (!sr_cls_in_canid_table[i]) {
			sal_kernel_print_err("[%s]: failed to allocate inbaund can mid table\n", MODULE_NAME);
			return SR_ERROR;
		}
		if ((if_name = sal_get_interface_name(i))) {
		 	interfaces_name[i] = SR_KZALLOC(strlen(if_name) + 1);
			if (!interfaces_name[i]) {
				sal_kernel_print_err("[%s]: failed to allocate interface name \n", MODULE_NAME);
				return SR_ERROR;
			}
			strcpy(interfaces_name[i], if_name);
		}
		
	}
	sal_kernel_print_info("[%s]: successfully initialized can mid classifier\n", MODULE_NAME);
	
	return SR_SUCCESS;
}

char *sr_cls_get_interface_name(SR_32 if_id)
{
	if (if_id >= CAN_INTERFACES_MAX)
		return NULL;
	return interfaces_name[if_id];
}

void sr_cls_canid_empty_table(SR_BOOL is_lock)
{
	SR_U32 i;

	for (i = 0; i < CAN_INTERFACES_MAX; i++) {
		memset(&sr_cls_out_canid_any_rules[i], 0, sizeof(bit_array));
		memset(&sr_cls_in_canid_any_rules[i], 0, sizeof(bit_array));
		sr_hash_empty_table(sr_cls_out_canid_table[i], is_lock);
		sr_hash_empty_table(sr_cls_in_canid_table[i], is_lock);
	}
}

void sr_cls_canid_uninit(void)
{ 
	SR_32 i;

	for (i = 0; i < CAN_INTERFACES_MAX; i++) {
		sr_hash_free_table(sr_cls_out_canid_table[i]);
		sr_cls_out_canid_table[i] = NULL;
		sr_hash_free_table(sr_cls_in_canid_table[i]);
		sr_cls_in_canid_table[i] = NULL;
		if (interfaces_name[i])
			SR_KFREE(interfaces_name[i]);
	}
}

#ifdef DEBUGFS_SUPPORT
struct sr_hash_table_t * get_cls_in_can_table(void){
	
	return sr_cls_in_canid_table;
}

struct sr_hash_table_t * get_cls_out_can_table(void){
	
	return sr_cls_out_canid_table;
}
#endif

bit_array *src_cls_out_canid_any(SR_32 if_id)
{
	return &sr_cls_out_canid_any_rules[if_id];
}

bit_array *src_cls_in_canid_any(SR_32 if_id)
{
	return &sr_cls_in_canid_any_rules[if_id];
}

void sr_cls_canid_remove(SR_32 canid, SR_8 dir, SR_32 if_id)
{ 
	sr_hash_delete((dir==SR_CAN_OUT)?sr_cls_out_canid_table[if_id]:sr_cls_in_canid_table[if_id], canid);
}

int sr_cls_canid_add_rule(SR_32 canid, SR_U32 rulenum, SR_8 dir, SR_32 if_id)
{
	struct sr_hash_ent_t *ent;
	
	if(canid != MSGID_ANY) { 
               /////////////////////////////////////////////////////////////////////////
              /*The 0 msgID is a valid number in the canbus protocol. 
                * but need to check if its really being used in the Automotive industry
                * or we gonna need to change our * = 0 = ANY convention here...*/ 
                ////////////////////////////////////////////////////////////////////////
		ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table[if_id]:sr_cls_in_canid_table[if_id], canid);
		if (!ent) {             
			ent = SR_ZALLOC(sizeof(*ent));
			if (!ent) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=cls-can:failed to allocate memory",REASON);
				return SR_ERROR;
			} else {
				ent->ent_type = CAN_MID;
				ent->key = (SR_U32)canid;
				sr_hash_insert((dir==SR_CAN_OUT)?sr_cls_out_canid_table[if_id]:sr_cls_in_canid_table[if_id],ent);
			}       
		}       

		sal_set_bit_array(rulenum, &ent->rules);
	}else{
		sal_set_bit_array(rulenum,(dir==SR_CAN_IN)?&sr_cls_in_canid_any_rules[if_id]:&sr_cls_out_canid_any_rules[if_id]);
		
	}
#ifdef DEBUG
	CEF_log_event(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
		"%s=rule assigned to %s=%u %s=%x %s=%s",MESSAGE,
		RULE_NUM_KEY,rulenum,
		CAN_MSG_ID,canid,
		DEVICE_DIRECTION,(dir==SR_CAN_OUT)? "out" : ((dir==SR_CAN_IN)? "in" : "in-out"));
#endif
	return SR_SUCCESS;
}

int sr_cls_canid_del_rule(SR_32 canid, SR_U32 rulenum, SR_8 dir, SR_32 if_id)
{
	if(canid != MSGID_ANY) { 
		struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table[if_id]:sr_cls_in_canid_table[if_id], canid);
		if (!ent) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to del %s=%u %s=%x %s=%s rule not found",REASON,
				RULE_NUM_KEY,rulenum,
				CAN_MSG_ID,canid,
				DEVICE_DIRECTION,(dir==SR_CAN_OUT)? "out" : ((dir==SR_CAN_IN)? "in" : "in-out"));
			return SR_ERROR;
		}
		sal_clear_bit_array(rulenum, &ent->rules);
		if (!ent->rules.summary) {
			sr_cls_canid_remove(canid,dir, if_id);
		}
	}else{// "Any" rules
		sal_clear_bit_array(rulenum, (dir==SR_CAN_OUT)?&sr_cls_out_canid_any_rules[if_id]:&sr_cls_in_canid_any_rules[if_id]);
	}
#ifdef DEBUG
	CEF_log_event(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
		"%s=rule remove %s=%u %s=%x %s=%s",MESSAGE,
		RULE_NUM_KEY,rulenum,
		CAN_MSG_ID,canid,
		DEVICE_DIRECTION,(dir==SR_CAN_OUT)? "out" : ((dir==SR_CAN_IN)? "in" : "in-out"));
#endif
	return SR_SUCCESS;
}

#ifdef DEBUG
void print_table_canid(struct sr_hash_table_t *table)
{
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (sr_cls_out_canid_table != NULL) {
		sal_kernel_print_info("printing can mid elements!\n");
		for(i = 0; i < HT_canid_SIZE; i++) {
			if (sr_cls_out_canid_table->buckets[i].head != NULL){
				sal_kernel_print_info("hash_index[%d]\n",i);
				curr = sr_cls_out_canid_table->buckets[i].head;				
				while (curr != NULL){
					sal_kernel_print_info("can mid: %x\n",curr->key);
					sr_cls_print_canid_rules(curr->key,SR_CAN_OUT);
					next = curr->next;
					curr= next;
				}
			}
		}		
		if(sr_cls_out_canid_table->buckets != NULL){
			sal_kernel_print_info("printed can mid table bucket\n");
		}
		sal_kernel_print_info("printed can mid table that orig size was: %u\n",sr_cls_out_canid_table->size);
	}	
}
#endif

struct sr_hash_ent_t *sr_cls_canid_find(SR_32 canid, SR_8 dir, SR_32 if_id)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table[if_id] : sr_cls_in_canid_table[if_id], canid);
	if (!ent) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=%x can mid not found",REASON,
			canid);
		return NULL;
	}
	return ent;
}

bit_array *sr_cls_match_canid(SR_32 canid, SR_8 dir, SR_32 if_id)
{
	
	struct sr_hash_ent_t *ent=sr_hash_lookup((dir==SR_CAN_OUT)?sr_cls_out_canid_table[if_id]:sr_cls_in_canid_table[if_id], canid);
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
				"%s=delete %s=%d %s=%x %s=%s",MESSAGE,
				RULE_NUM_KEY,msg->rulenum, 
				CAN_MSG_ID,msg->canid, 
				DEVICE_DIRECTION,(msg->dir==SR_CAN_OUT)? "out" : ((msg->dir==SR_CAN_IN)? "in" : "in-out"),
				IF_ID, msg->if_id);
			if (msg->dir==SR_CAN_BOTH) {
				// del IN
				if ((st =  sr_cls_canid_del_rule(msg->canid, msg->rulenum, SR_CAN_IN, msg->if_id)) != SR_SUCCESS)
					return st;
				// del OUT
				if ((st =  sr_cls_canid_del_rule(msg->canid, msg->rulenum, SR_CAN_OUT, msg->if_id)) != SR_SUCCESS)
					return st;
			} else { // IN/OUT
				if ((st =  sr_cls_canid_del_rule(msg->canid, msg->rulenum, msg->dir, msg->if_id)) != SR_SUCCESS)
					return st;
			}
			if ((st = sr_cls_exec_inode_del_rule(SR_CAN_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
			   return st;
			return sr_cls_uid_del_rule(SR_CAN_RULES, msg->uid, msg->rulenum);
		case SR_CLS_CANID_ADD_RULE:
			CEF_log_event(SR_CEF_CID_CAN, "info", SEVERITY_LOW,
				"%s=add %s=%d %s=%d %s=%x %s=%s",MESSAGE,
				RULE_NUM_KEY,msg->rulenum, 
				DEVICE_UID,msg->uid, 
				CAN_MSG_ID,msg->canid, 
				DEVICE_DIRECTION,(msg->dir==SR_CAN_OUT)? "out" : ((msg->dir==SR_CAN_IN)? "in" : "in-out"),
				IF_ID, msg->if_id);
			if (msg->dir==SR_CAN_BOTH) {
				// add IN
				if ((st = sr_cls_canid_add_rule(msg->canid, msg->rulenum, SR_CAN_IN, msg->if_id)) != SR_SUCCESS)
					return st;
				// add OUT
				if ((st = sr_cls_canid_add_rule(msg->canid, msg->rulenum,SR_CAN_OUT, msg->if_id)) != SR_SUCCESS)
					return st;
			} else { // IN/OUT
				if ((st = sr_cls_canid_add_rule(msg->canid, msg->rulenum, msg->dir, msg->if_id)) != SR_SUCCESS)
					return st;
			}
			if ((st =  sr_cls_exec_inode_add_rule(SR_CAN_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
				return st;
			return sr_cls_uid_add_rule(SR_CAN_RULES, msg->uid, msg->rulenum);
			break;
		default:
			break;
	}
	return SR_SUCCESS;
}
