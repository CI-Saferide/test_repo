#include "dispatcher.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_classifier.h"

//#include <linux/time.h> // for unit testing

#define UID_HASH_TABLE_SIZE 32
struct sr_hash_table_t *sr_cls_uid_table[SR_RULES_TYPE_MAX]; // by enum sr_rule_type
bit_array sr_cls_uid_any_rules[SR_RULES_TYPE_MAX];

int sr_cls_uid_init(void)
{
	int i;
	
	for (i=0; i<SR_RULES_TYPE_MAX; i++) {
		memset(&sr_cls_uid_any_rules[i], 0, sizeof(bit_array));

		sr_cls_uid_table[i] = sr_hash_new_table(UID_HASH_TABLE_SIZE);
		if (!sr_cls_uid_table[i]) {
			sal_kernel_print_err("[%s]: Failed to allocate UID table!\n", MODULE_NAME);
			sr_cls_uid_uninit();
			return SR_ERROR;
		}
	}
	//sal_kernel_print_info("[%s]: Successfully initialized UID classifier!\n", MODULE_NAME);

	return SR_SUCCESS;
}

void sr_cls_uid_uninit(void)
{ 
	SR_32 i, j;
	struct sr_hash_ent_t *curr, *next;
	
	for (j=0; j<SR_RULES_TYPE_MAX; j++) {
		if (sr_cls_uid_table[j] != NULL) {
			for(i = 0; i < UID_HASH_TABLE_SIZE; i++) {
				if (sr_cls_uid_table[j]->buckets[i].head != NULL){
					curr = sr_cls_uid_table[j]->buckets[i].head;				
					while (curr != NULL){
						next = curr->next;
						SR_FREE(curr);
						curr= next;
					}
				}
			}

			if(sr_cls_uid_table[j]->buckets != NULL){
				SR_FREE(sr_cls_uid_table[j]->buckets);
			}
			SR_FREE(sr_cls_uid_table[j]);
			sr_cls_uid_table[j] = NULL;
		}
	}
	sal_kernel_print_info("[%s]: Successfully removed UID classifier!\n", MODULE_NAME);
}

void sr_cls_uid_empty_table(SR_BOOL is_lock)
{
	int i;
	
	for (i=0; i<SR_RULES_TYPE_MAX; i++) {
        	memset(&sr_cls_uid_any_rules[i], 0, sizeof(bit_array));
        	sr_hash_empty_table(sr_cls_uid_table[i], is_lock);
	}
}  

struct sr_hash_table_t * get_cls_uid_table(enum sr_rule_type type){
	
	return sr_cls_uid_table[type];
}    

bit_array *sr_cls_uid_any(enum sr_rule_type type)
{
        return &sr_cls_uid_any_rules[type];
}

void sr_cls_uid_remove(enum sr_rule_type type, SR_32 uid)
{ 
	sr_hash_delete(sr_cls_uid_table[type], uid);
}

int sr_cls_uid_add_rule(enum sr_rule_type type, SR_32 uid, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent;

	if (uid != UID_ANY) {
		ent=sr_hash_lookup(sr_cls_uid_table[type], uid);
		if (!ent) {		
			ent = SR_ZALLOC(sizeof(*ent)); 
			if (!ent) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to add uid for rule %u, memory allocation fail",
					REASON,rulenum);
				return SR_ERROR;
			} else {
				ent->ent_type = UID;
				ent->key = (SR_U32)uid;
				sr_hash_insert(sr_cls_uid_table[type], ent);
			}	
		}	
		sal_set_bit_array(rulenum, &ent->rules);
	} else {
		sal_set_bit_array(rulenum, &sr_cls_uid_any_rules[type]);
	}
	return SR_SUCCESS;
}

int sr_cls_uid_del_rule(enum sr_rule_type type, SR_32 uid, SR_U32 rulenum)
{
	if (uid != UID_ANY) {
		struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_uid_table[type], uid);
		if (!ent) {
			// uid was delete for other entity of the rule (port, ip etc ...).
			return SR_SUCCESS;
		}
		sal_clear_bit_array(rulenum, &ent->rules);

		if (!ent->rules.summary) {
			sr_cls_uid_remove(type, uid);
		}
	} else { // "Any" rules
		sal_clear_bit_array(rulenum, &sr_cls_uid_any_rules[type]);
	}
	return SR_SUCCESS;
}

struct sr_hash_ent_t *sr_cls_uid_find(enum sr_rule_type type, SR_32 uid)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_uid_table[type], uid);
	if (!ent) {
		return NULL;
	}
	return ent;
}

bit_array *sr_cls_match_uid(enum sr_rule_type type, SR_32 uid)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_uid_table[type], uid);

	if (!ent) {
		return NULL;
	}
	return(&ent->rules);
}

SR_8 sr_cls_uid_msg_dispatch(struct sr_cls_uid_msg *msg)
{
        switch (msg->msg_type) {
                case SR_CLS_UID_DEL_RULE:
                        CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
							"%s=del uid rule %d from %d",MESSAGE,
							msg->rulenum,msg->uid);
                        return sr_cls_uid_del_rule(msg->rule_type, msg->uid, msg->rulenum);
                        break;
                case SR_CLS_UID_ADD_RULE:
                        CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
							"%s=add uid rule %d to %d",MESSAGE,
							msg->rulenum, msg->uid);
                        return sr_cls_uid_add_rule(msg->rule_type, msg->uid, msg->rulenum);
                        break;
                default:
                        break;
        }
        return SR_SUCCESS;
}
