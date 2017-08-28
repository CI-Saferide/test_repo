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
			sal_printf("[%s]: Failed to allocate UID table!\n", MODULE_NAME);
			sr_cls_uid_uninit();
			return SR_ERROR;
		}
	}
	sal_printf("[%s]: Successfully initialized UID classifier!\n", MODULE_NAME);

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
	sal_printf("[%s]: Successfully removed UID classifier!\n", MODULE_NAME);
}

void sr_cls_uid_empty_table(SR_BOOL is_lock)
{
	int i;
	
	for (i=0; i<SR_RULES_TYPE_MAX; i++) {
        	memset(&sr_cls_uid_any_rules[i], 0, sizeof(bit_array));
        	sr_hash_empty_table(sr_cls_uid_table[i], is_lock);
	}
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
	
	if (uid>=0) { // 0 is a valid uid. any negative would be considered as *
		ent=sr_hash_lookup(sr_cls_uid_table[type], uid);
		if (!ent) {		
			ent = SR_ZALLOC(sizeof(*ent)); 
			if (!ent) {
				sal_printf("Error: Failed to allocate memory\n");
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
	if (uid>=0) { // 0 is a valid uid. any negative would be considered as *
		struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_uid_table[type], uid);
		if (!ent) {
			sal_printf("Error can't del rule# %u on UID:%u - rule not found\n",rulenum,uid);
			return SR_ERROR;
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
                        sal_kernel_print_alert("Delete rule %d from %d\n", msg->rulenum, msg->uid);
                        return sr_cls_uid_del_rule(msg->rule_type, msg->uid, msg->rulenum);
                        break;
                case SR_CLS_UID_ADD_RULE:
                        sal_kernel_print_alert("Add rule %d to %d\n", msg->rulenum, msg->uid);
                        return sr_cls_uid_add_rule(msg->rule_type, msg->uid, msg->rulenum);
                        break;
                default:
                        break;
        }
        return SR_SUCCESS;
}


void sr_cls_uid_ut(void)
{
	struct sr_hash_ent_t *ent;

	sr_cls_uid_add_rule(SR_NET_RULES, 69, 7);
	ent = sr_cls_uid_find(SR_NET_RULES, 69);
	if (!ent || (ent->key != 69)) {
		sal_printf("sr_cls_uid_ut: failed to match UID\n");
	}
	sr_cls_uid_add_rule(SR_NET_RULES, 37, 8);
	ent = sr_cls_uid_find(SR_NET_RULES, 69);
	if (!ent || (ent->key != 69)) {
		sal_printf("sr_cls_uid_ut: failed to match UID\n");
	}
	ent = sr_cls_uid_find(SR_NET_RULES, 37);
	if (!ent || (ent->key != 37)) {
		sal_printf("sr_cls_uid_ut: failed to match UID\n");
	}
	sr_cls_uid_del_rule(SR_NET_RULES, 69, 7);
	ent = sr_cls_uid_find(SR_NET_RULES, 37);
	if (!ent || (ent->key != 37)) {
		sal_printf("sr_cls_uid_ut: failed to match UID\n");
	}
	ent = sr_cls_uid_find(SR_NET_RULES, 69);
	if (ent) {
		sal_printf("sr_cls_uid_ut: failed to match nonexistent UID\n");
	}
	sr_cls_uid_del_rule(SR_NET_RULES, 37, 8);
	ent = sr_cls_uid_find(SR_NET_RULES, 37);
	if (ent) {
		sal_printf("sr_cls_uid_ut: failed to match nonexistent UID\n");
	}
	sal_printf("sr_cls_uid_ut: SUCCESS!\n");

}
