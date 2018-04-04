#include "dispatcher.h"
#include "sal_linux.h"
#include "sr_hash.h"
#include "sal_bitops.h"
#include "sr_cls_exec_file.h"

struct sr_hash_table_t *sr_cls_exec_file_table;
bit_array sr_cls_exec_file_any_rules[SR_RULES_TYPE_MAX];

#define EXEC_FILE_HASH_TABLE_SIZE 8192

static int is_multy_entry_clear(struct sr_hash_ent_multy_t *ent)
{
	int is_clear = 1, i;

	for (i = 0; i < SR_RULES_TYPE_MAX && is_clear; i++) {
	    if (ent->rules[i].summary)
	       is_clear = 0;
	}
 
	return is_clear;
}

void sr_cls_exec_inode_remove(SR_U32 exec_inode)
{ 

	sr_hash_delete(sr_cls_exec_file_table, exec_inode);
}

bit_array *sr_cls_exec_file_any(enum sr_rule_type type)
{
        return &sr_cls_exec_file_any_rules[type];
}

// type: NET/FILE/CAN
// exec_inode: inode of executable
// rulenum: index of rule to be added
int sr_cls_exec_inode_add_rule(enum sr_rule_type type, SR_U32 exec_inode, SR_U32 rulenum)
{
	if (likely(exec_inode != INODE_ANY)) {
		struct sr_hash_ent_multy_t *ent=( struct sr_hash_ent_multy_t *)sr_hash_lookup(sr_cls_exec_file_table, exec_inode);
		if (!ent) {
			ent = SR_ZALLOC(sizeof(*ent));
			if (!ent) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
				"Failed to allocate memory for exec_file rule %d",REASON,
				rulenum);
				return SR_ERROR;
			} else {
				ent->key = exec_inode;
				CEF_log_debug(SR_CEF_CID_FILE, "info", SEVERITY_LOW, 
				"%s=add exec file inode %u",MESSAGE,
				ent->key);
				sr_hash_insert(sr_cls_exec_file_table, ent);
			}
		}
		sal_set_bit_array(rulenum, &(ent->rules[type]));
	} else { // ANY rules
		sal_set_bit_array(rulenum, &sr_cls_exec_file_any_rules[type]);
	}
	return SR_SUCCESS;
}

// type: NET/FILE/CAN
// exec_inode: inode of executable
// rulenum: index of rule to be added
int sr_cls_exec_inode_del_rule(enum sr_rule_type type, SR_U32 exec_inode, SR_U32 rulenum)
{
	if (likely(exec_inode != INODE_ANY)) {
		struct sr_hash_ent_multy_t *ent= (struct sr_hash_ent_multy_t *)sr_hash_lookup(sr_cls_exec_file_table, exec_inode);
		if (!ent) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to delete exec_file rule %d, inode %d not found",REASON,
			rulenum, exec_inode);
			return SR_ERROR;
		}
		sal_clear_bit_array(rulenum, &(ent->rules[type]));

                if (is_multy_entry_clear(ent)) { 
		    sr_cls_exec_inode_remove(exec_inode);
		}
	} else {
		sal_clear_bit_array(rulenum, &(sr_cls_exec_file_any_rules[type]));
	}
	return SR_SUCCESS;
}

struct sr_hash_table_t * get_cls_exec_file_table(void){
	
	return sr_cls_exec_file_table;
}

bit_array *sr_cls_match_exec_inode(enum sr_rule_type type, SR_U32 exec_inode)
{
        struct sr_hash_ent_multy_t *ent=(struct sr_hash_ent_multy_t *)sr_hash_lookup(sr_cls_exec_file_table, exec_inode);

        if (!ent) {
                return NULL;
        }
        return(&(ent->rules[type]));
}

struct sr_hash_ent_multy_t *sr_cls_exec_inode_find(enum sr_rule_type type, SR_U32 exec_inode)
{
	struct sr_hash_ent_multy_t *ent=(struct sr_hash_ent_multy_t *)sr_hash_lookup(sr_cls_exec_file_table, exec_inode);

	if (!ent) {
		return NULL;
	}
	return ent;
}

int sr_cls_exec_file_init(void)
{
	sr_cls_exec_file_table = sr_hash_new_table(EXEC_FILE_HASH_TABLE_SIZE);
	if (!sr_cls_exec_file_table) {
		sal_kernel_print_err("Failed to allocate hash table!\n");
		return SR_ERROR;
	}
	memset(&sr_cls_exec_file_any_rules, 0, sizeof(bit_array) * SR_RULES_TYPE_MAX);
	sal_kernel_print_info("Successfully initialized file classifier!\n");
	return SR_SUCCESS;
}

void sr_cls_exec_file_uninit(void)
{ 
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (!sr_cls_exec_file_table)
		return;

	for(i = 0; i < EXEC_FILE_HASH_TABLE_SIZE; i++) {
		if (sr_cls_exec_file_table->buckets[i].head != NULL){
			sal_kernel_print_info("hash_index[%d] - DELETEING\n",i);
			curr = sr_cls_exec_file_table->buckets[i].head;				
			while (curr != NULL){
				sal_kernel_print_info("\t\texec file inode : %u\n",curr->key);
				next = curr->next;
				SR_FREE(curr);
				curr= next;
			}
		}
	}

	if(sr_cls_exec_file_table->buckets != NULL){
		sal_kernel_print_info("DELETEING exec_file table->bucket\n");
		SR_FREE(sr_cls_exec_file_table->buckets);
	}
	SR_FREE(sr_cls_exec_file_table);
	sr_cls_exec_file_table = NULL;
	sal_kernel_print_info("[%s]: Successfully removed exec file classifier!\n", MODULE_NAME);
}

void sr_cls_exec_file_empty_table(SR_BOOL is_lock)
{
	memset(&sr_cls_exec_file_any_rules, 0, sizeof(bit_array) * SR_RULES_TYPE_MAX);
	sr_hash_empty_table(sr_cls_exec_file_table, is_lock);
}
