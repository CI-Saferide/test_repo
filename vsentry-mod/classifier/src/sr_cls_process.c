#include "dispatcher.h"
#include "sal_linux.h"
#include "sr_hash.h"
#include "sal_bitops.h"
#include "sr_cls_process.h"
#include "sr_cls_exec_file.h"
#include "sr_cls_exec_file.h"

struct sr_hash_table_t *sr_cls_process_table;

#define PROCESS_HASH_TABLE_SIZE 8192

int sr_cls_process_add(SR_32 pid)
{
	struct sr_hash_ent_process_t *ent;

	if (!sr_cls_process_table)
		return SR_SUCCESS;

	if (sr_hash_lookup(sr_cls_process_table, pid)) {
	    return SR_SUCCESS;
        }
        ent = SR_ZALLOC(sizeof(*ent));
	if (!ent) {
	    CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add process %d, memory allocation fail",REASON,
			pid);
	    return SR_ERROR;
        }

        ent->key = pid;
        ent->exec_inode = sal_get_exec_inode(pid); 
	sr_hash_insert(sr_cls_process_table, ent);

	return SR_SUCCESS;
}

int sr_cls_process_del(SR_32 pid)
{
	if (sr_cls_process_table)
		sr_hash_delete(sr_cls_process_table, pid);

	return SR_SUCCESS;
}

// Returns inode of executable
SR_U32 sr_cls_process_find_inode(SR_32 pid)
{
	struct sr_hash_ent_process_t *ent=(struct sr_hash_ent_process_t *)sr_hash_lookup(sr_cls_process_table, pid);

	if (!ent)
 	    return 0;
	
	return ent->exec_inode;
}

bit_array *sr_cls_process_match(enum sr_rule_type type, SR_32 pid)
{
        SR_U32 exec_inode;
        struct sr_hash_ent_multy_t *ent;

	if (!(exec_inode = sr_cls_process_find_inode(pid)))
	   return NULL;
        ent = (struct sr_hash_ent_multy_t *)sr_cls_exec_inode_find(type, exec_inode);
	if (!ent)
	    return NULL;
	return &(ent->rules[type]);
}

int sr_cls_process_init(void)
{
	sr_cls_process_table = sr_hash_new_table(PROCESS_HASH_TABLE_SIZE);
	if (!sr_cls_process_table) {
		sal_kernel_print_err("failed to allocate hash table for cls_process\n");
		return SR_ERROR;
	}
	sal_kernel_print_info("successfully initialized process table\n");
	return SR_SUCCESS;
}

void sr_cls_process_uninit(void)
{ 
	SR_32 i;
	struct sr_hash_ent_t *curr, *next;
	
	if (!sr_cls_process_table)
		return;

	for(i = 0; i < PROCESS_HASH_TABLE_SIZE; i++) {
		if (sr_cls_process_table->buckets[i].head != NULL){
			curr = sr_cls_process_table->buckets[i].head;				
			while (curr != NULL){
#ifdef DEBUG
				sal_kernel_print_info("\t\tDelete process : %u\n",curr->key);
#endif /* DEBUG */
				next = curr->next;
				SR_FREE(curr);
				curr= next;
			}
		}
	}

	if(sr_cls_process_table->buckets != NULL){
		sal_kernel_print_info("deleting process table bucket\n");
		SR_FREE(sr_cls_process_table->buckets);
	}
	SR_FREE(sr_cls_process_table);
	sr_cls_process_table = NULL;
	sal_kernel_print_info("[%s]: successfully removed process classifier\n", MODULE_NAME);
}
