#include "dispatcher.h"
#include "sal_linux.h"
#include "sr_hash.h"
#include "sal_bitops.h"
#include "sr_cls_process.h"
#include "sr_cls_exec_file.h"
#include "sr_cls_exec_file.h"

struct sr_hash_table_t *sr_cls_process_table;

int sr_cls_process_add(SR_32 pid)
{
	struct sr_hash_ent_process_t *ent;

	if (sr_hash_lookup(sr_cls_process_table, pid)) {
	    return SR_SUCCESS;
        }
        ent = SR_ZALLOC(sizeof(*ent));
	if (!ent) {
	    sal_kernel_print_alert("Error: Failed to allocate memory\n");
	    return SR_ERROR;
        }

        ent->key = pid;
        ent->exec_inode = sal_get_exec_inode(pid); 
	sr_hash_insert(sr_cls_process_table, ent);

	return SR_SUCCESS;
}

int sr_cls_process_del(SR_32 pid)
{
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

#ifdef UNIT_TEST
void sr_cls_process_ut(void)
{
	int st;

	if ((st = sr_cls_process_add(3084)) != SR_SUCCESS) {
 	    printk("*** Error add pid!!\n");
	    return;
	}
        printk("The inode :%d \n", sr_cls_process_find_inode(3084));
	if ((st = sr_cls_process_add(3084)) != SR_SUCCESS) {
 	    printk("*** Error add pid!!\n");
	    return;
	}
        printk("The inode :%d \n", sr_cls_process_find_inode(3084));

}
#endif /* UNIT_TEST */

int sr_cls_process_init(void)
{
	sr_cls_process_table = sr_hash_new_table(8192);
	if (!sr_cls_process_table) {
		sal_kernel_print_alert("Failed to allocate hash table!\n");
		return SR_ERROR;
	}
	sal_kernel_print_alert("Successfully initialized process table!\n");
	return SR_SUCCESS;
}

void sr_cls_process_uninit(void)
{
	if (!sr_cls_process_table)
	    return;
	SR_FREE(sr_cls_process_table->buckets);
	SR_FREE(sr_cls_process_table);
	sr_cls_process_table = NULL;
	
}
