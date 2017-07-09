#include "sal_linux.h"
#include "sr_cls_file.h"
#include "sr_cls_file_common.h"
#include "sr_hash.h"
#include "sal_bitops.h"

struct sr_hash_table_t *sr_cls_file_table;

int sr_cls_inode_add_rule(SR_U32 inode, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);
	if (!ent) {
		ent = SR_ZALLOC(sizeof(*ent));
		if (!ent) {
			sal_kernel_print_alert("Error: Failed to allocate memory\n");
			return SR_ERROR;
		} else {
			ent->key = inode;
			sr_hash_insert(sr_cls_file_table, ent);
		}
	}
	sal_set_bit_array(rulenum, &ent->rules);
	return SR_SUCCESS;
}

// filename: path of file/dir to add rule to
// rulenum: index of rule to be added
// treetop: 1 for the first call, 0 for recursive calls further down.
int sr_cls_inode_del_rule(SR_U32 inode, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);
	if (!ent) {
		sal_kernel_print_alert("Error: inode rule not found\n");
		return SR_ERROR;
	}
	sal_clear_bit_array(rulenum, &ent->rules);

	if (!ent->rules.summary) {
		sr_cls_inode_remove(inode);
	}
	return SR_SUCCESS;
}

// This function should be invoked upon file creation. 
// It will need to check if parent directory has rules associated with it and inherit accordingly
int sr_cls_inode_inherit(SR_U32 from, SR_U32 to)
{ 
	struct sr_hash_ent_t *parent, *fileent;

	parent=sr_hash_lookup(sr_cls_file_table, from);
	if (parent) {
		fileent=sr_hash_lookup(sr_cls_file_table, to);
		if (!fileent) {
			fileent = SR_ZALLOC(sizeof(*fileent));
			if (!fileent) {
				sal_kernel_print_alert("Error: Failed to allocate memory\n");
				return SR_ERROR;
			} else {
				fileent->key = to;
			}
		}
		sal_or_self_op_arrays(&fileent->rules, &parent->rules);
	}
	return SR_SUCCESS;
}
// This function should be invoked upon file deletion. 
// It will need to check if there's an entry and remove it
void sr_cls_inode_remove(SR_U32 inode)
{ 

	sr_hash_delete(sr_cls_file_table, inode);
}

void sr_cls_print_rules(SR_U32 inode)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);
	bit_array rules;
	SR_16 rule;

	memset(&rules, 0, sizeof(rules));
	sal_kernel_print_alert("sr_cls_print_rules called for inode %d\n", (int)inode);
	if (!ent) {
		sal_kernel_print_alert("Error: inode rule not found\n");
		return;
	}
	sal_or_self_op_arrays(&rules, &ent->rules);
	while ((rule = sal_ffs_and_clear_array (&rules)) != -1) {
		sal_kernel_print_alert("Rule #%d\n", rule);
	}
	
}

SR_8 sr_cls_msg_dispatch(struct sr_cls_msg *msg)
{
	switch (msg->msg_type) {
		case SR_CLS_INODE_INHERIT:
			//sal_kernel_print_alert("Inherit from %x to %x\n", msg->inode1, msg->inode2);
			return sr_cls_inode_inherit(msg->inode1, msg->inode2);
			break;
		case SR_CLS_INODE_DEL_RULE:
			//sal_kernel_print_alert("delete rule %d from %x\n", msg->rulenum, msg->inode1);
			return sr_cls_inode_del_rule(msg->inode1, msg->rulenum);
			break;
		case SR_CLS_INODE_ADD_RULE:
			//sal_kernel_print_alert("add rule %d to %x\n", msg->rulenum, msg->inode1);
			return sr_cls_inode_add_rule(msg->inode1, msg->rulenum);
			break;
		case SR_CLS_INODE_REMOVE:
			//sal_kernel_print_alert("remove inode %x\n", msg->inode1);
			sr_cls_inode_remove(msg->inode1);
			break;
		default:
			break;
	}
	return SR_SUCCESS;
}

void sr_cls_ut(void)
{
	sr_cls_inode_add_rule(1000, 5);
	sr_hash_print_table(sr_cls_file_table);
	sr_cls_inode_add_rule(1000, 555);
	sr_hash_print_table(sr_cls_file_table);
	sr_cls_inode_add_rule(2000, 2000);
	sr_hash_print_table(sr_cls_file_table);

	sr_cls_inode_add_rule(9192, 7);
	//sr_cls_print_rules(1000);
	sr_cls_print_rules(2000);
	//sr_cls_print_rules(9192);
	sr_cls_print_rules(1000);
	sr_cls_inode_del_rule(1000, 5);
	sr_cls_print_rules(1000);
	sr_cls_inode_del_rule(1000, 555);
	sr_cls_print_rules(1000);
	sr_cls_inode_remove(2000);
	//sr_cls_print_rules(2000);
	sr_cls_inode_del_rule(9192, 7);
	sr_hash_print_table(sr_cls_file_table);
	sal_kernel_print_alert("testing bucket collision\n");
	sr_cls_inode_add_rule(10, 7);
	sr_cls_inode_add_rule(8202, 17);
	sr_cls_inode_add_rule(16394, 27);
	sr_cls_inode_add_rule(24586, 37);
	sr_cls_inode_add_rule(32778, 47);
	sr_cls_print_rules(10);
	sr_cls_print_rules(8202);
	sr_cls_print_rules(16394);
	sr_cls_print_rules(24586);
	sr_cls_print_rules(32778);
	sr_cls_inode_del_rule(16394, 27);
	sr_cls_print_rules(10);
	sr_cls_print_rules(8202);
	sr_cls_print_rules(16394);
	sr_cls_print_rules(24586);
	sr_cls_print_rules(32778);
	sr_cls_inode_remove(8202);
	sr_cls_print_rules(10);
	sr_cls_print_rules(8202);
	sr_cls_print_rules(16394);
	sr_cls_print_rules(24586);
	sr_cls_print_rules(32778);
	sr_cls_inode_remove(10);
	sr_cls_inode_remove(24586);
	sr_cls_inode_remove(32778);


}

int sr_cls_fs_init(void)
{
	sr_cls_file_table = sr_hash_new_table(8192);
	if (!sr_cls_file_table) {
		sal_kernel_print_alert("Failed to allocate hash table!\n");
		return SR_ERROR;
	}
	sal_kernel_print_alert("Successfully initialized file classifier!\n");
	//sr_cls_ut();
	sal_kernel_print_alert("Finished running UTs\n");
	return SR_SUCCESS;
}

void sr_cls_fs_uninit(void)
{
	if (!sr_cls_file_table)
		return;
	//sr_hash_free_table(sr_cls_file_table);
	SR_FREE(sr_cls_file_table->buckets);
	SR_FREE(sr_cls_file_table);
	sr_cls_file_table = NULL;
	
}
