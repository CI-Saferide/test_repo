#include "sal_linux.h"
#include "sr_cls_file.h"
#include "sr_hash.h"

struct sr_hash_table_t *sr_cls_file_table;

int sr_cls_inode_add_rule(SR_U32 inode, SR_U32 rulenum)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);
	if (!ent) {
		ent = SR_ALLOC(sizeof(*ent));
		if (!ent) {
			sal_kernel_print_alert("Error: Failed to allocate memory\n");
			return SR_ERROR;
		} else {
			ent->key = inode;
		}
	}
	ent->pad[0] = (SR_U8)rulenum; // TODO: add bitops here
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
	ent->pad[0] = (SR_U8)rulenum; // TODO: add bitops here - mask out the bits
	// TODO: if last rule - delete entry
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
			fileent = SR_ALLOC(sizeof(*fileent));
			if (!fileent) {
				sal_kernel_print_alert("Error: Failed to allocate memory\n");
				return SR_ERROR;
			} else {
				fileent->key = to;
			}
		}
		fileent->pad[0] = parent->pad[0]; // TODO: add bitops here
	}
	return SR_SUCCESS;
}
// This function should be invoked upon file deletion. 
// It will need to check if there's an entry and remove it
void sr_cls_inode_remove(SR_U32 inode)
{ 
	struct sr_hash_ent_t *fileent;

	fileent=sr_hash_lookup(sr_cls_file_table, inode);
	if (!fileent) {
		return;
	}
	fileent->pad[0] = 10; // TODO: add bitops here
}

int sr_cls_init(void)
{
	sr_cls_file_table = sr_hash_new_table(8192);
	if (!sr_cls_file_table) {
		sal_kernel_print_alert("Failed to allocate hash table!\n");
		return SR_ERROR;
	}
	sal_kernel_print_alert("Successfully initialized file classifier!\n");
	return SR_SUCCESS;
}
