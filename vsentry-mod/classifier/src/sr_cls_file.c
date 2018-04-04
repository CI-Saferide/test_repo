#include "sal_linux.h"
#include "sr_cls_file.h"
#include "sr_cls_exec_file.h"
#include "sr_cls_file_common.h"
#include "sr_cls_filter_path_common.h"
#include "sr_hash.h"
#include "sal_bitops.h"
#include "sr_classifier.h"

struct sr_hash_table_t *sr_cls_file_table;
bit_array sr_cls_file_any_rules;

struct filter_path {
  SR_U8 *path;
  struct filter_path *next;
};

static struct filter_path *filter_path_list;

#if 0 /* no useage for this function, left for debug purposes */
static void sr_cls_filter_path_print(void)
{
	struct filter_path *iter;

	for (iter = filter_path_list; iter; iter = iter->next) {
		sal_kernel_print_info("**** path :%s \n", iter->path);
        }
}
#endif

static SR_32 sr_cls_filter_path_add(SR_U8 *path)
{
	struct filter_path *new_item;

	if (!(new_item = SR_ZALLOC(sizeof(struct filter_path))))
		return SR_ERROR;
	if (!(new_item->path = SR_ZALLOC(strlen(path) + 1))) {
		SR_FREE(new_item);
		return SR_ERROR;
	}
	strcpy(new_item->path, path);

	new_item->next = filter_path_list;
	filter_path_list = new_item;

	return SR_SUCCESS;
}

static SR_32 sr_cls_filter_path_del(SR_U8 *path)
{
	struct filter_path **iter, *help;

	for (iter = &filter_path_list; *iter && strcmp((*iter)->path, path); iter = &((*iter)->next));
	if (!*iter) {
		CEF_log_event(SR_CEF_CID_FILE, "error", SEVERITY_HIGH,
			"reason=filter_path_del path:%s not found",
			path);
		return SR_ERROR;
	}

	SR_FREE((*iter)->path);
	help = *iter;
	*iter = (*iter)->next;
 	SR_FREE(help);

	return SR_SUCCESS;
}

SR_BOOL sr_cls_filter_path_is_match(char *path)
{
	SR_BOOL is_match = SR_FALSE;
	struct filter_path *iter;
	int prefix_len, path_len;

	if (!path)
		return is_match;

	path_len = strlen(path);
	for (iter = filter_path_list; iter ; iter = iter->next) {
		prefix_len = strlen(iter->path);
		if (path_len >= prefix_len && !memcmp(path, iter->path, prefix_len)) {
			is_match = SR_TRUE;
			break;
		}
	}

	return is_match;
}

static void sr_cls_filter_path_deinit(void)
{
	struct filter_path *iter, *help;

	for (iter = filter_path_list; iter ;) {
		help = iter->next;
		SR_FREE(iter->path);
		SR_FREE(iter);
		iter = help;
	}
	filter_path_list = NULL;
}

struct sr_hash_table_t * get_cls_file_table(void){
	
	return sr_cls_file_table;
}

bit_array *sr_cls_file_any(void)
{
        return &sr_cls_file_any_rules;
}
int sr_cls_inode_add_rule(SR_U32 inode, SR_U32 rulenum)
{
	if (likely(inode != INODE_ANY)) {
		struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);
		if (!ent) {
			ent = SR_ZALLOC(sizeof(*ent));
			if (!ent) {
				CEF_log_event(SR_CEF_CID_FILE, "error", SEVERITY_HIGH,
								"reason=failed to allocate memory");
				return SR_ERROR;
			} else {
				ent->key = inode;
				sr_hash_insert(sr_cls_file_table, ent);
			}
		}
		sal_set_bit_array(rulenum, &ent->rules);
	} else { // ANY rules
		sal_set_bit_array(rulenum, &sr_cls_file_any_rules);
	}
	return SR_SUCCESS;
}

// filename: path of file/dir to add rule to
// rulenum: index of rule to be added
// treetop: 1 for the first call, 0 for recursive calls further down.
int sr_cls_inode_del_rule(SR_U32 inode, SR_U32 rulenum)
{
	if (likely(inode != INODE_ANY)) {
		struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);
		if (!ent) {
			CEF_log_event(SR_CEF_CID_FILE, "error", SEVERITY_HIGH,
				"reason=failed to del rule %d, inode rule not found",
				rulenum);
			return SR_ERROR;
		}
		sal_clear_bit_array(rulenum, &ent->rules);

		if (!ent->rules.summary) {
			sr_cls_inode_remove(inode);
		}
	} else {
		sal_clear_bit_array(rulenum, &sr_cls_file_any_rules);
	}
	return SR_SUCCESS;
}

// This function should be invoked upon file creation. 
// It will need to check if parent directory has rules associated with it and inherit accordingly
int sr_cls_inode_inherit(SR_U32 from, SR_U32 to)
{ 
	struct sr_hash_ent_t *parent, *fileent;
	int rc;

	parent=sr_hash_lookup(sr_cls_file_table, from);
	if (parent) {
		fileent=sr_hash_lookup(sr_cls_file_table, to);
		if (!fileent) {
			fileent = SR_ZALLOC(sizeof(*fileent));
			if (!fileent) {
				CEF_log_event(SR_CEF_CID_FILE, "error", SEVERITY_HIGH,
								"reason=failed to inherit inode, allocate memory failed");
				return SR_ERROR;
			} else {
				fileent->key = to;
			}
			if ((rc = sr_hash_insert(sr_cls_file_table, fileent)) != SR_SUCCESS) {
				SR_FREE(fileent);
				CEF_log_event(SR_CEF_CID_FILE, "error", SEVERITY_HIGH,
								"reason=failed to insert entry to file table");
				return rc;
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

bit_array *sr_cls_file_find(SR_U32 inode)
{
	struct sr_hash_ent_t *ent=sr_hash_lookup(sr_cls_file_table, inode);

	if (!ent) {
		return NULL;
	}
	return (&ent->rules);
}

SR_8 sr_cls_file_msg_dispatch(struct sr_cls_file_msg *msg)
{
	int st;

	switch (msg->msg_type) {
		case SR_CLS_INODE_INHERIT:
			//sal_kernel_print_alert("Inherit from %x to %x\n", msg->inode1, msg->inode2);
			return sr_cls_inode_inherit(msg->inode1, msg->inode2);
			break;
		case SR_CLS_INODE_DEL_RULE:
			CEF_log_debug(SR_CEF_CID_FILE, "info", SEVERITY_LOW,
				"msg=delete file rule %d from %x",
				msg->rulenum, msg->inode1);
			if ((st = sr_cls_inode_del_rule(msg->inode1, msg->rulenum)) != SR_SUCCESS)
			    return st;
			if ((st = sr_cls_exec_inode_del_rule(SR_FILE_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
			    return st;
			return sr_cls_uid_del_rule(SR_FILE_RULES, msg->uid, msg->rulenum);
			break;
		case SR_CLS_INODE_ADD_RULE:
			CEF_log_debug(SR_CEF_CID_FILE, "info", SEVERITY_LOW,
				"add file rule %d to %x",
				msg->rulenum, msg->inode1);
			if ((st = sr_cls_inode_add_rule(msg->inode1, msg->rulenum)) != SR_SUCCESS)
			    return st;
			if ((st = sr_cls_exec_inode_add_rule(SR_FILE_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
			    return st;
			return sr_cls_uid_add_rule(SR_FILE_RULES, msg->uid, msg->rulenum);
			break;
		case SR_CLS_INODE_REMOVE:
			CEF_log_debug(SR_CEF_CID_FILE, "info", SEVERITY_LOW,
				"remove inode %x",
				msg->inode1);
			sr_cls_inode_remove(msg->inode1);
			break;
		default:
			break;
	}
	return SR_SUCCESS;
}

SR_32 sr_cls_file_filter_path_msg_dispatch(struct sr_cls_filter_path_msg *msg)
{
	switch (msg->msg_type) {
		case SR_CLS_FILTER_PATH_ADD:
			return sr_cls_filter_path_add(msg->path);
			break;
		case SR_CLS_FILTER_PATH_REMOVE:
			return sr_cls_filter_path_del(msg->path);
			break;
		default:
			break;
	}
	return SR_SUCCESS;
}

void sr_cls_fs_empty_table(SR_BOOL is_lock)
{
	memset(&sr_cls_file_any_rules, 0, sizeof(bit_array));
	sr_hash_empty_table(sr_cls_file_table, is_lock);
}


int sr_cls_fs_init(void)
{
	sr_cls_file_table = sr_hash_new_table(8192);
	if (!sr_cls_file_table) {
		sal_kernel_print_err("Failed to allocate hash table!\n");
		return SR_ERROR;
	}
	memset(&sr_cls_file_any_rules, 0, sizeof(bit_array));
	sal_kernel_print_info("Successfully initialized file classifier!\n");
	return SR_SUCCESS;
}

void sr_cls_fs_uninit(void)
{
	if (!sr_cls_file_table)
		return;
	//sr_hash_free_table(sr_cls_file_table);
	sr_cls_filter_path_deinit();
	SR_FREE(sr_cls_file_table->buckets);
	SR_FREE(sr_cls_file_table);
	sr_cls_file_table = NULL;
	
}
