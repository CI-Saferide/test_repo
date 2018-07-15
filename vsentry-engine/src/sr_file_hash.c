#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sr_types.h>
#include <sr_gen_hash.h>
#include <sr_file_hash.h>
#include <sr_sal_common.h>
#include <sal_mem.h>

#define HASH_SIZE 500

static struct sr_gen_hash *file_hash;

typedef struct file_rules_data {
	struct file_rules_data *next;
	SR_U32 rulenum;
	char exec[SR_MAX_PATH_SIZE];
	char user[SR_MAX_PATH_SIZE];
	SR_U16 actions;
	SR_8 file_ops;
} file_rules_data_t; 

typedef struct file_rules_item {
   char file_path[SR_MAX_PATH_SIZE];
   file_rules_data_t *file_rules_list;
} file_rules_item_t;

SR_32 file_comp(void *data_in_hash, void *comp_val)
{
	file_rules_item_t *rules_item = (file_rules_item_t *)data_in_hash;

	if (!data_in_hash || !comp_val)
		return -1;

	return strcmp(rules_item->file_path, (char *)comp_val);
}

void file_free(void *data_in_hash)
{
	file_rules_data_t *ptr, *help;
	file_rules_item_t *rules_item = (file_rules_item_t *)data_in_hash;

	for (ptr = rules_item->file_rules_list; ptr; ) {
		help = ptr->next;
		SR_Free(ptr);
		ptr = help;
	}
}

void file_print(void *data_in_hash)
{
	file_rules_data_t *ptr;
	file_rules_item_t *rules_item = (file_rules_item_t *)data_in_hash;

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=file path:%s",MESSAGE,
		rules_item->file_path);
					
	for (ptr = rules_item->file_rules_list; ptr; ptr = ptr->next) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=rule %d user %s exec %s actions %x ops %x",MESSAGE,
			ptr->rulenum,
			ptr->user,
			ptr->exec,
			ptr->actions,
			ptr->file_ops);
	}
}

static SR_U32 create_key(void *data)
{
	SR_U32 i, len, sum = 0;
	char *name = (char *)data;

	if (!data)
		return 0;
	len = strlen(name);

 	for (i = 0; i < len; i++) 
		sum += name[i];

	return sum;
}

SR_32 sr_file_hash_init(void)
{
	hash_ops_t hash_ops = {};

	hash_ops.create_key = create_key;
	hash_ops.comp = file_comp;
	hash_ops.free = file_free;
	hash_ops.print = file_print;
	if (!(file_hash = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to gen hash table for file",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
} 

void sr_file_hash_deinit(void)
{
	sr_gen_hash_destroy(file_hash);
}

SR_32 sr_file_hash_delete_all(void)
{
	return sr_gen_hash_delete_all(file_hash, 0);
}

static SR_32 update_rule_item(file_rules_item_t *file_rule_item, char *exec, char *user, SR_U32 rulenum, SR_U16 actions, SR_8 file_ops)
{
	file_rules_data_t **iter;

	for (iter = &(file_rule_item->file_rules_list); *iter && (*iter)->rulenum != rulenum; iter = &((*iter)->next));
	/* If rule exists update, otherwise add */
	if (!*iter)  {
		SR_Zalloc(*iter, file_rules_data_t *, sizeof(file_rules_data_t));
		if (!*iter) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to allocate memory for file rule update",REASON);
			return SR_ERROR;
		}
	}
	(*iter)->rulenum = rulenum;
	strncpy((*iter)->exec, exec, SR_MAX_PATH_SIZE);
	strncpy((*iter)->user, user, SR_MAX_PATH_SIZE);
	(*iter)->actions = actions;
	(*iter)->file_ops = file_ops;

	return SR_SUCCESS;
}

SR_32 sr_file_hash_update_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U16 actions, SR_8 file_ops)
{
        file_rules_item_t *file_rule_item;
	SR_32 rc;

	/* If the file exists add the rule to the file. */
        if (!(file_rule_item = sr_gen_hash_get(file_hash, filename, 0))) {
		SR_Zalloc(file_rule_item, file_rules_item_t *, sizeof(file_rules_item_t));
		if (!file_rule_item)
			return SR_ERROR;
		strncpy(file_rule_item->file_path, filename, SR_MAX_PATH_SIZE); 
		update_rule_item(file_rule_item, exec, user, rulenum, actions, file_ops);
		/* Add the rule */
		if ((rc = sr_gen_hash_insert(file_hash, filename, file_rule_item, 0)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to insert rule to file table",REASON);
			return SR_ERROR;
		}
		
	} else
		update_rule_item(file_rule_item, exec, user, rulenum, actions, file_ops);

	return SR_SUCCESS;
}

SR_32 sr_file_hash_exec_for_file(char *filename, SR_U32 (*cb)(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U16 actions, SR_8 file_ops))
{
        file_rules_item_t *file_rule_item;
	file_rules_data_t *iter;
	SR_U32 rc;

        if (!(file_rule_item = sr_gen_hash_get(file_hash, filename, 0)))
		return SR_SUCCESS;
	for (iter = file_rule_item->file_rules_list; iter; iter = iter->next) {
		if ((rc = cb(file_rule_item->file_path, iter->exec, iter->user, iter->rulenum, iter->actions, iter->file_ops)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to exec file cb function",REASON);
			return SR_ERROR;
		}
	}

	return SR_SUCCESS;
}

void sr_file_hash_print(void)
{
	sr_gen_hash_print(file_hash);
}
