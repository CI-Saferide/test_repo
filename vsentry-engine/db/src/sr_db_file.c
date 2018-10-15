#include "sr_db.h"
#include "string.h"
#include "sal_linux.h"
#include "sal_mem.h"
#include "list.h"
#include "file_rule.h"
#include "sr_cls_wl_common.h"
#include "sr_engine_cli.h"

static list_t file_rules_list;

static void dump_file_rule(void *data, void *param)
{
	int fd = (int)(long)param, n, len;
	char buf[10000];
	SR_BOOL is_wl;
	file_rule_t *file_rule = (file_rule_t *)data;

	is_wl = (file_rule->rulenum >= SR_FILE_WL_START_RULE_NO);
	sprintf(buf, "file%s,%d,%d,%s,%s,%s,%s,%s%c",
		is_wl ? "_wl" : "", file_rule->rulenum, file_rule->tuple.id, file_rule->action_name,
		file_rule->tuple.filename, file_rule->tuple.permission, file_rule->tuple.user, file_rule->tuple.program, SR_CLI_END_OF_ENTITY);
	len = strlen(buf);
	if ((n = write(fd, buf, len)) < len) {
		printf("Write to CLI file failed \n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=write to cli for file failed.",REASON);
	}
}

SR_32 file_rule_dump_rules(int fd)
{
	list_exec_for_each(&file_rules_list, dump_file_rule, (void *)(long)fd);

	return SR_SUCCESS;
}

static bool file_rule_search_cb(void *candidate, void *data)
{
	file_rule_t *search_ptr = (file_rule_t *)data;
	file_rule_t *candidate_ptr = (file_rule_t *)candidate;

	if ((search_ptr->rulenum == candidate_ptr->rulenum) &&
		(search_ptr->tuple.id == candidate_ptr->tuple.id))
		return SR_TRUE;

	return SR_FALSE;
}

static int file_rule_compare_cb(void *a, void *b)
{
	file_rule_t *file_rule_a = (file_rule_t *)a;
	file_rule_t *file_rule_b = (file_rule_t *)b;

	if (file_rule_a->rulenum > file_rule_b->rulenum)
		return NODE_CMP_BIGGER;
	if (file_rule_a->rulenum < file_rule_b->rulenum)
		return NODE_CMP_SMALLER;
	if (file_rule_a->tuple.id > file_rule_b->tuple.id)
		return NODE_CMP_BIGGER;
	if (file_rule_a->tuple.id < file_rule_b->tuple.id)
		return NODE_CMP_BIGGER;
	
        return NODE_CMP_EQUAL;
}

static void file_rule_print_cb(void *data)
{
	file_rule_t *file_rule = (file_rule_t *)data;
	

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW, 
		"%s=%d %s=%d %s=%s %s=%s %s=%s %s=%s",
		RULE_NUM_KEY,file_rule->rulenum,
		"TupleID",file_rule->tuple.id,
		INODE_NUMBER,file_rule->tuple.filename,
		FILE_PERMISSION,file_rule->tuple.permission,
		DEVICE_UID,file_rule->tuple.user,
		DEVICE_FILE_PATH,file_rule->tuple.program);
}

SR_32 sr_db_file_rule_init(void)
{
	list_init(&file_rules_list, file_rule_search_cb, file_rule_print_cb, file_rule_compare_cb);

	return SR_SUCCESS;
}

SR_32 sr_db_file_rule_add(file_rule_t *file_rule)
{
	file_rule_t *new_item;

	SR_Zalloc(new_item, file_rule_t *, sizeof(file_rule_t));
	if (!new_item)
		return SR_ERROR;
	*new_item = *file_rule;
	if (!list_append(&file_rules_list, new_item)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=file rule add list_append failed",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

file_rule_t *sr_db_file_rule_get(file_rule_t *file_rule)
{
	node_t*  node;

	if (!(node = list_search_node(&file_rules_list, file_rule)))
		return NULL;
	return node ? (file_rule_t *)node->data : NULL;
}

SR_32 sr_db_file_rule_delete(file_rule_t *file_rule)
{
	node_t *node;
	void *data;

	if (!(node = list_search_node(&file_rules_list, file_rule)))
		return SR_NOT_FOUND;
	if (!(data = list_remove_node(&file_rules_list, node)))
		return SR_ERROR;
	SR_Free(data);

	return SR_SUCCESS;
}

SR_32 sr_db_file_rule_deinit(void)
{
	node_t *ptr = file_rules_list.head;

	while (ptr) {
        	if (ptr->data)
            		free(ptr->data);
        	list_remove_node(&file_rules_list, ptr);
		ptr = file_rules_list.head;
	}

	return SR_SUCCESS;
}

