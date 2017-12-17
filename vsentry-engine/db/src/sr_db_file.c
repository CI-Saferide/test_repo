#include "sr_db.h"
#include "string.h"
#include "sal_linux.h"
#include "sal_mem.h"
#include "list.h"
#include "file_rule.h"

static list_t file_rules_list;

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

	sal_printf("file_rule#%d tuple:%d name:%s perm:%s user:%s program:%s \n",
		file_rule->rulenum, file_rule->tuple.id, file_rule->tuple.filename, file_rule->tuple.permission, file_rule->tuple.user, file_rule->tuple.program);
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
		sal_printf("%s list_append failed !!!\n", __FUNCTION__);
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

	if (!(node = list_search_node(&file_rules_list, file_rule)))
		return SR_NOT_FOUND;
	if (!list_remove_node(&file_rules_list, node))
		return SR_ERROR;
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

