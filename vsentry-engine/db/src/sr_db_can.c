#include "sr_db.h"
#include "string.h"
#include "sal_linux.h"
#include "sal_mem.h"
#include "list.h"
#include "can_rule.h"

static list_t can_rules_list;

static bool can_rule_search_cb(void *candidate, void *data)
{
	can_rule_t *search_ptr = (can_rule_t *)data;
	can_rule_t *candidate_ptr = (can_rule_t *)candidate;

	if ((search_ptr->rulenum == candidate_ptr->rulenum) &&
		(search_ptr->tuple.id == candidate_ptr->tuple.id))
		return SR_TRUE;

	return SR_FALSE;
}

static int can_rule_compare_cb(void *a, void *b)
{
	can_rule_t *can_rule_a = (can_rule_t *)a;
	can_rule_t *can_rule_b = (can_rule_t *)b;

	if (can_rule_a->rulenum > can_rule_b->rulenum)
		return NODE_CMP_BIGGER;
	if (can_rule_a->rulenum < can_rule_b->rulenum)
		return NODE_CMP_SMALLER;
	if (can_rule_a->tuple.id > can_rule_b->tuple.id)
		return NODE_CMP_BIGGER;
	if (can_rule_a->tuple.id < can_rule_b->tuple.id)
		return NODE_CMP_BIGGER;
	
        return NODE_CMP_EQUAL;
}

static void can_rule_print_cb(void *data)
{
	can_rule_t *can_rule = (can_rule_t *)data;

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=%d %s=%d %s=%x %s=%d %s=%s %s=%s", 
		RULE_NUM_KEY,can_rule->rulenum,
		"TupleID",can_rule->tuple.id,
		CAN_MSG_ID,can_rule->tuple.msg_id,
		DEVICE_DIRECTION,can_rule->tuple.direction,
		DEVICE_UID,can_rule->tuple.user,
		DEVICE_FILE_PATH,can_rule->tuple.program);
}

SR_32 sr_db_can_rule_init(void)
{
	list_init(&can_rules_list, can_rule_search_cb, can_rule_print_cb, can_rule_compare_cb);

	return SR_SUCCESS;
}

SR_32 sr_db_can_rule_add(can_rule_t *can_rule)
{
	can_rule_t *new_item;

	SR_Zalloc(new_item, can_rule_t *, sizeof(can_rule_t));
	if (!new_item)
		return SR_ERROR;
	*new_item = *can_rule;
	if (!list_append(&can_rules_list, new_item)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=cal rule add :list_append failed",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

can_rule_t *sr_db_can_rule_get(can_rule_t *can_rule)
{
	node_t*  node;

	if (!(node = list_search_node(&can_rules_list, can_rule)))
		return NULL;
	return node ? (can_rule_t *)node->data : NULL;
}

SR_32 sr_db_can_rule_delete(can_rule_t *can_rule)
{
	node_t *node;

	if (!(node = list_search_node(&can_rules_list, can_rule)))
		return SR_NOT_FOUND;
	if (!list_remove_node(&can_rules_list, node))
		return SR_ERROR;
	return SR_SUCCESS;
}

SR_32 sr_db_can_rule_deinit(void)
{
	node_t *ptr = can_rules_list.head;

	while (ptr) {
        	if (ptr->data)
            		free(ptr->data);
        	list_remove_node(&can_rules_list, ptr);
		ptr = can_rules_list.head;
	}

	return SR_SUCCESS;
}

