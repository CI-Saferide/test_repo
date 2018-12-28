#include "sr_db.h"
#include "string.h"
#include "sal_linux.h"
#include "sal_mem.h"
#include "list.h"
#include "can_rule.h"
#include "sr_cls_wl_common.h"
#include "sr_engine_cli.h"

static list_t can_rules_list;

typedef struct look_for_s {
	SR_U16 rulenum;
	SR_32  tupleid;
	char   name[1024];
} look_for_t;

static void dump_can_rule(void *data, void *param)
{
        int fd = (int)(long)param, n, len;
	char buf[MAX_BUF_SIZE];
	SR_BOOL is_wl;

        can_rule_t *can_rule = (can_rule_t *)data;

	is_wl = (can_rule->rulenum >= SR_CAN_WL_START_RULE_NO);
        sprintf(buf, "can%s,%d,%d,%s,%d,%d,%s,%s,%s%c",
                is_wl ? "_wl" : "", can_rule->rulenum, can_rule->tuple.id, can_rule->action_name,
                can_rule->tuple.msg_id, can_rule->tuple.direction, can_rule->tuple.interface,
		can_rule->tuple.user, can_rule->tuple.program, SR_CLI_END_OF_ENTITY); 
        len = strlen(buf);
        if ((n = write(fd, buf, len)) < len) {
                perror("write");
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=write to cli for file failed.",REASON);
        }
}

SR_32 can_rule_dump_rules(int fd)
{
        list_exec_for_each(&can_rules_list, dump_can_rule, (void *)(long)fd);

        return SR_SUCCESS;
}

static SR_BOOL is_found;

static void looks_for_exec(void *data, void *param)
{
	can_rule_t *can_rule = (can_rule_t *)data;

	look_for_t *look_for = (look_for_t *)param;

	if (!strcmp(can_rule->tuple.program, look_for->name) && can_rule->rulenum == look_for->rulenum && can_rule->tuple.id != look_for->tupleid)
		is_found = SR_TRUE;

#ifdef DEBUG
	printf(">>>>>>>>>>>> in looks_for_Exec ruile:%d t:%d exec:%s: lookfor : rule:%d t:%d exec:%s: \n", 
		can_rule->rulenum, can_rule->tuple.id, can_rule->tuple.program,
		look_for->rulenum, look_for->tupleid, look_for->name);
#endif
}

static void looks_for_user(void *data, void *param)
{
	can_rule_t *can_rule = (can_rule_t *)data;

	look_for_t *look_for = (look_for_t *)param;

	if (!strcmp(can_rule->tuple.user, look_for->name) && can_rule->rulenum == look_for->rulenum && can_rule->tuple.id != look_for->tupleid)
		is_found = SR_TRUE;

#ifdef DEBUG
	printf(">>>>>>>>>>>> in looks_for_Exec ruile:%d t:%d exec:%s: lookfor: rule:%d t:%d user:%s: \n", 
		can_rule->rulenum, can_rule->tuple.id, can_rule->tuple.user,
		look_for->rulenum, look_for->tupleid, look_for->name);
#endif
}

SR_BOOL can_rule_tuple_exist_for_field(SR_U16 rulenum, SR_U32 tupleid, SR_BOOL is_program, char *value)
{
	look_for_t data;

	data.rulenum = rulenum;
	data.tupleid = tupleid;
	strncpy(data.name, value, 1024);

	is_found = SR_FALSE;
	
	list_exec_for_each(&can_rules_list, is_program ? looks_for_exec : looks_for_user, (void *)&data);

	return is_found;
}

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

