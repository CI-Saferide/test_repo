#include "sr_db.h"
#include "string.h"
#include "sal_linux.h"
#include "list.h"
#include "action.h"
#include "db_tools.h"

typedef struct {
	SR_BOOL is_populated;
	action_t action;
} action_db_t;

static action_db_t db_actions[DB_MAX_NUM_OF_ACTIONS];

SR_32 sr_db_action_init(void)
{
	SR_U32 i;

	for (i = 0; i < DB_MAX_NUM_OF_ACTIONS; i++)
		db_actions[i].is_populated = SR_FALSE;	

	return SR_SUCCESS;
}

SR_32 sr_db_init(void)
{
	sr_db_action_init();
	sr_db_ip_rule_init();
	sr_db_file_rule_init();
	sr_db_can_rule_init();

	return SR_SUCCESS;
}

void sr_db_deinit(void)
{
	sr_db_can_rule_deinit();
	sr_db_file_rule_deinit();
	sr_db_ip_rule_deinit();
}

SR_32 sr_db_action_update_action(action_t *action)
{
	SR_U32 i;

	/* Look for the action */
	for (i = 0; i < DB_MAX_NUM_OF_ACTIONS; i++) {
		if (db_actions[i].is_populated && !strncmp(db_actions[i].action.action_name, action->action_name, ACTION_STR_SIZE)) {
			db_actions[i].action = *action;
			return SR_SUCCESS;
		}
	}

	/* Add new action */
	for (i = 0; i < DB_MAX_NUM_OF_ACTIONS && db_actions[i].is_populated; i++);
	if (i == DB_MAX_NUM_OF_ACTIONS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
			"%s=max number of action have reached.",REASON);
		return SR_ERROR;
	}
	db_actions[i].action = *action;
	db_actions[i].is_populated = SR_TRUE;

	return SR_SUCCESS;
}

SR_32 sr_db_action_delete_action(action_t *action)
{
	SR_U32 i;

	/* Look for the action */
	for (i = 0; i < DB_MAX_NUM_OF_ACTIONS; i++) {
		if (db_actions[i].is_populated && !strncmp(db_actions[i].action.action_name, action->action_name, ACTION_STR_SIZE)) {
			db_actions[i].is_populated = SR_FALSE;
			return SR_SUCCESS;
		}
	}

	return SR_NOT_FOUND;
}

action_t *sr_db_action_get_action(char *action_name)
{
	SR_U32 i;

	for (i = 0; i < DB_MAX_NUM_OF_ACTIONS; i++) {
		if (db_actions[i].is_populated && !strncmp(db_actions[i].action.action_name, action_name, ACTION_STR_SIZE)) {
			return &db_actions[i].action;
		}
	}

	return NULL;
}

SR_32 action_dump(int fd)
{
	SR_U32 i, len;
        char buf[10000];

	for (i = 0; i < DB_MAX_NUM_OF_ACTIONS; i++) {
		if (!db_actions[i].is_populated)
			continue;
        	sprintf(buf, "action,%s,%s,%s#", db_actions[i].action.action_name, get_action_string(db_actions[i].action.action), 
			get_action_log_facility_string(db_actions[i].action.log_facility));
		len = strlen(buf);
		if (write(fd, buf, len) < len) {
			printf("Write to cli failed !!\n");
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=write to cli for file failed.",REASON);
		}
	}

	return SR_SUCCESS;
}

