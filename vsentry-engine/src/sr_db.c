#include "sr_db.h"
#include "string.h"

static action_t db_actions[ACTION_TOTAL] = {};

void sr_db_init(void)
{
	action_e i;

	for (i = 0; i < ACTION_TOTAL; i++) {
		switch (i) { 
			case ACTION_DROP:
				strncpy(db_actions[i].action_name, SR_DB_ACTION_DROP_NAME, ACTION_STR_SIZE);
				break;
			case ACTION_ALLOW:
				strncpy(db_actions[i].action_name, SR_DB_ACTION_ALLOW_NAME, ACTION_STR_SIZE);
				break;
			default:
				break;
		}
	}
}

action_t *sr_db_get_action(char *action_name)
{
	action_e i;

	for (i = 0; i < ACTION_TOTAL; i++) {
		if (!strncmp(db_actions[i].action_name, action_name, ACTION_STR_SIZE))
			return &db_actions[i];
	}

	return NULL;
}
