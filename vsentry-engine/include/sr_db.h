#ifndef _SR_DB_H_
#define _SR_DB_H_

#include "sr_types.h"
#include "action.h"

#define SR_DB_ENGINE_NAME_SIZE 32
#define SR_DB_ENGINE_START "start"
#define SR_DB_ENGINE_STOP "stop"
#define SR_DB_ACTION_DROP_NAME "drop"
#define SR_DB_ACTION_ALLOW_NAME "allow"

void sr_db_init(void);
action_t *sr_db_get_action(char *action_name);

#endif
