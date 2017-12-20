#ifndef _SR_DB_H_
#define _SR_DB_H_

#include "sr_types.h"
#include "action.h"
#include "sr_db_ip.h"
#include "sr_db_file.h"
#include "sr_db_can.h"

#define SR_DB_ENGINE_NAME_SIZE 32
#define SR_DB_ENGINE_START "start"
#define SR_DB_ENGINE_STOP "stop"
#define SR_DB_ACTION_DROP_NAME "drop"
#define SR_DB_ACTION_ALLOW_NAME "allow"
#define SR_DB_ACTION_LOG_NAME "log"

SR_32 sr_db_init(void);
void sr_db_deinit(void);
SR_32 sr_db_action_update_action(action_t *action);
action_t *sr_db_action_get_action(char *action_name);
SR_32 sr_db_action_delete_action(action_t *action);

#endif
