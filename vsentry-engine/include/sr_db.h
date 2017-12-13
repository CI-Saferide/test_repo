#ifndef _SR_DB_H_
#define _SR_DB_H_

#include "sr_types.h"
#include "action.h"
#include "ip_rule.h"

#define SR_DB_ENGINE_NAME_SIZE 32
#define SR_DB_ENGINE_START "start"
#define SR_DB_ENGINE_STOP "stop"
#define SR_DB_ACTION_DROP_NAME "drop"
#define SR_DB_ACTION_ALLOW_NAME "allow"
#define SR_DB_ACTION_LOG_NAME "log"

SR_32 sr_db_init(void);
void sr_db_deinit(void);
action_t *sr_db_action_get_action(char *action_name);
SR_32 sr_db_ip_rule_add(ip_rule_t *ip_rule);
SR_32 sr_db_ip_rule_delete(ip_rule_t *ip_rule);
ip_rule_t * sr_db_ip_rule_get(ip_rule_t *ip_rule);
void sr_db_ip_rule_print(void);

#endif
