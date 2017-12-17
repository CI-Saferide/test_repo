#ifndef _SR_DB_CAN_H_
#define _SR_DB_CAN_H_

#include "sr_types.h"
#include "can_rule.h"

SR_32 sr_db_can_rule_init(void);
SR_32 sr_db_can_rule_deinit(void);
SR_32 sr_db_can_rule_add(can_rule_t *can_rule);
SR_32 sr_db_can_rule_delete(can_rule_t *can_rule);
can_rule_t * sr_db_can_rule_get(can_rule_t *can_rule);
void arik_print(char *msg);

#endif
