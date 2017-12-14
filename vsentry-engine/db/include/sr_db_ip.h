#ifndef _SR_DB_IP_H_
#define _SR_DB_IP_H_

#include "sr_types.h"
#include "ip_rule.h"

SR_32 sr_db_ip_rule_init(void);
SR_32 sr_db_ip_rule_deinit(void);
SR_32 sr_db_ip_rule_add(ip_rule_t *ip_rule);
SR_32 sr_db_ip_rule_delete(ip_rule_t *ip_rule);
ip_rule_t * sr_db_ip_rule_get(ip_rule_t *ip_rule);
void sr_db_ip_rule_print(void);

#endif
