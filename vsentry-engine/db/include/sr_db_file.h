#ifndef _SR_DB_FILE_H_
#define _SR_DB_FILE_H_

#include "sr_types.h"
#include "file_rule.h"

SR_32 sr_db_file_rule_init(void);
SR_32 sr_db_file_rule_deinit(void);
SR_32 sr_db_file_rule_add(file_rule_t *file_rule);
SR_32 sr_db_file_rule_delete(file_rule_t *file_rule);
file_rule_t * sr_db_file_rule_get(file_rule_t *file_rule);

#endif
