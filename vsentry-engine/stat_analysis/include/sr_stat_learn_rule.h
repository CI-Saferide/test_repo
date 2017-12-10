#ifndef __LEARN_RULE__
#define __LEARN_RULE__

#include "sr_stat_analysis.h"

SR_32 sr_stat_learn_rule_hash_init(void);
void sr_stat_learn_rule_hash_uninit(void);
SR_32 sr_stat_learn_rule_hash_update(char *exec, sr_stat_con_stats_t *con_stats);
SR_32 sr_stat_learn_rule_hash_exec_for_all(SR_32 (*cb)(void *hash_data, void *data));
SR_32 sr_stat_learn_rule_hash_delete(char *exec);
void sr_stat_learn_rule_ut(void);
void sr_learn_rule_connection_hash_print(void);
SR_32 sr_stat_learn_rule_create_process_rules(void);

#endif
