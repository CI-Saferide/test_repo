#ifndef __LEARN_RULE__
#define __LEARN_RULE__

#include "sr_stat_analysis.h"

#define LEARN_RULE_TOLLERANCE 1.05

SR_32 sr_stat_learn_rule_hash_init(void);
void sr_stat_learn_rule_hash_uninit(void);
SR_32 sr_stat_learn_rule_hash_update(char *exec, sr_stat_con_stats_t *con_stats);
SR_32 sr_stat_learn_rule_hash_exec_for_all(SR_32 (*cb)(void *hash_data, void *data));
SR_32 sr_stat_learn_rule_hash_delete(char *exec);
SR_32 sr_stat_learn_rule_hash_delete_all(void);
void sr_stat_learn_rule_ut(void);
void sr_learn_rule_connection_hash_print(void);
SR_32 sr_stat_learn_rule_create_process_rules(void);
SR_32 sr_stat_learn_rule_cleanup_process_rules(void);
SR_32 sr_stat_learn_rule_deploy(void);
SR_32 sr_stat_learn_rule_undeploy(void);

#endif

