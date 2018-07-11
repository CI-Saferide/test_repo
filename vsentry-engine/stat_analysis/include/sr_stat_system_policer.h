#ifndef __SYSYTEM_POLICER_H___
#define __SYSYTEM_POLICER_H___

#include "sr_ec_common.h"
#include "sr_types.h"

#define SR_SYSTEM_POLICER_AGED_THRESHHOLD 60

SR_32 sr_stat_system_policer_init(void);
void sr_stat_system_policer_uninit(void);
SR_32 sr_stat_system_policer_new_data(struct sr_ec_system_stat_t *stats);
SR_32 sr_stat_system_policer_delete_aged(void);
SR_32 sr_start_system_policer_data_finish(void);
void sr_stat_system_policer_print(void);
void sr_stat_system_policer_learn_print(void);
SR_32 sr_stat_policer_load_file(void);

#endif
