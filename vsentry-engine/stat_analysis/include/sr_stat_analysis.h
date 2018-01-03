#ifndef __STAT_ANALYSIS_H_
#define __STAT_ANALYSIS_H_

#include "sr_types.h"
#include "sr_stat_process_connection.h"

typedef enum {
	SR_STAT_MODE_LEARN,
	SR_STAT_MODE_PROTECT,
	SR_STAT_MODE_HALT,
	SR_STAT_MODE_OFF,
} sr_stat_mode_t;

SR_32 sr_stat_analysis_init(void);
void sr_stat_analysis_uninit(void);
SR_32 sr_stat_analysis_process_died(SR_U32 pid);
void sr_stat_analysis_dump(void);
void sr_stat_analysis_ut(void);
SR_32 sr_stat_analysis_send_msg(SR_U8 msg_type, sr_stat_connection_info_t *connection_info);
void sr_stat_analysis_learn_mode_set(sr_stat_mode_t mode);
sr_stat_mode_t sr_stat_analysis_learn_mode_get(void);

#endif
