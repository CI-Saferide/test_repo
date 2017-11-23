#ifndef __STAT_ANALYSIS_H_
#define __STAT_ANALYSIS_H_

#include "sr_types.h"
#include "sr_stat_process_connection.h"

SR_32 sr_stat_analysis_init(void);
void sr_stat_analysis_uninit(void);
SR_32 sr_stat_analysis_process_died(SR_U32 pid);
void sr_stat_analysis_dump(void);
void sr_stat_analysis_ut(void);
SR_32 sr_stat_analysis_send_msg(SR_U8 msg_type, sr_stat_connection_info_t *connection_info);

#endif
