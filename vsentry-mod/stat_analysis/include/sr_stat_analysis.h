#ifndef __SR_STAT_ANALYSIS_
#define __SR_STAT_ANALYSIS_

#include "sr_types.h"
#include "sr_stat_connection.h"
#include "sr_stat_port.h"
#include "sr_stat_analysis_common.h"

SR_32 sr_stat_analysis_init(void);
void sr_stat_analysis_uninit(void);
void sr_stat_analisys_print_connections(SR_BOOL is_print_LRU);
SR_32 sr_stat_analysis_start_transmit(void);
void sr_stat_analysis_report_porcess_die(SR_U32 pid);
SR_32 sr_stat_analysis_handle_message(struct sr_stat_analysis_msg *msg);
void sr_stat_analysis_garbage_collector(void);
SR_BOOL sr_stat_analysis_um_is_running(void);

#endif
