#ifndef SR_STAT_ANALYSIS_COMMON_
#define SR_STAT_ANALYSIS_COMMON_
#include "sr_types.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"

#define SR_AGING_CHECK_TIME 60
#define SR_AGING_TIME 300

enum {
	SR_STAT_ANALYSIS_CONNECTION_DIED,
	SR_STAT_ANALYSIS_KEEP_ALIVE,
	SR_STATS_ANALYSIS_MAX = SR_STAT_ANALYSIS_KEEP_ALIVE,
	SR_STATS_ANALYSIS_TOTAL = (SR_STATS_ANALYSIS_MAX + 1),
};

struct sr_stat_analysis_msg {
	SR_U8 msg_type;
	sr_connection_id_t con_id;
};

#endif
