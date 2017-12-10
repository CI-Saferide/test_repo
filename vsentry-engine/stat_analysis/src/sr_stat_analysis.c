#include "sr_sal_common.h"
#include "sr_stat_analysis.h"
#include "sr_msg_dispatch.h"
#include "sr_msg.h"
#include "sr_stat_analysis_common.h"
#include "sr_stat_learn_rule.h"
#include <stdio.h>

static SR_U64 last_aging;
static sr_stat_mode_t stat_mode;

SR_32 sr_stat_analysis_init(void)
{
	SR_U64 t;

	if (sr_stat_learn_rule_hash_init() != SR_SUCCESS) {
		sal_printf("stat analysis init failed at sr_stat_learn_rule_hash_init\n");
		return SR_ERROR;
	}

	if (sr_stat_process_connection_hash_init() != SR_SUCCESS) {
		sal_printf("stat analysis init failed at sr_stat_process_connection_hash_init\n");
		sr_stat_learn_rule_hash_uninit();
		return SR_ERROR;
	}
	t = sal_get_time();
	last_aging = t;
	stat_mode = SR_STAT_MODE_LEARN;

	return SR_SUCCESS;
}

void sr_stat_analysis_uninit(void)
{
	sr_stat_process_connection_hash_uninit();
	sr_stat_learn_rule_hash_uninit();
}

void sr_stat_analysis_dump(void)
{
	sr_stat_process_connection_hash_print();
}

void sr_stat_analysis_ut(void)
{
	sr_stat_process_connection_ut();
}

SR_32 sr_stat_analysis_send_msg(SR_U8 msg_type, sr_stat_connection_info_t *connection_info)
{
	sr_stat_analysis_msg_t *msg;

        msg = (sr_stat_analysis_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
        if (msg) {
                msg->msg_type = SR_MSG_TYPE_STAT_ANALYSIS;
                msg->sub_msg.msg_type = msg_type;
		msg->sub_msg.con_id.saddr = connection_info->con_id.saddr;
		msg->sub_msg.con_id.daddr = connection_info->con_id.daddr;
		msg->sub_msg.con_id.ip_proto = connection_info->con_id.ip_proto;
		msg->sub_msg.con_id.sport = connection_info->con_id.sport;
		msg->sub_msg.con_id.dport = connection_info->con_id.dport;
                sr_send_msg(ENG2MOD_BUF, sizeof(msg));
        }

        return SR_SUCCESS;
}

SR_32 process_died_cb(SR_U32 process_id, sr_stat_connection_info_t *connection_info)
{

	sr_stat_analysis_send_msg(SR_STAT_ANALYSIS_CONNECTION_DIED, connection_info);

        return SR_SUCCESS;
}

SR_32 sr_stat_analysis_process_died(SR_U32 pid)
{
	SR_32 rc;
	SR_U64 t;

	t = sal_get_time();

	if ((rc = sr_stat_process_connection_hash_exec_for_process(pid, process_died_cb)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_exec_for_process FAILED !!!\n");
		return SR_ERROR;
        }
	if ((rc = sr_stat_process_connection_hash_delete(pid)) == SR_ERROR) {
		sal_printf("sr_stat_process_connection_hash_exec_for_process FAILED !!!\n");
		return SR_ERROR;
        }

	if (t - last_aging > SR_AGING_CHECK_TIME) {
		sr_stat_connection_info_t con = {};
#ifdef SR_STAT_ANALYSIS_DEBUG
		sal_printf("STAT ANALYSIS AGING \n");
#endif 
		// Its time to check for aging
		sr_stat_process_connection_delete_aged_connections();
		last_aging = t; 
		// Send keep alive just in case
		sr_stat_analysis_send_msg(SR_STAT_ANALYSIS_KEEP_ALIVE, &con);
 	}

	return SR_SUCCESS;
}

sr_stat_mode_t sr_stat_analysis_learn_mode_get(void)
{
	return stat_mode;
} 

void sr_stat_analysis_learn_mode_set(sr_stat_mode_t new_stat_mode)
{
	if (new_stat_mode == SR_STAT_MODE_PROTECT && stat_mode == SR_STAT_MODE_LEARN)
		st_stats_process_connection_protect();
	stat_mode = new_stat_mode;
} 