#include "sr_sal_common.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_ec_common.h"
#include "sr_ml_conngraph.h"
#include "sr_event_receiver.h"
#include "sr_cls_rules_control.h"
#include "sr_cls_file_control.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#include "sr_stat_process_connection.h"
#endif

SR_32 sr_ml_mode = ML_MODE_LEARN;
// TODO: load profile at startup, determine default loading state

void sr_ml_changemode(SR_32 mode)
{
	if (mode != sr_ml_mode) {
		switch (mode) {
			case ML_MODE_LEARN:
				// clear runtime data structure, start new learning
				sr_ml_conngraph_clear_graph();
				//sr_ml_conngraph_loadconf();
				break;
			case ML_MODE_DETECT:
				// TODO: load learnt profile?
				sr_ml_conngraph_save();
				break;
		}
		sr_ml_mode = mode;
	}
	
}

int counter=0;

void sr_event_receiver(SR_8 *msg_buff, SR_U32 msg_len)
{
	struct sr_ec_new_connection_t *pNewConnection;
	struct sr_ec_file_t *pNewFile;
	SR_U32 offset = 0, rc;
#ifdef CONFIG_STAT_ANALYSIS
	struct sr_ec_connection_stat_t *pConStats;
	struct sr_ec_process_died_t *pProcessDied;
	sr_stat_connection_info_t connection_info = {};
	SR_32 spid;
#endif

	while (offset < msg_len) {
		switch  (msg_buff[offset++]) {
			case SR_EVENT_NEW_CONNECTION:
				// collect
				pNewConnection = (struct sr_ec_new_connection_t *) &msg_buff[offset];
				sr_ml_conngraph_event(pNewConnection);
				offset += sizeof(struct sr_ec_new_connection_t);
				break;
			case SR_EVENT_FILE_CREATED:
				pNewFile = (struct sr_ec_file_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_file_t);
				if ((rc = sr_cls_file_create((char *)(pNewFile->name))) != SR_SUCCESS) {
					sal_printf("Error %s: handle_file_created, failed file:%s\n", __FUNCTION__, pNewFile->name);
				}
				break;
#ifdef CONFIG_STAT_ANALYSIS
			case SR_EVENT_STATS_CONNECTION:
				pConStats = (struct sr_ec_connection_stat_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_connection_stat_t);
				connection_info.con_id.saddr.v4addr = pConStats->con_id.source_addr.v4addr;
				connection_info.con_id.daddr.v4addr = pConStats->con_id.remote_addr.v4addr;
				connection_info.con_id.ip_proto = pConStats->con_id.ip_proto;
				connection_info.con_id.sport = pConStats->con_id.sport;
				connection_info.con_id.dport = pConStats->con_id.dport;
				connection_info.tx_msgs = pConStats->tx_msgs;
				connection_info.tx_bytes = pConStats->tx_bytes;
				connection_info.rx_msgs = pConStats->rx_msgs;
				connection_info.rx_bytes = pConStats->rx_bytes;
#ifdef SR_STAT_ANALYSIS_DEBUG
				if (pConStats->con_id.sport == 7777 || pConStats->con_id.dport == 7777 ||
				    pConStats->con_id.sport == 22 || pConStats->con_id.dport == 22) { 
				sal_printf("CONN DEBUG proto:%d saddr:%x daddr:%x sport:%d dport:%d pid:%d rx_msgs:%d rx_bytes:%d tx_msgs:%d tx_bytes:%d \n",
					pConStats->con_id.ip_proto, 
					pConStats->con_id.source_addr.v4addr,
					pConStats->con_id.remote_addr.v4addr,
					pConStats->con_id.sport, 
					pConStats->con_id.dport, 
					pConStats->pid,
					pConStats->rx_msgs,
					pConStats->rx_bytes,
					pConStats->tx_msgs,
					pConStats->tx_bytes);
				}
#endif
				if ((rc = sr_stat_process_connection_hash_update(pConStats->pid, &connection_info)) != SR_SUCCESS) {
                			sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
					break;	
				}
				break;
			case SR_EVENT_PROCESS_DIED:
				pProcessDied = (struct sr_ec_process_died_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_process_died_t);
				spid = (SR_32)(pProcessDied->pid);
				if (spid <= 0)
					break;
				if ((rc = sr_stat_analysis_process_died(pProcessDied->pid)) != SR_SUCCESS) {
                			sal_printf("sr_stat_analysis_process_died FAILED !!!\n");
					break;	
				}
				break;
#endif
			default:
				break;
		}
	}
}
