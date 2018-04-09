#include "sr_sal_common.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_ec_common.h"
#include "sr_ml_conngraph.h"
#include "sr_event_receiver.h"
#include "sr_stat_analysis.h"
#include "sr_stat_process_connection.h"

void sr_event_stats_receiver(SR_8 *msg_buff, SR_U32 msg_len)
{
	SR_U32 offset = 0, rc;
	struct sr_ec_connection_stat_t *pConStats;
	struct sr_ec_connection_transmit_t *pConTran;
	sr_stat_connection_info_t connection_info = {};

	while (offset < msg_len) {
		switch  (msg_buff[offset++]) {
			case SR_EVENT_STATS_CONNECTION:
				pConStats = (struct sr_ec_connection_stat_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_connection_stat_t);
				connection_info.con_id.saddr.v4addr = pConStats->con_id.source_addr.v4addr;
				connection_info.con_id.daddr.v4addr = pConStats->con_id.remote_addr.v4addr;
				connection_info.con_id.ip_proto = pConStats->con_id.ip_proto;
				connection_info.con_id.sport = pConStats->con_id.sport;
				connection_info.con_id.dport = pConStats->con_id.dport;
				connection_info.con_stats.tx_msgs = pConStats->tx_msgs;
				connection_info.con_stats.tx_bytes = pConStats->tx_bytes;
				connection_info.con_stats.rx_msgs = pConStats->rx_msgs;
				connection_info.con_stats.rx_bytes = pConStats->rx_bytes;
				connection_info.transmit_time = pConStats->curr_time;
#ifdef SR_STAT_ANALYSIS_DEBUG
				if (pConStats->con_id.sport == 5001 || pConStats->con_id.dport == 5001 ||
				    pConStats->con_id.sport == 22 || pConStats->con_id.dport == 22) { 
				CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
					"%s=CONN DEBUG proto:%d saddr:%x daddr:%x sport:%d dport:%d pid:%d rx_msgs:%d rx_bytes:%d tx_msgs:%d tx_bytes:%d time:%llu",MESSAGE,
					pConStats->con_id.ip_proto, 
					pConStats->con_id.source_addr.v4addr,
					pConStats->con_id.remote_addr.v4addr,
					pConStats->con_id.sport, 
					pConStats->con_id.dport, 
					pConStats->pid,
					pConStats->rx_msgs,
					pConStats->rx_bytes,
					pConStats->tx_msgs,
					pConStats->tx_bytes,
					pConStats->curr_time);
				}
#endif
				if ((rc = sr_stat_process_connection_hash_update(pConStats->pid, &connection_info)) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"%s=failed to update hash table for process connection",REASON);
					break;	
				}
				break;
			case SR_EVENT_STATS_CONNECTION_TRANSMIT:
				pConTran = (struct sr_ec_connection_transmit_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_connection_transmit_t);
				if ((rc = sr_stat_process_connection_hash_finish_transmit(pConTran->count)) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"%s=failed to hash exec for process connection",REASON);
					break;	
				}
				break;
			default:
				break;
		}
	}
}
