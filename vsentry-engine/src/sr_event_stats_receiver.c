#include "sr_sal_common.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_ec_common.h"
#include "sr_event_receiver.h"
#include "sr_stat_analysis.h"
#include "sr_stat_process_connection.h"
#include "sr_white_list_file.h"
#include "sr_white_list_can.h"
#include "sr_white_list_ip.h"
#ifdef CONFIG_SYSTEM_POLICER
#include "sr_stat_system_policer.h"
#endif

static SR_32 handle_stat_connection(struct sr_ec_connection_stat_t *con)
{
	sr_stat_connection_info_t connection_info = {};
	SR_32 rc;

	connection_info.con_id.saddr.v4addr = con->con_id.source_addr.v4addr;
	connection_info.con_id.daddr.v4addr = con->con_id.remote_addr.v4addr;
	connection_info.con_id.ip_proto = con->con_id.ip_proto;
	connection_info.con_id.sport = con->con_id.sport;
	connection_info.con_id.dport = con->con_id.dport;
	connection_info.con_stats.tx_msgs = con->tx_msgs;
	connection_info.con_stats.tx_bytes = con->tx_bytes;
	connection_info.con_stats.rx_msgs = con->rx_msgs;
	connection_info.con_stats.rx_bytes = con->rx_bytes;
	connection_info.transmit_time = con->curr_time;
#ifdef SR_STAT_ANALYSIS_DEBUG
	if (con->con_id.sport == 5001 || con->con_id.dport == 5001 ||
				    con->con_id.sport == 22 || con->con_id.dport == 22) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=CONN DEBUG proto:%d saddr:%x daddr:%x sport:%d dport:%d pid:%d rx_msgs:%d rx_bytes:%d tx_msgs:%d tx_bytes:%d time:%llu",MESSAGE,
					con->con_id.ip_proto,
					con->con_id.source_addr.v4addr,
					con->con_id.remote_addr.v4addr,
					con->con_id.sport,
					con->con_id.dport,
					con->pid,
					con->rx_msgs,
					con->rx_bytes,
					con->tx_msgs,
					con->tx_bytes,
					con->curr_time);
				}
#endif

	if ((rc = sr_stat_process_connection_hash_update(con->pid, &connection_info)) != SR_SUCCESS) {
              CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to update hash table for process connection",REASON);
              return rc;
	}

	return SR_SUCCESS;
}

static SR_32 handle_stat_connection_wl(struct sr_ec_connection_stat_wl_t *con_wl)
{
	struct sr_ec_new_connection_wl_t new_con = {};
	SR_32 rc;

	if ((rc = handle_stat_connection(&(con_wl->con))) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"%s=failed to handle stat connection",REASON);
		return rc;
	}

	/* If learn send to conection graph */
	if (con_wl->con.con_id.ip_proto == 17 && con_wl->con.is_outgoing) {
		strncpy(new_con.exec, con_wl->exec, SR_MAX_PATH_SIZE);
	    new_con.con.remote_addr = con_wl->con.con_id.remote_addr;
	    new_con.con.ip_proto = con_wl->con.con_id.ip_proto;
		if ((rc = sr_white_list_ip_new_connection(&new_con)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to add udp connection to ip white list",REASON);
			return rc;
		}
	}

	return SR_SUCCESS;

}

void sr_event_stats_receiver(SR_8 *msg_buff, SR_U32 msg_len)
{
	SR_U32 offset = 0, rc;
	struct sr_ec_connection_stat_t *pConStats;
	struct sr_ec_connection_stat_wl_t *pConStats_wl;
	struct sr_ec_connection_transmit_t *pConTran;
	struct sr_ec_file_wl_t *pFile_wl;
	struct sr_ec_can_t *wl_can;
	struct sr_ec_new_connection_wl_t *pNewConnection_wl;
#ifdef CONFIG_SYSTEM_POLICER
	struct sr_ec_system_stat_t *p_system;
#endif

	while (offset < msg_len) {
		switch  (msg_buff[offset++]) {
			case SR_EVENT_STATS_CONNECTION:
				pConStats = (struct sr_ec_connection_stat_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_connection_stat_t);
				handle_stat_connection(pConStats);
				break;
			case SR_EVENT_STATS_CONNECTION_WL:
				pConStats_wl = (struct sr_ec_connection_stat_wl_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_connection_stat_wl_t);
				handle_stat_connection_wl(pConStats_wl);
				break;
			case SR_EVENT_STATS_CONNECTION_TRANSMIT:
				pConTran = (struct sr_ec_connection_transmit_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_connection_transmit_t);
				if ((rc = sr_stat_process_connection_hash_finish_transmit(pConTran->count)) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"%s=failed to hash exec for process connection",REASON);
					break;	
				}
				/* Use this oportunity to check for aging */
				sr_stat_analysis_handle_aging();
				break;
#ifdef CONFIG_SYSTEM_POLICER
			case SR_EVENT_STATS_SYSTEM:
				p_system = (struct sr_ec_system_stat_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_system_stat_t);
				if ((rc = sr_stat_system_policer_new_data(p_system)) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"failed processing system policer new data");
					break;	
				}
				break;
			case SR_EVENT_STATS_SYSTEM_FINISH:
				offset += sizeof(struct sr_ec_system_finish_t);
				if ((rc = sr_start_system_policer_data_finish()) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"failed processing system policer finish notification.");
					break;	
				}
				break;
#endif
			case SR_EVENT_STATS_FILE_WL:
				pFile_wl = (struct sr_ec_file_wl_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_file_wl_t);
				if ((rc = sr_white_list_file_wl(pFile_wl)) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"%s=sr_white_list_open failed",REASON);
					break;	
				}
				break;
			case SR_EVENT_STATS_CANBUS:
				wl_can = (struct sr_ec_can_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_can_t);
				
				if ((rc = sr_white_list_canbus(wl_can)) != SR_SUCCESS) { // hashing function
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"%s=failed to hash exec for process canbus",REASON);
					break;	
				}
				break;					
			case SR_EVENT_STATS_NEW_CONNECTION_WL:
				pNewConnection_wl = (struct sr_ec_new_connection_wl_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_new_connection_wl_t);
				if (sr_white_list_ip_new_connection(pNewConnection_wl) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"%s=failed to hash exec for process ip new connection creation",REASON);
					break;	
				}
                                break;
			default:
				break;
		}
	}
}
