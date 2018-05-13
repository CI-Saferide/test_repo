#include "sr_sal_common.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_ec_common.h"
#include "sr_event_receiver.h"
#include "sr_cls_rules_control.h"
#include "sr_cls_file_control.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#include "sr_stat_process_connection.h"
#endif

// TODO: load profile at startup, determine default loading state

void sr_event_receiver(SR_8 *msg_buff, SR_U32 msg_len)
{
	struct sr_ec_file_t *pNewFile;
#ifdef CONFIG_STAT_ANALYSIS
	struct sr_ec_process_died_t *pProcessDied;
	SR_32 spid;
#endif
	SR_U32 offset = 0;
	SR_32 rc;

	while (offset < msg_len) {
		switch  (msg_buff[offset++]) {
			case SR_EVENT_FILE_CREATED:
				pNewFile = (struct sr_ec_file_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_file_t);
#ifdef SR_STAT_ANALYSIS_DEBUG
				CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=file created :%s",MESSAGE,
					pNewFile->name ? (char *)(pNewFile->name) : "");
#endif
				if ((rc = sr_cls_file_create((char *)(pNewFile->name))) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to handle file create for %s",REASON,
						pNewFile->name);
				}
				break;
#ifdef CONFIG_STAT_ANALYSIS
			 case SR_EVENT_PROCESS_DIED:
				pProcessDied = (struct sr_ec_process_died_t *) &msg_buff[offset];
				offset += sizeof(struct sr_ec_process_died_t);
				spid = (SR_32)(pProcessDied->pid);
#ifdef SR_STAT_ANALYSIS_DEBUG
				CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=Process died:%d",MESSAGE,
					spid);
#endif
				if (spid <= 0)
					break;
				if ((rc = sr_stat_analysis_process_died(pProcessDied->pid)) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to handle process died",REASON);
					break;
				}
				break;
#endif
			default:
				break;
		}
	}
}
