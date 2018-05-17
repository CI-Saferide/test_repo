#include "sr_log.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"
#include "sr_info_gather.h"
#include "sr_event_stats_receiver.h"
#include "sr_ec_common.h"

static SR_32 sr_info_gather_loop(void *data)
{
        SR_32 ret;
        SR_8 *msg;
	int fd;
	SR_BOOL is_msg;
	ssize_t n __attribute__((unused));

        CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=engine gather_loop started",MESSAGE);
                
	if (!(fd = sal_get_vsentry_fd())) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=sr_info_gather_loop: no vsenbtry fd", REASON);
		return SR_ERROR;
	}

        ret = sr_msg_alloc_buf(ENG2LOG_BUF, MAX_BUFFER_SIZE);
        if (ret != SR_SUCCESS){
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to init log buf",REASON);
                return 0;
        }
         
        ret = sr_msg_alloc_buf(MOD2LOG_BUF, MAX_BUFFER_SIZE);
        if (ret != SR_SUCCESS){
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to init log buf",REASON);
                return 0;
        }               
         
#ifdef CONFIG_STAT_ANALYSIS
        ret = sr_msg_alloc_buf(MOD2STAT_BUF, MAX_BUFFER_SIZE);
        if (ret != SR_SUCCESS){
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to init stat buf",REASON);
                return 0;
        }               
#endif
 
        while (!sr_task_should_stop(SR_INFO_GATHER_TASK)) {
				is_msg = SR_FALSE;
                msg = sr_read_msg(MOD2LOG_BUF, &ret);
                if (ret > 0) {
                        //printf ("recv\n");
						is_msg = SR_TRUE;
                        log_print_cef_msg((CEF_payload*)msg);
                        sr_free_msg(MOD2LOG_BUF);
                }       

                msg = sr_read_msg(ENG2LOG_BUF, &ret);
                if (ret > 0) {
						is_msg = SR_TRUE;
                        CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
							"%s=ENG2LOG msg: %s",MESSAGE,
							msg);
                        sr_free_msg(ENG2LOG_BUF);
                }

#ifdef CONFIG_STAT_ANALYSIS
                msg = sr_read_msg(MOD2STAT_BUF, &ret);
                if (ret > 0) {
					is_msg = SR_TRUE;
#ifdef SR_STAT_ANALYSIS_DEBUG
			CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
				"%s=got message ret:%d",MESSAGE,
				ret);
#endif
					sr_event_stats_receiver(msg, ret);
                    sr_free_msg(MOD2STAT_BUF);
				}
#endif
				// If no msgs hang until messages are sent
				if (!is_msg)
					n = read(fd, NULL, SR_SYNC_GATHER_INFO);
        }

        /* free allocated buffer */
        sr_msg_free_buf(ENG2LOG_BUF);
        sr_msg_free_buf(MOD2LOG_BUF);
#ifdef CONFIG_STAT_ANALYSIS
        sr_msg_free_buf(MOD2STAT_BUF);
#endif

        CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=engine gather_loop end",MESSAGE);

        return 0;
}

SR_32 sr_info_gather_init (void)
{
        CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=starting info gather module",MESSAGE);

        if (sr_start_task(SR_INFO_GATHER_TASK, sr_info_gather_loop) != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to start gather_loop",REASON);
                return SR_ERROR;
        }

        return SR_SUCCESS;
}

void sr_info_gather_uninit(void)
{
        sr_stop_task(SR_INFO_GATHER_TASK);
}
