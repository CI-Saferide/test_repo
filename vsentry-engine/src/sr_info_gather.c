#include "sr_log.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"
#include "sr_info_gather.h"
#include "sr_event_stats_receiver.h"

static SR_32 sr_info_gather_loop(void *data)
{
        SR_32 ret;
        SR_8 *msg;

        sal_printf("engine_info_gather_loop started\n");
                
        ret = sr_msg_alloc_buf(ENG2LOG_BUF, MAX_BUFFER_SIZE);
        if (ret != SR_SUCCESS){
                sal_printf("failed to init log buf\n");
                return 0;
        }
         
        ret = sr_msg_alloc_buf(MOD2LOG_BUF, MAX_BUFFER_SIZE);
        if (ret != SR_SUCCESS){
                sal_printf("failed to init log buf\n");
                return 0;
        }               
         
#ifdef CONFIG_STAT_ANALYSIS
        ret = sr_msg_alloc_buf(MOD2STAT_BUF, MAX_BUFFER_SIZE);
        if (ret != SR_SUCCESS){
                sal_printf("failed to init stat buf\n");
                return 0;
        }               
#endif
 
        while (!sr_task_should_stop(SR_INFO_GATHER_TASK)) {
                msg = sr_read_msg(MOD2LOG_BUF, &ret);
                if (ret > 0) {
                        log_print_cef_msg((CEF_payload*)msg);
                        sr_free_msg(MOD2LOG_BUF);
                }       

                msg = sr_read_msg(ENG2LOG_BUF, &ret);
                if (ret > 0) {
                        sal_printf("ENG2LOG msg: %s\n", msg);
                        sr_free_msg(ENG2LOG_BUF);
                }

#ifdef CONFIG_STAT_ANALYSIS
                msg = sr_read_msg(MOD2STAT_BUF, &ret);
                if (ret > 0) {
#ifdef SR_STAT_ANALYSIS_DEBUG
			sal_printf("Got message ret:%d \n", ret);
#endif
			sr_event_stats_receiver(msg, ret);
                        sr_free_msg(MOD2STAT_BUF);
                }
#endif
        }

        /* free allocated buffer */
        sr_msg_free_buf(ENG2LOG_BUF);
        sr_msg_free_buf(MOD2LOG_BUF);
#ifdef CONFIG_STAT_ANALYSIS
        sr_msg_free_buf(MOD2STAT_BUF);
#endif

        sal_printf("engine_info_gather_loop end\n");

        return 0;
}

SR_32 sr_info_gather_init (void)
{
        sal_printf("Starting info_init module!\n");

        if (sr_start_task(SR_INFO_GATHER_TASK, sr_info_gather_loop) != SR_SUCCESS) {
                sal_printf("failed to start sr_info_gather_loop\n");
                return SR_ERROR;
        }

        return SR_SUCCESS;
}

void sr_info_gather_uninit(void)
{
        sr_stop_task(SR_INFO_GATHER_TASK);
}
