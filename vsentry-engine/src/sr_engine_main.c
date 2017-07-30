#include "sr_types.h"
#include "sr_tasks.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_engine_main.h"
#include "sr_sal_common.h"
#include "sr_log.h"
#include "sr_msg_dispatch.h"
#include "sr_cls_file_control.h"
#include "sr_cls_network_control.h"
#include "sr_cls_canbus_control.h"
#include "sr_cls_port_control.h"
#include "sr_cls_rules_control.h"
#include "sr_config.h"
#include <arpa/inet.h> // TODO: take care of the agnostic part

SR_32 engine_main_loop(void *data)
{
	SR_32 ret;
	SR_U8 *msg;

	sal_printf("engine_main_loop started\n");

	/* init the module2engine buffer*/
	ret = sr_msg_alloc_buf(MOD2ENG_BUF, MAX_BUFFER_SIZE);
	if (ret != SR_SUCCESS){
		sal_printf("failed to init MOD2ENG msg_buf\n");
		return SR_ERROR;
	}

	while (!sr_task_should_stop(SR_ENGINE_TASK)) {
		msg = sr_read_msg(MOD2ENG_BUF, &ret);
		if (ret > 0) {
			sal_printf("MOD2ENG msg[len %d]. msg: %s\n", ret, msg);
			sr_free_msg(MOD2ENG_BUF);
		}

		if (ret == 0)
			sal_schedule_timeout(1);
	}

	/* free allocated buffer */
	sr_msg_free_buf(MOD2ENG_BUF);

	sal_printf("engine_main_loop end\n");

	return SR_SUCCESS;
}

static void eng2mod_test(void)
{
	sr_file_msg_cls_t *msg;
	SR_U8 count = 0;

	while (count < 32) {
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = (count % SR_CLS_INODE_TOTAL);
			msg->sub_msg.rulenum = count;
			msg->sub_msg.inode1 = count;
			msg->sub_msg.inode2 = count;
			sr_send_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		}
		count++;
	}
}


SR_32 sr_engine_start(void)
{
	SR_32 ret;
	SR_U8 run = 1;

	sal_printf("Welcome to sr-engine App!\n");

	ret = sr_log_init("[VSENTRY]", 0);
	if (ret != SR_SUCCESS){
		sal_printf("failed to init sr_log\n");
		return SR_ERROR;
	}

	ret = sr_start_task(SR_ENGINE_TASK, engine_main_loop);
	if (ret != SR_SUCCESS) {
		sal_printf("failed to start engine_main_loop\n");
		sr_stop_task(SR_LOG_TASK);
		return SR_ERROR;
	}

	ret = sr_msg_alloc_buf(ENG2MOD_BUF, MAX_BUFFER_SIZE);
	if (ret != SR_SUCCESS){
		sal_printf("failed to init ENG2MOD msg_buf\n");
		return SR_ERROR;
	}

	/* hardcoded configuration */	
	
	config_ut();
	while (run) {
		SR_8 input = getchar();

		switch (input) {
			case 'b':
				run = 0;
				break;
			case 's':
				sr_msg_print_stat();
				break;
			case 't':
				eng2mod_test();
				break;
		}
	}

	sr_stop_task(SR_ENGINE_TASK);
	sr_stop_task(SR_LOG_TASK);

	return 0;
}
