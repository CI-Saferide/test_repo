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
#include "sr_event_receiver.h"
#include "sr_config.h"
#include "sr_ml_conngraph.h"
#include "sr_sal_common.h"
#include "sr_control.h"
#include "sr_ver.h"
#include "sr_file_hash.h"
#include "sr_can_collector.h"
#include "sr_config_parse.h"
#include "sr_info_gather.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#endif
extern struct canTaskParams can_args;
extern struct config_params_t config_params;

extern SR_8* disk;

SR_32 engine_main_loop(void *data)
{
	SR_32 ret;
	SR_8 *msg;

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
			sr_event_receiver(msg, ret);
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
	FILE *f;

	sal_printf("vsentry engine started\n");

	ret = sr_log_init("[vsentry]", 0);
	if (ret != SR_SUCCESS){
		sal_printf("failed to init sr_log\n");
		return SR_ERROR;
	}

#ifdef CONFIG_STAT_ANALYSIS
	ret = sr_stat_analysis_init();
	if (ret != SR_SUCCESS){
		sal_printf("failed to init sr_stat_analysis_init\n");
		return SR_ERROR;
	}
#endif

	ret = sr_info_gather_init();
	if (ret != SR_SUCCESS){
		sal_printf("failed to init sr_stat_analysis_init\n");
		return SR_ERROR;
	}

	ret = sr_ml_conngraph_init();
	if (ret != SR_SUCCESS){
		sal_printf("failed to init sr_ml_conngraph\n");
		return SR_ERROR;
	}

	ret = sr_start_task(SR_ENGINE_TASK, engine_main_loop);
	if (ret != SR_SUCCESS) {
		sal_printf("failed to start engine_main_loop\n");
		sr_stop_task(SR_INFO_GATHER_TASK);
		return SR_ERROR;
	}

	ret = sr_msg_alloc_buf(ENG2MOD_BUF, MAX_BUFFER_SIZE);
	if (ret != SR_SUCCESS){
		sal_printf("failed to init ENG2MOD msg_buf\n");
		return SR_ERROR;
	}

	ret = sr_file_hash_init();
	if (ret != SR_SUCCESS){
		sal_printf("failed to init file_hash\n");
		return SR_ERROR;
	}

	ret = sr_create_filter_paths();
	if (ret != SR_SUCCESS){
		sal_printf("failed to init sr_create_fileter_faths\n");
		return SR_ERROR;
	}

	config_ut();
	read_vsentry_config("sr_config", config_params);
	can_args.can_interface = config_params.can0_interface;
	if(config_params.collector_enable){
		ret = sr_start_task(SR_CAN_COLLECT_TASK, can_collector_init);
		if (ret != SR_SUCCESS) {
			sal_printf("Failed to start CAN-Bus Collector\n");
			return SR_ERROR;	
		}	
		sal_printf("CAN-Bus Collector - ENABLED!\n");
	} else {
		sal_printf("CAN-Bus Collector - DISABLED!\n");
	}
	/* indicate VPI that we are running */
	f = fopen("/tmp/sec_state", "w");
	fprintf(f, "on");
	fclose(f);
	//sr_control_set_state(SR_FALSE); /* just an example */
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
			case 'p':
				can_args.can_print = !can_args.can_print;
				sal_printf("\nCAN-Bus %s prints - Enable|Disable\n", can_args.can_interface);
				break;			
			case 'v':
				sal_printf("\nAvailable Space under %s is: %ld bytes\n",disk,sal_gets_space(disk));
				break;				
		}
	}
	
	sr_stop_task(SR_CAN_COLLECT_TASK);
	sr_stop_task(SR_ENGINE_TASK);
#ifdef CONFIG_STAT_ANALYSIS
	sr_stat_analysis_uninit();
#endif
	sr_info_gather_uninit();
	sr_file_hash_deinit();

	return 0;
}
