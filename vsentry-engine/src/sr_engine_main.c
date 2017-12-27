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
#include "sr_config.h"
#include "sr_file_hash.h"
#include "sr_can_collector.h"
#include "sr_config_parse.h"
#include "sr_info_gather.h"
#include "sr_static_policy.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#endif
#include "internal_api.h"
#include "sr_db.h"
#ifdef CONFIG_CAN_ML
#include "sr_ml_can.h"
#endif /* CONFIG_CAN_ML */
#include "sr_log_uploader.h"
//#include "sr_conio.h"

extern struct canTaskParams can_args;
extern struct config_params_t config_params;

extern SR_8* disk;

SR_32 engine_main_loop(void *data)
{
	SR_32 ret;
	SR_8 *msg;

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"engine_main_loop started\n");

	/* init the module2engine buffer*/
	ret = sr_msg_alloc_buf(MOD2ENG_BUF, MAX_BUFFER_SIZE);
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"failed to init MOD2ENG msg_buf\n");
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

	CEF_log_event(SR_CEF_CID_SYSTEM, "warning", SEVERITY_MEDIUM,
					"engine_main_loop end\n");

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
	
	read_vsentry_config("sr_config", config_params);

	ret = sr_log_init("[vsentry]", 0);
	if (ret != SR_SUCCESS){
		printf("failed to init sr_log\n");
		return SR_ERROR;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"vsentry engine started\n");

	ret = sr_log_uploader_init();
	if (ret != SR_SUCCESS){
		printf("failed to init_log_uploader\n");
		return SR_ERROR;
	}

#ifdef CONFIG_STAT_ANALYSIS
	ret = sr_stat_analysis_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to init sr_stat_analysis_init\n");
		return SR_ERROR;
	}
#endif

#ifdef CONFIG_CAN_ML
	ret = sr_ml_can_hash_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to init can_ml hash table\n");
		return SR_ERROR;
	}
#endif /* CONFIG_CAN_ML */

	ret = sr_info_gather_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to init sr_stat_analysis_init\n");
		return SR_ERROR;
	}

	ret = sr_ml_conngraph_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to init sr_ml_conngraph\n");
		return SR_ERROR;
	}

	ret = sr_start_task(SR_ENGINE_TASK, engine_main_loop);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to start engine_main_loop\n");
		sr_stop_task(SR_INFO_GATHER_TASK);

		return SR_ERROR;
	}

	ret = sr_msg_alloc_buf(ENG2MOD_BUF, MAX_BUFFER_SIZE);
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to init ENG2MOD msg_buf\n");
		return SR_ERROR;
	}

	ret = sr_file_hash_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to init file_hash\n");
		return SR_ERROR;
	}

	ret = sr_create_filter_paths();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to init sr_create_fileter_faths\n");
		return SR_ERROR;
	}

	sr_db_init();
	sentry_init(sr_config_vsentry_db_cb);

	sr_static_policy_db_mng_start();

#ifdef UNIT_TEST
	config_ut();
#endif

	read_vsentry_config("sr_config", config_params);
	can_args.can_interface = config_params.can0_interface;
	if(config_params.collector_enable){
		ret = sr_start_task(SR_CAN_COLLECT_TASK, can_collector_init);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"failed to start can-bus collector\n");
			return SR_ERROR;	
		}	
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
						"can-bus collector - enabled!\n");
	} else {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
						"can-bus collector - disabled!\n");
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
#ifdef SR_CAN_DEBUG_PRINT			
			case 'p':
				can_args.can_print = !can_args.can_print;
				printf("\rcan-bus %s prints - %s\n", can_args.can_interface, (can_args.can_print)? "enabled" : "disabled");
				break;
#endif						
			case 'v':
					printf("\navailable space under %s is: %lld bytes\n",disk,sal_gets_space(disk));
				break;
			case 'd':
#ifdef CONFIG_CAN_ML
					printf ("printing debud info for ml_can\n");
					sr_ml_can_print_hash();
#endif /* CONFIG_CAN_ML */
				break;
		}
	}
	//sr_static_policy_db_mng_stop();
	sr_stop_task(SR_CAN_COLLECT_TASK);
	sr_stop_task(SR_ENGINE_TASK);
	sentry_stop();
#ifdef CONFIG_STAT_ANALYSIS
	sr_stat_analysis_uninit();
#endif /* CONFIG_STAT_ANALYSIS */
#ifdef CONFIG_CAN_ML
	sr_ml_can_hash_deinit();
#endif /* CONFIG_CAN_ML */
	sr_info_gather_uninit();
	sr_file_hash_deinit();
	sr_db_deinit();
	sr_log_uploader_deinit();
	return 0;
}
