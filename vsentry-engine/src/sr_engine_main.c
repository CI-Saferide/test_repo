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
#include "sr_sal_common.h"
#include "sr_control.h"
#include "sr_ver.h"
#include "sr_config.h"
#include "sr_file_hash.h"
#include "sr_can_collector.h"
#include "sr_config_parse.h"
#include "sr_info_gather.h"
#include "sr_static_policy.h"
#include "sr_white_list.h"
#include "sr_white_list_ip.h"
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
#include "sr_command.h"
#include "sr_config_common.h"
#include "sr_can_collector.h"
#include "sr_config_parse.h"

static SR_32 engine_main_loop(void *data)
{
	SR_32 ret;
	SR_8 *msg;
	int fd;
	ssize_t n __attribute__((unused));

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=engine_main_loop started",MESSAGE);

	/* init the module2engine buffer*/
	ret = sr_msg_alloc_buf(MOD2ENG_BUF, MAX_BUFFER_SIZE);
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to init MOD2ENG msg_buf",REASON);
		return SR_ERROR;
	}

	if (!(fd = sal_get_vsentry_fd())) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
                        "%s=sr_info_gather_loop: no vsenbtry fd", REASON);
                return SR_ERROR;
	}

	while (!sr_task_should_stop(SR_ENGINE_TASK)) {
		msg = sr_read_msg(MOD2ENG_BUF, &ret);
		if (ret > 0) {
			sr_event_receiver(msg, (SR_U32)ret);
			sr_free_msg(MOD2ENG_BUF);
		}

		if (ret == 0)
			n = read(fd, NULL, SR_SYNC_ENGINE);
	}

	/* free allocated buffer */
	sr_msg_free_buf(MOD2ENG_BUF);

	CEF_log_event(SR_CEF_CID_SYSTEM, "warning", SEVERITY_MEDIUM,
		"%s=engine_main_loop end",MESSAGE);

	return SR_SUCCESS;
}

static void eng2mod_test(void)
{
	sr_file_msg_cls_t *msg;
	SR_U32 count = 0;

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

SR_32 sr_engine_start(int argc, char *argv[])
{
	SR_32 ret;
	SR_BOOL run = SR_TRUE;
	FILE *f;
	sr_config_msg_t *msg;
	struct config_params_t *config_params;
	struct canTaskParams *can_args;
	SR_8 *config_file = NULL;
	SR_32 cmd_line;
	
	while ((cmd_line = getopt (argc, argv, "hc:")) != -1)
	switch (cmd_line) {
		case 'h':
			printf ("param					description\n");
			printf ("----------------------------------------------------------------------\n");
			printf ("-c [path]				specifies configuration file full path\n");        
			printf ("\n");
			return 0;
			break;
		case 'c':
			config_file = optarg;
			break;
	}
	
	if (NULL == config_file) {
		/* no config file parameters passed, using current directory */
		char cwd[1024];
		if (getcwd(cwd, sizeof(cwd)) != NULL) {
			strcat(cwd, "/sr_config");
			read_vsentry_config(cwd);
		} else
			/* try without current directory */
			read_vsentry_config("sr_config");
	} else
		/* using config file from cmd_line */
		read_vsentry_config(config_file);

	config_params = sr_config_get_param();
	can_args = sr_can_collector_args();

	ret = sr_log_init("[vsentry]", 0);
	if (ret != SR_SUCCESS){
		printf("failed to init sr_log\n");
		return SR_ERROR;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=vsentry engine started",MESSAGE);

#ifdef SUPPORT_REMOTE_SERVER
	ret = sr_log_uploader_init();
	if (ret != SR_SUCCESS){
		printf("failed to init_log_uploader\n");
		return SR_ERROR;
	}
#endif /* SUPPORT_REMOTE_SERVER */

	ret = sr_white_list_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init sr_white_list_init",REASON);
		return SR_ERROR;
	}

	ret = sal_vsentry_fd_open();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed sal_fd_vsentry_open", REASON);
		return SR_ERROR;
	}

#ifdef CONFIG_STAT_ANALYSIS
	ret = sr_stat_analysis_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init sr_stat_analysis_init",REASON);
		return SR_ERROR;
	}
#endif

#ifdef CONFIG_CAN_ML
	ret = sr_ml_can_hash_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init can_ml hash table",REASON);
		return SR_ERROR;
	}
#endif /* CONFIG_CAN_ML */

	ret = sr_info_gather_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init sr_stat_analysis_init",REASON);
		return SR_ERROR;
	}

	ret = sr_white_list_ip_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init sr_white_list_ip_init",REASON);
		return SR_ERROR;
	}

	ret = sr_start_task(SR_ENGINE_TASK, engine_main_loop);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to start engine_main_loop",REASON);
		sr_stop_task(SR_INFO_GATHER_TASK);

		return SR_ERROR;
	}

	ret = sr_msg_alloc_buf(ENG2MOD_BUF, MAX_BUFFER_SIZE);
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init ENG2MOD msg_buf",REASON);
		return SR_ERROR;
	}

	ret = sr_file_hash_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init file_hash",REASON);
		return SR_ERROR;
	}

	ret = sr_create_filter_paths();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init sr_create_fileter_paths",REASON);
		return SR_ERROR;
	}

	sr_db_init();
	sentry_init(sr_config_vsentry_db_cb);
	
#ifdef SUPPORT_REMOTE_SERVER
#ifdef ENBALE_POLICY_UPDATE
	/* enbale automatic policy updates from server */
	sr_static_policy_db_mng_start();
#endif /* ENBALE_POLICY_UPDATE */
#endif /* SUPPORT_REMOTE_SERVER */

	sr_get_command_start();

	strncpy(can_args->can_interface, config_params->can0_interface, CAN_NAME);
	if(config_params->collector_enable){
		ret = sr_start_task(SR_CAN_COLLECT_TASK, can_collector_init);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"%s=failed to start can-bus collector",REASON);
			return SR_ERROR;	
		}	
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
						"%s=can-bus collector - enabled!",MESSAGE);
	} else {
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
						"%s=can-bus collector - disabled!",MESSAGE);
	}
	/* indicate VPI that we are running */
	if (!(f = fopen("/tmp/sec_state", "w"))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to open file /tmp/sec_state",REASON);
		return SR_ERROR;	
	}
	fprintf(f, "on");
	fclose(f);
	
	/* sending config params to kernel */
    msg = (sr_config_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_CONFIG;
		msg->sub_msg.cef_max_rate = config_params->cef_max_rate; 
		msg->sub_msg.def_file_action = config_params->default_file_action;
		msg->sub_msg.def_can_action = config_params->default_can_action;
		msg->sub_msg.def_net_action = config_params->default_net_action;
		sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
	} else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to transfer config info to kernel",REASON);
	while (run) {
		SR_32 input = getchar();

		switch (input) {
			case 'b':
				run = SR_FALSE;
				break;
			case 's':
				sr_msg_print_stat();
				break;
			case 't':
				eng2mod_test();
				break;
#ifdef SR_CAN_DEBUG_PRINT			
			case 'p':
				can_args->can_print = !can_args->can_print;
				printf("\rcan-bus %s prints - %s\n", can_args->can_interface, (can_args->can_print)? "enabled" : "disabled");
				break;
#endif						
			case 'v':
					printf("\navailable space under %s is: %lld bytes\n",CAN_COLLECTOR_DISK,sal_gets_space(CAN_COLLECTOR_DISK));
				break;
#ifdef CONFIG_CAN_ML
			case 'd':
					printf ("printing debug info for ml_can\n");
					sr_ml_can_print_hash();
				break;
			case 'e':
					printf ("Move to WL learn mode \n");
					sr_white_list_set_mode(SR_WL_MODE_LEARN);
				break;
			case 'f':
				printf ("Move to WL prootect mode \n");
				sr_white_list_set_mode(SR_WL_MODE_APPLY);
				break;
			case 'g':
				printf ("Move to WL OFF mode \n");
				sr_white_list_set_mode(SR_WL_MODE_OFF);
				break;
			case 'z':
				printf("print the white list !!!\n");
				//sr_white_list_hash_print();
				sr_white_list_ip_print();
				break;
#endif /* CONFIG_CAN_ML */
		}
	}
	sr_get_command_stop();
#ifdef SUPPORT_REMOTE_SERVER
#ifdef ENBALE_POLICY_UPDATE
	sr_static_policy_db_mng_stop();
#endif /* ENBALE_POLICY_UPDATE */
#endif /* SUPPORT_REMOTE_SERVER */
	sr_stop_task(SR_CAN_COLLECT_TASK);
	sr_stop_task(SR_ENGINE_TASK);
	sentry_stop();
#ifdef CONFIG_STAT_ANALYSIS
	sr_stat_analysis_uninit();
#endif /* CONFIG_STAT_ANALYSIS */
	sr_white_list_uninit();
	sr_white_list_ip_uninit();
#ifdef CONFIG_CAN_ML
	sr_ml_can_hash_deinit();
#endif /* CONFIG_CAN_ML */
	sr_info_gather_uninit();
	sr_file_hash_deinit();
	sr_db_deinit();
	sr_log_uploader_deinit();
	sr_log_deinit();
	sal_vsentry_fd_close();
	return 0;
}
