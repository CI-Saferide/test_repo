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
#ifdef SR_CLI
#include "sal_cli_interface.h"
#endif
#ifdef CONFIG_IRDETO_INTERFACE
#include "irdeto_unix_interface.h"
#endif
#include "sr_stat_system_policer.h"
#ifdef IRDETO
#include "irdeto_interface.h"
#endif
#include "sr_engine_static_rules.h"

#ifdef BIN_CLS_DB
#include "sr_bin_cls_eng.h"
#endif

#ifdef REDIS_TEST
#include "redis_mng.h"
#endif

static SR_BOOL is_engine_on;

SR_BOOL get_engine_state(void)
{
	return is_engine_on;
}

void set_engine_state(SR_BOOL is_on)
{
	is_engine_on = is_on;
}

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
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=sr_info_gather_loop: no vsentry fd", REASON);
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

static SR_32 handle_mem_opt(cls_file_mem_optimization_t mem_opt)
{
	sr_cls_file_control_set_mem_opt(mem_opt);

 	// Send the memory optimization value to the Kernel
 	if (sr_control_set_mem_opt(mem_opt) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to set memory optimization flag to kernel", REASON);
 		return SR_ERROR;
	}

	return SR_SUCCESS;
}

static SR_32 sr_engine_read_init_values(char *vsentry_config_file)
{
	FILE *f_conf;
	char buf[CONFIG_LINE_BUFFER_SIZE], *param, *value;

	if (!vsentry_config_file || !*vsentry_config_file)
		return SR_SUCCESS;

	if (!(f_conf = fopen(vsentry_config_file, "r"))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to open config file %s",REASON, vsentry_config_file);
		return SR_SUCCESS;
	}

	while (fgets(buf, CONFIG_LINE_BUFFER_SIZE, f_conf)) {
		if (buf[0] == '#')
			continue;
		param = strtok(buf, " ");
		if (!param)
			continue;
		value = strtok(NULL, " \n");
		if (!value)
			continue;
		if (!strcmp(param, "FILE_CLS_MEM_OPTIMIZE")) {
			if (handle_mem_opt(atoi(value)) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to handle memory optimization, value=%s",REASON, value);
				return SR_SUCCESS;
			}
		}
	}

	fclose(f_conf);

	return SR_SUCCESS;
}

SR_32 sr_engine_write_conf(char *param, char *value)
{
	struct config_params_t *config_params;
	FILE *f_conf;

	config_params = sr_config_get_param();
	if (!(f_conf = fopen(config_params->vsentry_config_file, "w"))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to open config file %s",REASON, config_params->vsentry_config_file);
		return SR_ERROR;
	}
	// TODO : Add real logic to this function which overide the file now.
	fprintf(f_conf, "%s %s\n", param, value);

	fclose(f_conf);

	return SR_SUCCESS;
}

static void engine_shutdown(void)
{
	struct config_params_t *config_params;

	config_params = sr_config_get_param();
#ifdef SR_CLI
	sal_cli_interface_uninit();
#endif

#ifdef IRDETO
	irdeto_interface_uninit();
#endif
#ifdef CONFIG_IRDETO_INTERFACE
	irdeto_unix_interface_uninit();
#endif /* CONFIG_IRDETO_INTERFACE */

	if (config_params->remote_server_support_enable) {
		sr_get_command_stop();
	}
	if (config_params->remote_server_support_enable && config_params->policy_update_enable) {
		sr_static_policy_db_mng_stop();
	}

	sr_stop_task(SR_INFO_GATHER_TASK);
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
}

static void sr_engine_pre_stop_cb(void)
{
	sal_vsentry_unlock();
}

static void sr_interrupt_cb(int i)
{
	engine_shutdown();
	exit(0);
}

#ifdef REDIS_TEST
// cb function to load db
static void db_add_rule_or_action(void *rule, SR_8 type, SR_32 *status)
{
	switch (type) {
	case CONFIG_NET_RULE:
		*status = sr_db_ip_rule_add(rule);
		break;
	case CONFIG_FILE_RULE:
		*status = sr_db_file_rule_add(rule);
		break;
	case CONFIG_CAN_RULE:
//		printf("*** DBG *** add can rule\n");
		*status = sr_db_can_rule_add(rule);
		break;
	case CONFIG_TYPE_MAX:
		*status = sr_db_action_update_action(rule);
		break;
	default:
		printf("ERROR: db_add_rule_or_action called with non supported type %d\n", type);
		*status = -1;
		break;
	}
}

static int sr_redis_load(int tcp, int pipeline)
{
	int i;
	can_rule_t can_rule, *can_rule_ptr;
	ip_rule_t net_rule, *net_rule_ptr;
	file_rule_t file_rule, *file_rule_ptr;
	char file[60];
	char perms[4];
	struct timeval t1, t2;
	redisContext *c = redis_mng_session_start(tcp);
	if (c == NULL) {
		printf("ERROR: redis_mng_session_start failed\n");
		redis_mng_session_end(c);
		return -1;
	}
	sr_db_init();

	gettimeofday(&t1,NULL);
	if (redis_mng_load_db(c, pipeline, db_add_rule_or_action)) {
		printf("ERROR: redis_mng_load_db failed\n");
		redis_mng_session_end(c);
		sr_db_deinit();
		return -1;
	}
	gettimeofday(&t2,NULL);
	printf("Load time: %.3fs\n",
			(((((long long)t2.tv_sec)*1000000)+t2.tv_usec) - ((((long long)t1.tv_sec)*1000000)+t1.tv_usec))/1000000.0);

	redis_mng_session_end(c);

	// verify all rules are there (NOTE: every 10th rule was removed)
	for (i = 0; i < 1200; i++) {
		can_rule.rulenum = i;
		can_rule.tuple.id = 1;

		net_rule.rulenum = i;
		net_rule.tuple.id = 1;

		file_rule.rulenum = i;
		file_rule.tuple.id = 1;

		if (i % 10 == 0) { // removed

			if (sr_db_can_rule_get(&can_rule)) {
				printf("ERROR: sr_db_can_rule_get %d exist\n", i);
				sr_db_deinit();
				return -1;
			}

			if (sr_db_ip_rule_get(&net_rule)) {
				printf("ERROR: sr_db_net_rule_get %d exist\n", i);
				sr_db_deinit();
				return -1;
			}

			if (sr_db_file_rule_get(&file_rule)) {
				printf("ERROR: sr_db_file_rule_get %d exist\n", i);
				sr_db_deinit();
				return -1;
			}

		} else { // added
			if (!(can_rule_ptr = sr_db_can_rule_get(&can_rule))) {
				printf("ERROR: sr_db_can_rule_get %d failed\n", i);
				sr_db_deinit();
				return -1;
			}
			// verify CAN params
			if (strcmp(can_rule_ptr->action_name, "log")) {
				printf("ERROR: can rule %d action %s != log\n", i, can_rule_ptr->action_name);
				sr_db_deinit();
				return -1;
			}
			if (can_rule_ptr->tuple.direction != 0) {
				printf("ERROR: can rule %d dir %d != 0\n", i, can_rule_ptr->tuple.direction);
				sr_db_deinit();
				return -1;
			}
			if (strcmp(can_rule_ptr->tuple.interface, "NULL")) {
				printf("ERROR: can rule %d interface %s != NULL\n", i, can_rule_ptr->tuple.interface);
				sr_db_deinit();
				return -1;
			}
			if (can_rule_ptr->tuple.max_rate != 100) {
				printf("ERROR: can rule %d rate %d != 100\n", i, can_rule_ptr->tuple.max_rate);
				sr_db_deinit();
				return -1;
			}
			if (can_rule_ptr->tuple.msg_id != i + 2) {
				printf("ERROR: can rule %d mid %d != %d\n", i, can_rule_ptr->tuple.msg_id, i + 2);
				sr_db_deinit();
				return -1;
			}
			if (strcmp(can_rule_ptr->tuple.program, "NULL")) {
				printf("ERROR: can rule %d prog %s != NULL\n", i, can_rule_ptr->tuple.program);
				sr_db_deinit();
				return -1;
			}
			if (strcmp(can_rule_ptr->tuple.user, "NULL")) {
				printf("ERROR: can rule %d user %s != NULL\n", i, can_rule_ptr->tuple.user);
				sr_db_deinit();
				return -1;
			}

			if (!(net_rule_ptr = sr_db_ip_rule_get(&net_rule))) {
				printf("ERROR: sr_db_ip_rule_get %d failed\n", i);
				sr_db_deinit();
				return -1;
			}
			// verify NET params
			if (strcmp(net_rule_ptr->action_name, "drop_log")) {
				printf("ERROR: can rule %d action %s != log\n", i, net_rule_ptr->action_name);
				sr_db_deinit();
				return -1;
			}
			// addr_lsb = i % 256;
			// mask = (i / 256) * 8;
			// 192.168.2.%d/%d", addr_lsb, 32 - mask);
			if (net_rule_ptr->tuple.dstaddr.s_addr != (192 << 24 | 168 << 16 | 2 << 8 | (i % 256))) {
				printf("ERROR: ip rule %d dst addr %08x != %08x\n", i, net_rule_ptr->tuple.dstaddr.s_addr,
						192 << 24 | 168 << 16 | 2 << 8 | (i % 256));
				sr_db_deinit();
				return -1;
			}
			if (net_rule_ptr->tuple.dstnetmasklen != 32 - ((i / 256) * 8)) {
				printf("ERROR: ip rule %d dst mask len %d != %d\n", i, net_rule_ptr->tuple.dstnetmasklen, 32 - ((i / 256) * 8));
				sr_db_deinit();
				return -1;
			}
			// sprintf(strs.addrs.sa, "192.168.1.%d/%d", addr_lsb, mask);
			if (net_rule_ptr->tuple.srcaddr.s_addr != (192 << 24 | 168 << 16 | 1 << 8 | (i % 256))) {
				printf("ERROR: ip rule %d src addr %08x != %08x\n", i, net_rule_ptr->tuple.srcaddr.s_addr,
						192 << 24 | 168 << 16 | 2 << 8 | (i % 256));
				sr_db_deinit();
				return -1;
			}
			if (net_rule_ptr->tuple.srcnetmasklen != (i / 256) * 8) {
				printf("ERROR: ip rule %d src mask len %d != %d\n", i, net_rule_ptr->tuple.srcnetmasklen, (i / 256) * 8);
				sr_db_deinit();
				return -1;
			}
//			if (i == 1)
//					printf("*** DBG *** GET dp %d, sp %d\n", net_rule_ptr->tuple.dstport, net_rule_ptr->tuple.srcport);
			if (net_rule_ptr->tuple.dstport != i + 3) {
				printf("ERROR: ip rule %d dst port %d != %d\n", i, net_rule_ptr->tuple.dstport, i + 3);
				sr_db_deinit();
				return -1;
			}
			if (net_rule_ptr->tuple.srcport != i + 1) {
				printf("ERROR: ip rule %d src port %d != %d\n", i, net_rule_ptr->tuple.srcport, i + 1);
				sr_db_deinit();
				return -1;
			}
			if (net_rule_ptr->tuple.max_rate != 100) {
				printf("ERROR: ip rule %d rate %d != 100\n", i, net_rule_ptr->tuple.max_rate);
				sr_db_deinit();
				return -1;
			}
			if (strcmp(net_rule_ptr->tuple.program, "NULL")) {
				printf("ERROR: ip rule %d prog %s != NULL\n", i, net_rule_ptr->tuple.program);
				sr_db_deinit();
				return -1;
			}
			if (strcmp(net_rule_ptr->tuple.user, "NULL")) {
				printf("ERROR: ip rule %d user %s != NULL\n", i, net_rule_ptr->tuple.user);
				sr_db_deinit();
				return -1;
			}

			if (!(file_rule_ptr = sr_db_file_rule_get(&file_rule))) {
				printf("ERROR: sr_db_file_rule_get %d failed\n", i);
				sr_db_deinit();
				return -1;
			}
			// verify file params
			if (strcmp(file_rule_ptr->action_name, "drop")) {
				printf("ERROR: file rule %d action %s != drop\n", i, file_rule_ptr->action_name);
				sr_db_deinit();
				return -1;
			}
			sprintf(file, "a_file_path_of_50_chars_length_123456789_0AB____GH");
			sprintf(file + 44, "%04d", i);
			if (strcmp(file_rule_ptr->tuple.filename, file)) {
				printf("ERROR: file rule %d filepath %s != %s\n", i, file_rule_ptr->tuple.filename, file);
				sr_db_deinit();
				return -1;
			}
			file_op_convert((i % 3) ? ((i % 3) == 1 ? SR_FILEOPS_EXEC : SR_FILEOPS_READ) : SR_FILEOPS_WRITE, perms);
			if (strcmp(file_rule_ptr->tuple.permission, perms)) {
				printf("ERROR: file rule %d permission %s != %s\n", i, file_rule_ptr->tuple.permission, perms);
				sr_db_deinit();
				return -1;
			}
			if (file_rule_ptr->tuple.max_rate != 100) {
				printf("ERROR: file rule %d rate %d != 100\n", i, file_rule_ptr->tuple.max_rate);
				sr_db_deinit();
				return -1;
			}
			if (strcmp(file_rule_ptr->tuple.program, "NULL")) {
				printf("ERROR: file rule %d prog %s != NULL\n", i, file_rule_ptr->tuple.program);
				sr_db_deinit();
				return -1;
			}
			if (strcmp(file_rule_ptr->tuple.user, "NULL")) {
				printf("ERROR: file rule %d user %s != NULL\n", i, file_rule_ptr->tuple.user);
				sr_db_deinit();
				return -1;
			}
		}
	}

	sr_db_deinit();
	return 0;
}
// test Redis: connect either by TCP or Unix sockets
static int sr_redis_test(int tcp, int clean_first, int clean_at_end)
{
	SR_32 rc, i, j;
	SR_U8 addr_lsb, mask;
	union {
		char file[64];
		struct {
			char sa[20];
			char da[20];
			char s_port[8];
			char d_port[8];
			char proto[4];
		} addrs;
		char mid[16];
	} strs;

	redisContext *c = redis_mng_session_start(tcp);
	if (c == NULL) {
		printf("ERROR: redis_mng_session_start failed\n");
		redis_mng_session_end(c);
		return -1;
	}

	if (clean_first) { // clean DB
		if (redis_mng_clean_db(c)) {
			printf("ERROR: redis_mng_clean_db failed\n");
			redis_mng_session_end(c);
			return -1;
		}
	}

	// add 1200 file rules
	sprintf(strs.file, "a_file_path_of_50_chars_length_123456789_0AB____GH");
	for (i = 0; i < 1200; i++) {
		sprintf(strs.file + 44, "%04d", i);
		j = i % 3;
		if ((rc = redis_mng_add_file_rule(c, i, strs.file, "NULL", "NULL", "drop",
				j ? (j == 1 ? "R"/*SR_FILEOPS_READ*/ : "W"/*SR_FILEOPS_WRITE*/) : "X"/*SR_FILEOPS_EXEC*/))) {
			printf("ERROR: redis_mng_add_file_rule %d failed, ret %d\n", i, rc);
			redis_mng_session_end(c);
			return -1;
		}
	}
	// add 1200 net rules
	for (i = 0; i < 1200; i++) {
		addr_lsb = i % 256;
		mask = (i / 256) * 8;
		sprintf(strs.addrs.sa, "192.168.1.%d/%d", addr_lsb, mask);
		sprintf(strs.addrs.da, "192.168.2.%d/%d", addr_lsb, 32 - mask);
		sprintf(strs.addrs.proto, "%02d", addr_lsb);
		sprintf(strs.addrs.s_port, "%04d", i);
		sprintf(strs.addrs.d_port, "%04d", i + 3);
//		if (i == 1) {
//			printf("*** DBG *** ADD: d_port %s\n", strs.addrs.d_port);
//			printf("*** DBG *** ADD: s_port %s\n", strs.addrs.s_port);
//		}
		if ((rc = redis_mng_add_net_rule(c, i, strs.addrs.sa, strs.addrs.da, strs.addrs.proto, strs.addrs.s_port,
				strs.addrs.d_port, "NULL", "NULL", "drop_log"))) {
			printf("ERROR: redis_mng_add_net_rule %d failed, ret %d\n", i, rc);
			redis_mng_session_end(c);
			return -1;
		}
	}
	// add 1200 can rules
	for (i = 0; i < 1200; i++) {
		sprintf(strs.mid, "%d", i);
		if ((rc = redis_mng_add_can_rule(c, i, strs.mid, "NULL", "NULL", "NULL", "log", 0))) {
			printf("ERROR: redis_mng_add_can_rule %d failed, ret %d\n", i, rc);
			redis_mng_session_end(c);
			return -1;
		}
	}

	// update all the rules
	for (i = 0; i < 1200; i++) {
		j = i % 3;
		if ((rc = redis_mng_mod_file_rule(c, i, NULL, NULL, NULL, NULL,
				j ? (j == 1 ? "X"/*SR_FILEOPS_EXEC*/ : "R"/*SR_FILEOPS_READ*/) : "W"/*SR_FILEOPS_WRITE*/))) {
			printf("ERROR: redis_mng_modify_file_rule %d failed, ret %d\n", i, rc);
			redis_mng_session_end(c);
			return -1;
		}
		addr_lsb = i % 256;
		mask = (i / 256) * 8;
		sprintf(strs.addrs.s_port, "%04d", i + 1);
		if ((rc = redis_mng_mod_net_rule(c, i, NULL, NULL, NULL, strs.addrs.s_port, NULL, NULL, NULL, NULL))) {
			printf("ERROR: redis_mng_modify_net_rule %d failed, ret %d\n", i, rc);
			redis_mng_session_end(c);
			return -1;
		}
		sprintf(strs.mid, "%d", i + 2);
		if ((rc = redis_mng_mod_can_rule(c, i, strs.mid, NULL, NULL, NULL, NULL, "both"))) {
			printf("ERROR: redis_mng_modify_can_rule %d failed, ret %d\n", i, rc);
			redis_mng_session_end(c);
			return -1;
		}
	}

	// delete 1/10 of the rules
	for (i = 0; i < 1200; i++) {
		if (i % 10 == 0) {
			if ((rc = redis_mng_del_file_rule(c, i))) {
				printf("ERROR: redis_mng_del_file_rule %d failed, ret %d\n", i, rc);
				redis_mng_session_end(c);
				return -1;
			}
			if ((rc = redis_mng_del_net_rule(c, i))) {
				printf("ERROR: redis_mng_del_net_rule %d failed, ret %d\n", i, rc);
				redis_mng_session_end(c);
				return -1;
			}
			if ((rc = redis_mng_del_can_rule(c, i))) {
				printf("ERROR: redis_mng_del_can_rule %d failed, ret %d\n", i, rc);
				redis_mng_session_end(c);
				return -1;
			}
		}
	}

	if (clean_at_end) { // clean DB
		if (redis_mng_clean_db(c)) {
			printf("ERROR: redis_mng_clean_db failed\n");
			redis_mng_session_end(c);
			return -1;
		}
	}
	redis_mng_session_end(c);
	return 0;
}
#endif

SR_32 sr_engine_start(int argc, char *argv[])
{
	SR_32 ret;
	FILE *f;
	sr_config_msg_t *msg;
	struct config_params_t *config_params;
	struct canTaskParams *can_args;
	SR_8 *config_file = NULL;
	SR_32 cmd_line;
	SR_BOOL run = SR_TRUE;
	SR_BOOL background = SR_FALSE;

	sal_set_interrupt_cb(sr_interrupt_cb);

	while ((cmd_line = getopt (argc, argv, "bhc:")) != -1)
	switch (cmd_line) {
		case 'h':
			printf ("param					description\n");
			printf ("----------------------------------------------------------------------\n");
			printf ("-c [path]				specifies configuration file full path\n");        
			printf ("-b 					run in background\n");
			printf ("\n");
			return 0;
			break;
		case 'b':
			background = SR_TRUE;
			break;
		case 'c':
			config_file = optarg;
			break;
	}

	if (background && (daemon(0, 0) < 0)) {
		fprintf(stderr, "failed to run in background .. exiting ...\n");
		exit (-1);
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

	if (config_params->remote_server_support_enable) {
		ret = sr_log_uploader_init();
		if (ret != SR_SUCCESS){
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"%s=failed to init remote services",REASON);
			return SR_ERROR;
		}
	}

	ret = sal_vsentry_fd_open();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to open vsentry fd", REASON);
		return SR_ERROR;
	}

	ret = sr_msg_alloc_buf(ENG2MOD_BUF, MAX_BUFFER_SIZE);
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to init ENG2MOD msg_buf",REASON);
		return SR_ERROR;
	}

	ret = sr_engine_read_init_values(config_params->vsentry_config_file);
	if (ret != SR_SUCCESS){
		printf("failed to read conf  sr_engine\n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=No read conf sr_engine", REASON);
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

	ret = sr_task_set_pre_stop_cb(SR_ENGINE_TASK, sr_engine_pre_stop_cb);
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed setting task pre stop cb",REASON);
		return SR_ERROR;
	}
	ret = sr_start_task(SR_ENGINE_TASK, engine_main_loop);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to start engine_main_loop",REASON);
		sr_stop_task(SR_INFO_GATHER_TASK);

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

#ifdef SR_CLI
	ret = sal_cli_interface_init();
	if (ret != SR_SUCCESS){
	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=failed to init cli interface",REASON);
		return SR_ERROR;
	}
#endif

 	if (create_static_white_list()) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to create Irdeto static white list ",REASON);
		return SR_ERROR;
	}
#ifdef CONFIG_IRDETO_INTERFACE
	ret = irdeto_unix_interface_init();
#endif /* CONFIG_IRDETO_INTERFACE */
#ifdef IRDETO
	ret = irdeto_interface_init();
	if (ret != SR_SUCCESS){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to init irdeto interface",REASON);
		return SR_ERROR;
	}
#endif

#ifdef BIN_CLS_DB
	bin_cls_init();
#endif
#ifdef REDIS_TEST
#define TCP 1
#define PIPELINE 1
	printf("\nRedis start - %s, %s:\n", TCP ? "TCP" : "Unix socket", PIPELINE ? "pipelined" : "non-pipelined");
	// read after boot
	if (sr_redis_load(TCP, PIPELINE))
		printf("*** REDIS LOAD *** failed\n");
	else
		printf("*** REDIS LOAD *** SUCCESS!!!\n");
	// add entries for next boot
	if (sr_redis_test(TCP, 1, 0))
		printf("*** REDIS TEST *** failed\n\n");
	else
		printf("*** REDIS TEST *** SUCCESS!!!\n\n");
#endif

	sr_db_init();
	sentry_init(sr_config_vsentry_db_cb);
	
	/* policy update depends on remote server support */
	if (config_params->remote_server_support_enable && config_params->policy_update_enable) {
		/* enable automatic policy updates from server */
		sr_static_policy_db_mng_start();
	}

	if (config_params->remote_server_support_enable) {
		sr_get_command_start();
	}

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

	/* sending config params to kernel - only after all rules were sent to Kernel*/
	while (sr_config_get_mod_state())
		usleep(10000);
	sleep(3);
	msg = (sr_config_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_CONFIG;
		msg->sub_msg.cef_max_rate = config_params->cef_max_rate; 
		msg->sub_msg.def_file_action = config_params->default_file_action;
#ifdef BIN_CLS_DB
		/* when working with bin cls we need the date to be allowed so
		 * it could get to the bin cls and not dropped by vsentry cls */
		msg->sub_msg.def_can_action = SR_CLS_ACTION_ALLOW;
		msg->sub_msg.def_net_action = SR_CLS_ACTION_ALLOW;
#else
		msg->sub_msg.def_can_action = config_params->default_can_action;
		msg->sub_msg.def_net_action = config_params->default_net_action;
#endif
		msg->sub_msg.system_policer_interval = config_params->system_policer_interval;
		sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
	} else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to transfer config info to kernel",REASON);

	while (run) {
		if (background) {
			sleep (1);
			continue;
		}

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
#endif /* CONFIG_CAN_ML */
			case 'e':
					printf ("Move to WL learn mode \n");
					sr_white_list_set_mode(SR_WL_MODE_LEARN, NULL);
				break;
			case 'f':
				printf ("Move to WL prootect mode \n");
				sr_stat_analysis_learn_mode_set(SR_STAT_MODE_PROTECT);
				//sr_white_list_set_mode(SR_WL_MODE_APPLY, NULL);
				break;
			case 'g':
				printf ("Move to WL OFF mode \n");
				sr_white_list_set_mode(SR_WL_MODE_OFF, NULL);
				break;
			case 'z':
				printf("print the white list !!!\n");
				CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
                        			"%s=print the white list",MESSAGE);
				sr_white_list_hash_print();
				sr_white_list_ip_print();
				//printf("print connection object:\n");
				//CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
				//	"%s=print connection object",MESSAGE);
				//sr_control_util(SR_CONTROL_PRINT);
				break;
#ifdef CONFIG_SYSTEM_POLICER
			case 'y':
				printf("SYSTEM POLICER learn table:\n");
				sr_stat_system_policer_learn_print();
				break;
#endif
#ifdef BIN_CLS_DB
			case 'P':
				cls_print();
				break;

			case 'R':
				bin_cls_reload();
				break;

			case 'E':
				bin_cls_toggle_enable();
				break;

			case 'U':
				bin_cls_update(true);
				break;
#endif
		}
	}

	engine_shutdown();
	return 0;
}
