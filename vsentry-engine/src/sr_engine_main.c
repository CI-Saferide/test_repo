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
	
	sr_cls_add_ipv4(htonl(0x0a0a0a00), htonl(0xFFFFFF00), 50, SR_DIR_SRC);
	sr_cls_port_add_rule(22, 50, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x0a0a0a00), htonl(0xFFFFFF00), 60, SR_DIR_SRC);
	sr_cls_port_add_rule(24, 60, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x709), htonl(0xFFFFFFFF), 70, SR_DIR_SRC);
	sr_cls_port_add_rule(22, 70, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x0a0a0a2e), htonl(0xFFFFFFFF), 80, SR_DIR_SRC);
	sr_cls_port_add_rule(22, 80, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x555), htonl(0xFFFFFFFF), 90, SR_DIR_SRC);
	sr_cls_port_add_rule(555, 90, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x0a000000), htonl(0xFF000000), 100, SR_DIR_SRC);
	sr_cls_port_add_rule(22, 100, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x00000000), htonl(0x00000000), 110, SR_DIR_SRC);
	sr_cls_add_ipv4(htonl(0x0a0a0a32), htonl(0xFFFFFFFF), 110, SR_DIR_DST);
	sr_cls_port_add_rule(0, 110, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_port_add_rule(22, 110, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_port_add_rule(23, 110, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_port_add_rule(24, 110, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_port_add_rule(25, 110, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_port_add_rule(26, 110, SR_DIR_SRC, IPPROTO_TCP);

	sr_cls_rule_add(_SR_NET_RULES, 50, _SR_ACTION_ALLOW, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_NET_RULES, 60, _SR_ACTION_ALLOW, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_NET_RULES, 70, _SR_ACTION_ALLOW, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_NET_RULES, 80, _SR_ACTION_ALLOW|_SR_ACTION_LOG, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_NET_RULES, 90, _SR_ACTION_ALLOW, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_NET_RULES, 100, _SR_ACTION_DROP, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_NET_RULES, 110, _SR_ACTION_DROP, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);	


	sr_cls_canid_add_rule(0x107,10);
	sr_cls_canid_add_rule(0x116,11);
	sr_cls_canid_add_rule(0x30b,12);
	sr_cls_canid_add_rule(0x31b,13);
	sr_cls_canid_add_rule(0x3c0,14);
	sr_cls_canid_add_rule(0x3da,15);
	sr_cls_canid_add_rule(0x101,16);

	sr_cls_rule_add(_SR_CAN_RULES, 10, _SR_ACTION_DROP, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_CAN_RULES, 11, _SR_ACTION_DROP, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_CAN_RULES, 15, _SR_ACTION_ALLOW|_SR_ACTION_LOG, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_CAN_RULES, 16, _SR_ACTION_DROP, 0, 0, _SR_ACTION_DROP, 0, 0, 0, 0);

	//sr_cls_inode_add_rule(1603491, 1); // /templab/file1
	//sr_cls_inode_add_rule(1605650, 2); // /templab/dir2
	//sr_cls_inode_add_rule(1605649, 3); // /templab/dir1
	//sr_cls_inode_add_rule(1603488, 4); // /templab
	
	//sr_cls_file_add_rule("/sbin", 1, 1);
	sr_cls_file_add_rule("/home/artur/Downloads", 2, 1);
	//sr_cls_file_add_rule("/proc", 3, 1);
	//sr_cls_file_add_rule("/var", 4, 1);	
	
	sr_cls_rule_add(_SR_FILE_RULES, 1, _SR_ACTION_ALLOW, _SR_FILEOPS_READ,0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_FILE_RULES, 2, _SR_ACTION_DROP, _SR_FILEOPS_READ,0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_FILE_RULES, 3, _SR_ACTION_ALLOW, _SR_FILEOPS_WRITE|_SR_FILEOPS_READ,0, _SR_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(_SR_FILE_RULES, 4, _SR_ACTION_DROP, _SR_FILEOPS_WRITE|_SR_FILEOPS_READ,0, _SR_ACTION_DROP, 0, 0, 0, 0);

	/* hardcoded configuration */
	//sr_cls_file_add_rule("/templab/file1", 1, 1);
	//sr_cls_file_add_rule("/templab/dir2", 2, 1);
	//sr_cls_file_add_rule("/templab/dir1", 3, 1);
	//sr_cls_file_add_rule("/templab", 4, 1);
//#if 0
	//sr_cls_file_add_rule("/sbin", 1, 1);
	//sr_cls_file_add_rule("/bin", 2, 1);
	//sr_cls_file_add_rule("/proc", 3, 1);
	//sr_cls_file_add_rule("/var", 4, 1);
//#endif

	//sr_cls_inode_add_rule(1603491, 1); // /templab/file1
	//sr_cls_inode_add_rule(1605650, 2); // /templab/dir2
	//sr_cls_inode_add_rule(1605649, 3); // /templab/dir1
	//sr_cls_inode_add_rule(1603488, 4); // /templab
	
	
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
