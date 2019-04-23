#include "sr_types.h"
#include "sr_engine_main.h"
#include "sr_engine_cli.h"
#include "sr_db.h"
#include "sr_db_file.h"
#include "sr_db_ip.h"
#include "sr_db_can.h"
#include "sal_linux.h"
#include "sysrepo_mng.h"
#include "db_tools.h"
#include "sr_white_list.h"
#include "sr_control.h"
#include "sr_config.h"
#include "redis_mng.h"

static int g_fd;
static redisContext *c;

static void engine_status_dump(int fd)
{
	char buf[100];
	SR_32 len, n;

	sprintf(buf, "engine,%s%c", get_engine_state() ? "on" : "off", SR_CLI_END_OF_ENTITY);
	len = strlen(buf);
	if ((n = write(fd, buf, len)) < len) {
                printf("Write to CLI file failed \n");
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=write to cli for file failed.",REASON);
        }       
}

static void cli_print_cb(char *buf) {
	char print_buf[512];
	SR_32 n, rc;
	
	sprintf(print_buf, "%s%c", buf, SR_CLI_END_OF_ENTITY);
	n = strlen(print_buf);
	rc = write(g_fd, print_buf, n);
	if (rc < n) {
                printf("Write in cli print cb failed \n");
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=Write in cli print cb failed.",REASON);
	}
}

void sr_engine_cli_print(SR_32 fd)
{
	char buf[256];
	SR_32 n;

	snprintf(buf, 256, "\nLearning: \n%c:", SR_CLI_END_OF_ENTITY);
	n = strlen(buf);
	if (write(fd, buf, n) < n) {
		printf("Write in cli print failed \n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=Write in cli print failed.",REASON);
	}

	white_list_print_cb_register(cli_print_cb);
	white_list_ip_print_cb_register(cli_print_cb);

	g_fd = fd;
  	sr_white_list_hash_print();
	sprintf(buf, "\n IP Learning:\n%c", SR_CLI_END_OF_ENTITY);
	n = strlen(buf);
	if (write(fd, buf, n) < n) {
		printf("Write in cli print failed \n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=Write in cli print failed.",REASON);
	}
	sr_white_list_ip_print();
	sprintf(buf, "%c", SR_CLI_END_OF_TRANSACTION);
	if (write(fd, buf, 1) < 1) {
		printf("Write in cli print failed, end transaction \n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=Write in cli print failed.",REASON);
	}
	printf("print connection object:\n");
	sr_control_util(SR_CONTROL_PRINT);
}

void sr_engine_cli_load(SR_32 fd)
{
	char buf[2] = {};

	engine_status_dump(fd);
	action_dump(fd);
	file_rule_dump_rules(fd);
	ip_rule_dump_rules(fd);
	can_rule_dump_rules(fd);
	buf[0] = SR_CLI_END_OF_TRANSACTION;
	if (write(fd, buf, 1) < 1) {
		printf("write failed buf\n");
	}
}

static void handle_action(sr_action_record_t *action, SR_32 *status)
{
	printf(">>>>>> Handle action :%s bm:%d log:%d rl bm:%d rl log:%d \n", action->name,
		action->actions_bitmap,
		action->log_target,
		action->rl_actions_bitmap,
		action->rl_log_target);

	*status = SR_SUCCESS;
}

static void handle_net_rule(sr_net_record_t *net_rule, SR_32 *status)
{
	switch (net_rule->net_item.net_item_type) {
		case NET_ITEM_ACTION:
			printf(">>>>>>>>>> Add IP rule rule:%d action:%s \n", net_rule->rulenum, net_rule->net_item.u.action); 
			break;
		case NET_ITEM_SRC_ADDR:
			printf("   >>>>> SRC addr :%s \n", net_rule->net_item.u.src_addr); 
			break;
		case NET_ITEM_DST_ADDR:
			printf("   >>>>>> DST addr :%s \n", net_rule->net_item.u.dst_addr); 
			break;
		case NET_ITEM_PROTO:
			printf("   >>>>>> Proto :%d \n", net_rule->net_item.u.proto); 
			break;
		case NET_ITEM_SRC_PORT:
			printf("   >>>>>>>>> SRC Port :%d \n", net_rule->net_item.u.src_port); 
			break;
		case NET_ITEM_DST_PORT:
			printf("   >>>>>>>>> DST Port :%d \n", net_rule->net_item.u.dst_port); 
			break;
		case NET_ITEM_UP_RL:
			printf("   >>>>>>>>> UP RL :%d \n", net_rule->net_item.u.up_rl); 
			break;
		case NET_ITEM_DOWN_RL:
			printf("   >>>>>>>>> DOWN RL :%d \n", net_rule->net_item.u.up_rl); 
			break;
		case NET_ITEM_PROGRAM:
			printf("   >>>>>>>>> PROGRAM :%s \n", net_rule->net_item.u.program); 
			break;
		case NET_ITEM_USER:
			printf("   >>>>>>>>> USER :%s \n", net_rule->net_item.u.user); 
			break;
		default:
			break;
	}
}

static void handle_can_rule(sr_can_record_t *can_rule, SR_32 *status)
{
	switch (can_rule->can_item.can_item_type) {
		case CAN_ITEM_ACTION:
			printf(">>>>>>>>>> Add CAN rule rule:%d action:%s \n", can_rule->rulenum, can_rule->can_item.u.action); 
			break;
		case CAN_ITEM_MSG_ID:
			printf("   >>>>> MSG ID :%x \n", can_rule->can_item.u.msg_id); 
			break;
		case CAN_ITEM_DIR:
			printf("   >>>>> CAN_ITEM_DIR :%s \n", can_rule->can_item.u.dir); 
			break;
		case CAN_ITEM_INF:
			printf("   >>>>> CAN_ITEM_INF :%s \n", can_rule->can_item.u.inf); 
			break;
		case CAN_ITEM_PROGRAM:
			printf("   >>>>>>>>> PROGRAM :%s \n", can_rule->can_item.u.program); 
			break;
		case CAN_ITEM_USER:
			printf("   >>>>>>>>> USER :%s \n", can_rule->can_item.u.user); 
			break;
		default:
			break;
	}
}

static void handle_file_rule(sr_file_record_t *file_rule, SR_32 *status)
{
	switch (file_rule->file_item.file_item_type) {
		case FILE_ITEM_ACTION:
			printf(">>>>>>>>>> Add FILE rule:%d action:%s \n", file_rule->rulenum, file_rule->file_item.u.action); 
			break;
		case FILE_ITEM_FILENAME:
			printf("   >>>>> FILENAME :%s \n", file_rule->file_item.u.filename); 
			break;
		case FILE_ITEM_PERM:
			printf("   >>>>> PERM :%s \n", file_rule->file_item.u.perm); 
			break;
		case FILE_ITEM_PROGRAM:
			printf("   >>>>>>>>> PROGRAM :%s \n", file_rule->file_item.u.program); 
			break;
		case FILE_ITEM_USER:
			printf("   >>>>>>>>> USER :%s \n", file_rule->file_item.u.user); 
			break;
		default:
			break;
	}
}

static void handle_entity(void *data, redis_entity_type_t type, SR_32 *status)
{
	sr_action_record_t *action;
	sr_net_record_t  *net_rule;
	sr_can_record_t  *can_rule;
	sr_file_record_t  *file_rule;

	*status = SR_SUCCESS;

	switch (type) { 
		case  ENTITY_TYPE_ACTION:
			action = (sr_action_record_t *)data;
#ifdef DEBUG
		 	printf("XXXXXXXXXX handle_entity ACTION name :%s \n", action->name);
#endif
			handle_action(action, status);
			break;
		case  ENTITY_TYPE_IP_RULE:
			net_rule = (sr_net_record_t *)data;
#ifdef DEBUG
		 	printf("XXXXXXXXXX handle_entity IP rule \n");
#endif
			handle_net_rule(net_rule, status);
			break;
		case  ENTITY_TYPE_FILE_RULE:
			file_rule = (sr_file_record_t *)data;
#ifdef DEBUG
		 	printf("XXXXXXXXXX handle_entity FILE rule \n");
#endif
			handle_file_rule(file_rule, status);
			break;
		case  ENTITY_TYPE_CAN_RULE:
			can_rule = (sr_can_record_t *)data;
#ifdef DEBUG
		 	printf("XXXXXXXXXX handle_entity CAN rule \n");
#endif
			handle_can_rule(can_rule, status);
			break;
		default:
			*status = SR_ERROR;
			printf("ERROR: entity UNKOWN type :%d \n", type);
			break;
	}
}

SR_32 sr_engine_cli_commit(SR_32 fd)
{
	SR_32 rc = SR_SUCCESS;

	sr_engine_get_db_lock();
	c = redis_mng_session_start();
        if (!c) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                        "%s=redis session start failed",REASON);
                rc = SR_ERROR;
                goto out;
        }

	if (redis_mng_load_db(c, SR_TRUE, handle_entity) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=exec for all actions failed",REASON);
		rc = SR_ERROR;
		goto out;
	}

out:
	if (c)
		redis_mng_session_end(c);
	sr_engine_get_db_unlock();

	return rc;
}


