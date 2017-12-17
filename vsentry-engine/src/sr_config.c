/* sr_config.c */
#include "sr_config.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_cls_port_control.h"
#include "sr_cls_network_control.h"
#include "sr_cls_rules_control.h"
#include "sr_cls_canbus_control.h"
#include "sr_cls_file_control.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_control.h"
//need to move these headers to sal_linux.h
#include <arpa/inet.h>
#include <poll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sr_file_hash.h>
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#include "sr_stat_learn_rule.h"
#ifdef SR_STAT_ANALYSIS_DEBUG
#include <signal.h>
#endif
#endif
#include "sentry.h"
#include "action.h"
#include "ip_rule.h"
#include "file_rule.h"
#include "can_rule.h"
#include "sr_db.h"

#ifdef SR_STAT_ANALYSIS_DEBUG
static void handler(int signal)
{
	switch (signal) { 
		case 10:
			sr_learn_rule_connection_hash_print();
			break;
		case 12:
			//sr_stat_analysis_learn_mode_set(SR_STAT_MODE_PROTECT);
			//sr_stat_analysis_dump();
			//sr_learn_rule_connection_hash_print();
			//sr_control_util(SR_CONTROL_GARBAGE_COLLECTION);
			//sr_control_util(SR_CONTROL_PRINT_CONNECTIONS);
			break;
		default:
			break;
 	}
}
#endif

static char filename[] = "sr_engine.cfg";

static SR_32 handle_engine_start_stop(char *engine)
{
        FILE *f;

	f = fopen("/tmp/sec_state", "w");
	if (!strncmp(engine, SR_DB_ENGINE_START, SR_DB_ENGINE_NAME_SIZE)) {
		sr_control_set_state(SR_TRUE);
		fprintf(f, "on");
	} else if (!strncmp(engine, SR_DB_ENGINE_STOP, SR_DB_ENGINE_NAME_SIZE)) {
		sr_control_set_state(SR_FALSE);
		fprintf(f, "off");
	}
	fclose(f);

	return SR_SUCCESS;
}

static SR_32 handle_action(action_t *action)
{
	action_t *db_action;

	db_action = sr_db_action_get_action(action->action_name);
	if (!db_action) {
		sal_printf("%s action:%s not found\n", __FUNCTION__, action->action_name);
		return SR_ERROR;
	}
	db_action->action = action->action;
	db_action->log_facility = action->log_facility;
	db_action->log_severity = action->log_severity;
	db_action->black_list = action->black_list;
	db_action->terminate = action->terminate;

	return SR_SUCCESS;
}

static SR_32 convert_action(char *action_name, SR_U16 *actions_bitmap)
{
	action_t *db_action;
	
	db_action = sr_db_action_get_action(action_name);
	if (!db_action) {
		sal_printf("%s action:%s not found\n", __FUNCTION__, action_name);
		return SR_ERROR;
	}
	switch (db_action->action) {
                case ACTION_DROP:
                        *actions_bitmap = SR_CLS_ACTION_DROP;
                        break;
                case ACTION_ALLOW:
                        *actions_bitmap = SR_CLS_ACTION_ALLOW;
                        break;
                default:
                        break;
        }
        if (db_action->log_facility != LOG_NONE)
                *actions_bitmap |= SR_CLS_ACTION_LOG;

	return SR_SUCCESS;
}

static SR_32 add_ip_rule(ip_rule_t *rule)
{
	SR_U16 actions_bitmap = 0;
	char *user, *program;

	if (sr_db_ip_rule_add(rule) != SR_SUCCESS) {
		sal_printf("%s sr_db_ip_rule_add: FAILED\n", __FUNCTION__);
		return SR_ERROR;
	}

	if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
		sal_printf("%s convert action: FAILED\n", __FUNCTION__);
		return SR_ERROR;
	}

	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";

	sr_cls_port_add_rule(rule->tuple.srcport, program, user, rule->rulenum, SR_DIR_SRC, rule->tuple.proto);
	sr_cls_port_add_rule(rule->tuple.dstport, program, user, rule->rulenum, SR_DIR_DST, rule->tuple.proto);
	sr_cls_add_ipv4(rule->tuple.srcaddr.s_addr, program, user, rule->tuple.srcnetmask.s_addr, rule->rulenum, SR_DIR_SRC);
	sr_cls_add_ipv4(rule->tuple.dstaddr.s_addr, program, user, rule->tuple.dstnetmask.s_addr, rule->rulenum, SR_DIR_DST);
	sr_cls_rule_add(SR_NET_RULES, rule->rulenum, actions_bitmap, SR_FILEOPS_READ, SR_RATE_TYPE_BYTES, rule->tuple.max_rate, /* net_rule.rate_action */ 0 ,
                         /* net_ruole.action.log_target */ 0 , /* net_rule.tuple.action.email_id */ 0 , /* net_rule.tuple.action.phone_id */ 0 , /* net_rule.action.skip_rulenum */ 0);

	return SR_SUCCESS;
}

static SR_32 update_ip_rule(ip_rule_t *rule)
{
	ip_rule_t *old_rule;
	SR_U16 actions_bitmap = 0;
	char *user, *program, *old_user, *old_program;

	if (!(old_rule = sr_db_ip_rule_get(rule))) {
		sal_printf("%s failed gettig old rule#:%d \n", __FUNCTION__, rule->rulenum);
		return SR_ERROR;
	}
	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";
	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";
	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";

	if (strncmp(rule->action_name, old_rule->action_name, ACTION_STR_SIZE) != 0) {
		if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
			sal_printf("%s convert action: FAILED\n", __FUNCTION__);
			return SR_ERROR;
		}
		sr_cls_rule_add(SR_NET_RULES, rule->rulenum, actions_bitmap, SR_FILEOPS_READ, SR_RATE_TYPE_BYTES, rule->tuple.max_rate, /* net_rule.rate_action */ 0 ,
                         /* net_ruole.action.log_target */ 0 , /* net_rule.tuple.action.email_id */ 0 , /* net_rule.tuple.action.phone_id */ 0 , /* net_rule.action.skip_rulenum */ 0);
		strncpy(old_rule->action_name, rule->action_name, ACTION_STR_SIZE);
	}

	if (old_rule->tuple.srcport != rule->tuple.srcport) {
		sr_cls_port_del_rule(old_rule->tuple.srcport, old_program, old_user, old_rule->rulenum, SR_DIR_SRC, old_rule->tuple.proto);
		sr_cls_port_add_rule(rule->tuple.srcport, program, user, rule->rulenum, SR_DIR_SRC, rule->tuple.proto);
		old_rule->tuple.srcport = rule->tuple.srcport;
	}	
	if (old_rule->tuple.dstport != rule->tuple.dstport) {
		sr_cls_port_del_rule(old_rule->tuple.dstport, old_program, old_user, old_rule->rulenum, SR_DIR_DST, old_rule->tuple.proto);
		sr_cls_port_add_rule(rule->tuple.dstport, program, user, rule->rulenum, SR_DIR_DST, rule->tuple.proto);
		old_rule->tuple.dstport = rule->tuple.dstport;
	}	
	if (old_rule->tuple.srcaddr.s_addr != rule->tuple.srcaddr.s_addr ||
	    old_rule->tuple.srcnetmask.s_addr != old_rule->tuple.srcnetmask.s_addr) {
		sr_cls_del_ipv4(old_rule->tuple.srcaddr.s_addr, old_program, old_user, old_rule->tuple.srcnetmask.s_addr, old_rule->rulenum, SR_DIR_SRC);
		sr_cls_add_ipv4(rule->tuple.srcaddr.s_addr, program, user, rule->tuple.srcnetmask.s_addr, rule->rulenum, SR_DIR_SRC);
		old_rule->tuple.srcaddr.s_addr = rule->tuple.srcaddr.s_addr;
	}	
	if (old_rule->tuple.dstaddr.s_addr != rule->tuple.dstaddr.s_addr ||
	    old_rule->tuple.dstnetmask.s_addr != old_rule->tuple.dstnetmask.s_addr) {
		sr_cls_del_ipv4(old_rule->tuple.dstaddr.s_addr, old_program, old_user, old_rule->tuple.dstnetmask.s_addr, old_rule->rulenum, SR_DIR_DST);
		sr_cls_add_ipv4(rule->tuple.dstaddr.s_addr, program, user, rule->tuple.dstnetmask.s_addr, rule->rulenum, SR_DIR_DST);
		old_rule->tuple.dstaddr.s_addr = rule->tuple.dstaddr.s_addr;
	}	
	if (strncmp(old_program, program, PROG_NAME_SIZE) != 0) {
		sr_cls_port_del_rule(old_rule->tuple.srcport, old_program, old_user, old_rule->rulenum, SR_DIR_SRC, old_rule->tuple.proto);
		sr_cls_port_add_rule(rule->tuple.srcport, program, user, rule->rulenum, SR_DIR_SRC, rule->tuple.proto);
		strncpy(old_rule->tuple.program, rule->tuple.program, PROG_NAME_SIZE);
	}	
	if (strncmp(old_user, user, USER_NAME_SIZE) != 0) {
		sr_cls_port_del_rule(old_rule->tuple.srcport, old_program, old_user, old_rule->rulenum, SR_DIR_SRC, old_rule->tuple.proto);
		sr_cls_port_add_rule(rule->tuple.srcport, program, user, rule->rulenum, SR_DIR_SRC, rule->tuple.proto);
		strncpy(old_rule->tuple.user, rule->tuple.user, USER_NAME_SIZE);
	}	

	return SR_SUCCESS;
}

static SR_32 delete_ip_rule(ip_rule_t *rule)
{
	sr_cls_port_del_rule(rule->tuple.srcport, rule->tuple.program, rule->tuple.user, rule->rulenum, SR_DIR_SRC, rule->tuple.proto);
	sr_cls_port_del_rule(rule->tuple.dstport, rule->tuple.program, rule->tuple.user, rule->rulenum, SR_DIR_DST, rule->tuple.proto);
	sr_cls_del_ipv4(rule->tuple.srcaddr.s_addr, rule->tuple.program, rule->tuple.user, rule->tuple.srcnetmask.s_addr, rule->rulenum, SR_DIR_SRC);
	sr_cls_del_ipv4(rule->tuple.dstaddr.s_addr, rule->tuple.program, rule->tuple.user, rule->tuple.dstnetmask.s_addr, rule->rulenum, SR_DIR_DST);
	sr_db_ip_rule_delete(rule);

	return SR_SUCCESS;
}

#define PERM_R (1 << 2)
#define PERM_W (1 << 1)
#define PERM_X (1 << 0)

static void convert_permissions(char *permissions, SR_U8 *premisions_bitmaps)
{
	SR_U8 perms;
        if (!permissions)
                return;
	
	perms = atoi(permissions + 2);

	*premisions_bitmaps = 0;
 	if (perms & PERM_X)
 		*premisions_bitmaps |= SR_FILEOPS_EXEC;
	if (perms & PERM_W)
		*premisions_bitmaps |= SR_FILEOPS_WRITE;
	if (perms & PERM_R)
		*premisions_bitmaps |= SR_FILEOPS_READ;
}

static SR_32 add_file_rule(file_rule_t *rule)
{
	SR_U16 actions_bitmap = 0;
	SR_U8 permissions = 0;
	char *user, *program;

	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";

	if (sr_db_file_rule_add(rule) != SR_SUCCESS) {
		sal_printf("%s sr_db_file_rule_add: FAILED\n", __FUNCTION__);
		return SR_ERROR;
	}

	if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
		sal_printf("%s convert action: FAILED\n", __FUNCTION__);
		return SR_ERROR;
	}

	convert_permissions(rule->tuple.permission, &permissions);
	sr_cls_file_add_rule(rule->tuple.filename, program, user, rule->rulenum, 1);
	sr_cls_rule_add(SR_FILE_RULES, rule->rulenum, actions_bitmap, permissions, SR_RATE_TYPE_BYTES, rule->tuple.max_rate, /* net_rule.rate_action */ 0 ,
                         /* net_ruole.action.log_target */ 0 , /* net_rule.tuple.action.email_id */ 0 , /* net_rule.tuple.action.phone_id */ 0 , /* net_rule.action.skip_rulenum */ 0);

	return SR_SUCCESS;
}

static SR_32 update_file_rule(file_rule_t *rule)
{
	SR_U16 actions_bitmap = 0;
	SR_U8 permissions = 0;
	file_rule_t *old_rule;
	char *user, *program, *old_user, *old_program;

	if (!(old_rule = sr_db_file_rule_get(rule))) {
		sal_printf("%s failed gettig old rule#:%d \n", __FUNCTION__, rule->rulenum);
		return SR_ERROR;
	}
	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";
	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";
	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";

	sr_cls_file_del_rule(old_rule->tuple.filename, old_program, old_user, rule->rulenum, 1);
	if (strncmp(rule->action_name, old_rule->action_name, ACTION_STR_SIZE) != 0 || 	
		strncmp(rule->tuple.permission, old_rule->tuple.permission, 4) != 0) {
		convert_permissions(rule->tuple.permission, &permissions);
		if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
			sal_printf("%s convert action: FAILED\n", __FUNCTION__);
			return SR_ERROR;
		}
		sr_cls_rule_add(SR_FILE_RULES, rule->rulenum, actions_bitmap, permissions, SR_RATE_TYPE_EVENT, rule->tuple.max_rate, /* net_rule.rate_action */ 0 ,
                         /* net_ruole.action.log_target */ 0 , /* net_rule.tuple.action.email_id */ 0 , /* net_rule.tuple.action.phone_id */ 0 , /* net_rule.action.skip_rulenum */ 0);
		strncpy(old_rule->action_name, rule->action_name, ACTION_STR_SIZE);
		strncpy(old_rule->tuple.permission, rule->tuple.permission, 4);
	}

	strncpy(old_rule->tuple.filename, rule->tuple.filename, FILE_NAME_SIZE);
	strncpy(old_rule->tuple.program, rule->tuple.program, PROG_NAME_SIZE);
	strncpy(old_rule->tuple.user, rule->tuple.user, USER_NAME_SIZE);
	sr_cls_file_add_rule(rule->tuple.filename, program, user, rule->rulenum, 1);

	return SR_SUCCESS;
}

static SR_32 delete_file_rule(file_rule_t *rule)
{
	sr_cls_file_del_rule(rule->tuple.filename, rule->tuple.program, rule->tuple.user, rule->rulenum, 1);
	sr_db_file_rule_delete(rule);

	return SR_SUCCESS;
}

static SR_32 add_can_rule(can_rule_t *rule)
{
	SR_U16 actions_bitmap = 0;
	char *user, *program;

	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";

	if (sr_db_can_rule_add(rule) != SR_SUCCESS) {
		sal_printf("%s sr_db_can_rule_add: FAILED\n", __FUNCTION__);
		return SR_ERROR;
	}

	if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
		sal_printf("%s convert action: FAILED\n", __FUNCTION__);
		return SR_ERROR;
	}

	sr_cls_canid_add_rule(rule->tuple.msg_id, program, user, rule->rulenum);
	sr_cls_rule_add(SR_CAN_RULES, rule->rulenum, actions_bitmap, 0, SR_RATE_TYPE_BYTES, rule->tuple.max_rate, /* net_rule.rate_action */ 0 ,
                         /* net_ruole.action.log_target */ 0 , /* net_rule.tuple.action.email_id */ 0 , /* net_rule.tuple.action.phone_id */ 0 , /* net_rule.action.skip_rulenum */ 0);

	return SR_SUCCESS;
}

static SR_32 update_can_rule(can_rule_t *rule)
{
	SR_U16 actions_bitmap = 0;
	can_rule_t *old_rule;
	char *user, *program, *old_user, *old_program;

	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";

	if (!(old_rule = sr_db_can_rule_get(rule))) {
		sal_printf("%s failed gettig old rule#:%d \n", __FUNCTION__, rule->rulenum);
		return SR_ERROR;
	}
	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";
	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";
	sr_cls_canid_del_rule(old_rule->tuple.msg_id, old_program, old_user, old_rule->rulenum);
	if (strncmp(rule->action_name, old_rule->action_name, ACTION_STR_SIZE)) {
		if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
			sal_printf("%s convert action: FAILED\n", __FUNCTION__);
			return SR_ERROR;
		}
		sr_cls_rule_add(SR_CAN_RULES, rule->rulenum, actions_bitmap, 0, SR_RATE_TYPE_EVENT, rule->tuple.max_rate, /* net_rule.rate_action */ 0 ,
                         /* net_ruole.action.log_target */ 0 , /* net_rule.tuple.action.email_id */ 0 , /* net_rule.tuple.action.phone_id */ 0 , /* net_rule.action.skip_rulenum */ 0);
		strncpy(old_rule->action_name, rule->action_name, ACTION_STR_SIZE);
	}

	old_rule->tuple.msg_id = rule->tuple.msg_id;
	old_rule->tuple.direction = rule->tuple.direction;
	strncpy(old_rule->tuple.program, rule->tuple.program, PROG_NAME_SIZE);
	strncpy(old_rule->tuple.user, rule->tuple.user, USER_NAME_SIZE);
	sr_cls_canid_add_rule(rule->tuple.msg_id, program, user, rule->rulenum);

	return SR_SUCCESS;
}

static SR_32 delete_can_rule(can_rule_t *rule)
{
	sr_cls_canid_del_rule(rule->tuple.msg_id, rule->tuple.program, rule->tuple.user, rule->rulenum);
	sr_db_can_rule_delete(rule);

	return SR_SUCCESS;
}

void sr_config_vsentry_db_cb(int type, int op, void *entry)
{
	switch (type) {
		case SENTRY_ENTRY_ACTION:
			handle_action((action_t *)entry);
			break;
		case SENTRY_ENTRY_IP:
			ip_rule_display((ip_rule_t *)entry);
			switch (op) {
				case SENTRY_OP_CREATE:
					add_ip_rule((ip_rule_t *)entry);
					break;
				case SENTRY_OP_MODIFY:
					update_ip_rule((ip_rule_t *)entry);
        				break;
				case SENTRY_OP_DELETE:
					delete_ip_rule((ip_rule_t *)entry);
        				break;
				default:
					break;
			}
        		break;
		case SENTRY_ENTRY_CAN:
			can_rule_display((can_rule_t *)entry);
			switch (op) {
				case SENTRY_OP_CREATE:
					add_can_rule((can_rule_t *)entry);
					break;
				case SENTRY_OP_MODIFY:
					update_can_rule((can_rule_t *)entry);
        				break;
				case SENTRY_OP_DELETE:
					delete_can_rule((can_rule_t *)entry);
        				break;
				default:
					break;
			}
			break;
		case SENTRY_ENTRY_FILE:
			file_rule_display((file_rule_t *)entry);
			switch (op) {
				case SENTRY_OP_CREATE:
					add_file_rule((file_rule_t *)entry);
					break;
				case SENTRY_OP_MODIFY:
					update_file_rule((file_rule_t *)entry);
        				break;
				case SENTRY_OP_DELETE:
					delete_file_rule((file_rule_t *)entry);
        				break;
				default:
					break;
			}
			break;
		case SENTRY_ENTRY_ENG:
			handle_engine_start_stop((char *)entry);
			break;
		default:
			break;
	}
}


SR_BOOL write_config_record (void* ptr, enum sr_header_type rec_type)
{
	FILE* 					conf_file;
	conf_file = fopen(filename,"ab");
	switch (rec_type) {
	case CONFIG_NET_RULE: {
		struct sr_net_record	net_rec;
		struct sr_net_entry*	net_entry;
		memcpy(&net_rec, ptr, sizeof(net_rec));
		net_entry = (struct sr_net_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&net_rec, 1, sizeof(net_rec),conf_file);
		fwrite(net_entry->process, net_entry->process_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_FILE_RULE: {
		struct sr_file_record	file_rec;
		struct sr_file_entry*	file_entry;
		memcpy(&file_rec, ptr, sizeof(file_rec));
		file_entry = (struct sr_file_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&file_rec, 1, sizeof(file_rec),conf_file);
		fwrite(file_entry->process, file_entry->process_size, sizeof(SR_8),conf_file);
		fwrite(file_entry->filename, file_entry->filename_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_CAN_RULE: {
		struct sr_can_record		can_rec;
		struct sr_can_entry*		can_entry;
		memcpy(&can_rec, ptr, sizeof(can_rec));
		can_entry = (struct sr_can_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&can_rec, 1, sizeof(can_rec),conf_file);
		fwrite(can_entry->process, can_entry->process_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_PHONE_ENTRY: {
		struct sr_phone_record*	phone_entry;
		phone_entry = (struct sr_phone_record*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(phone_entry, 1, sizeof(struct sr_phone_record),conf_file);
		break;
		}
	case CONFIG_EMAIL_ENTRY: {
		struct sr_email_record		email_rec;
		struct sr_email_entry*		email_entry;
		memcpy(&email_rec, ptr, sizeof(email_rec));
		email_entry = (struct sr_email_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&email_rec, 1, sizeof(email_rec),conf_file);
		fwrite(email_entry->email, email_entry->email_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_LOG_TARGET: {
		struct sr_log_record		log_rec;
		struct sr_log_entry*		log_entry;
		memcpy(&log_rec, ptr, sizeof(log_rec));
		log_entry = (struct sr_log_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&log_rec, 1, sizeof(log_rec),conf_file);
		fwrite(log_entry->log_target, log_entry->log_size, sizeof(SR_8),conf_file);
		break;
		}
	default:
		fclose (conf_file);
		return SR_FALSE;
		break;
	};
	
	fclose (conf_file);
	return SR_TRUE;
}

SR_BOOL read_config_file (void)
{
	FILE* 					conf_file;
	char					process[4096];
	enum sr_header_type		rec_type;
	conf_file = fopen(filename,"rb");
	
	if (!conf_file) {
		return SR_TRUE;
	}

	while (!feof(conf_file)) {
		if (1 != fread(&rec_type, sizeof(rec_type), 1, conf_file)) {
				fclose (conf_file);
				return SR_FALSE;
			}
		switch (rec_type) {
		case CONFIG_NET_RULE: {
			struct sr_net_record	net_rec;
			if (1 != fread(&net_rec, sizeof(net_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			if (net_rec.process_size != fread(&process, sizeof(SR_8), net_rec.process_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_port_add_rule(net_rec.src_port, process, "*", net_rec.rulenum, SR_DIR_SRC, net_rec.proto);
			sr_cls_port_add_rule(net_rec.dst_port, process, "*", net_rec.rulenum, SR_DIR_DST, net_rec.proto);
			sr_cls_add_ipv4(htonl(net_rec.src_addr), process, "*", htonl(net_rec.src_netmask), net_rec.rulenum, SR_DIR_SRC);
			sr_cls_add_ipv4(htonl(net_rec.dst_addr), process, "*", htonl(net_rec.dst_netmask), net_rec.rulenum, SR_DIR_DST);
			sr_cls_rule_add(SR_NET_RULES, net_rec.rulenum, net_rec.action.actions_bitmap, 0, SR_RATE_TYPE_EVENT, net_rec.max_rate, net_rec.rate_action, net_rec.action.log_target, net_rec.action.email_id, net_rec.action.phone_id, net_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_FILE_RULE: {
			struct sr_file_record	file_rec;
			char					filename[4096];
			if (1 != fread(&file_rec, sizeof(file_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			memset(filename, 0, 4096);
			if (file_rec.process_size != fread(&process, sizeof(SR_8), file_rec.process_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			if (file_rec.filename_size != fread(&filename, sizeof(SR_8), file_rec.filename_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_file_add_rule(filename, process, "*", file_rec.rulenum, 1);
			sr_cls_rule_add(SR_FILE_RULES, file_rec.rulenum, file_rec.action.actions_bitmap, SR_FILEOPS_READ, SR_RATE_TYPE_EVENT, file_rec.max_rate, file_rec.rate_action, file_rec.action.log_target, file_rec.action.email_id, file_rec.action.phone_id, file_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_CAN_RULE: {
			struct sr_can_record	can_rec;
			if (1 != fread(&can_rec, sizeof(can_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			if (can_rec.process_size != fread(&process, sizeof(SR_8), can_rec.process_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_canid_add_rule(can_rec.msg_id, process, "*", can_rec.rulenum);
			sr_cls_rule_add(SR_CAN_RULES, can_rec.rulenum, can_rec.action.actions_bitmap, 0, SR_RATE_TYPE_EVENT, can_rec.max_rate, can_rec.rate_action, can_rec.action.log_target, can_rec.action.email_id, can_rec.action.phone_id, can_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_PHONE_ENTRY: {
			struct sr_phone_record	phone_rec;
			if (1 != fread(&phone_rec, sizeof(phone_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			printf ("msg type = phone entry\n");
			printf ("phone_id = %d\n", phone_rec.phone_id);
			printf ("phone_number = %s\n", phone_rec.phone_number);
			break;
			}
		case CONFIG_EMAIL_ENTRY: {
			struct sr_email_record	email_rec;
			char					email[256];
			if (1 != fread(&email_rec, sizeof(email_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(email, 0, 256);
			if (email_rec.email_size != fread(&email, sizeof(SR_8), email_rec.email_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			printf ("msg type = email entry\n");
			printf ("email_id = %d\n", email_rec.email_id);
			printf ("email = %s\n", email);
			break;
			}
		case CONFIG_LOG_TARGET: {
			struct sr_log_record	log_rec;
			char					log_target[256];
			if (1 != fread(&log_rec, sizeof(log_rec), 1, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(log_target, 0, 256);
			if (log_rec.log_size != fread(&log_target, sizeof(SR_8), log_rec.log_size, conf_file)) {
				sal_printf("fail to read from config file, line %d\n", __LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			printf ("msg type = log target\n");
			printf ("log_id = %d\n", log_rec.log_id);
			printf ("log target = %s\n", log_target);
			break;
			}
		default:
			fclose (conf_file);
			return SR_FALSE;
			break;
		};
	} /* end of configuration file reached */

	fclose (conf_file);
	return SR_TRUE;
}

#ifdef UNIT_TEST
SR_U32 handle_rule_ut(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U16 actions, SR_8 file_ops)
{
	printf("**** handle_rule file:%s rule#%d exec:%s user:%s actions:%x file_ops:%x \n", 
		filename, rulenum, exec, user, actions, file_ops);

 	return SR_SUCCESS;
}
#endif

SR_U32 sr_create_filter_paths(void)
{
	sal_os_t os;
	
	if (sal_get_os(&os) != SR_SUCCESS) {
		sal_printf("%s failed sal_get_os\n");
		return SR_ERROR;
	}

	switch (os) { 
		case SAL_OS_LINUX_UBUNTU:
			sr_cls_file_add_remove_filter_path("/var/log/psad", SR_TRUE);
			break;
		default:
			break;
	}

	return SR_SUCCESS;
}

#ifdef UNIT_TEST
static void file_hash_ut(void)
{
 	SR_32 rc;

	printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXX file hash ut \n");
	rc =  sr_file_hash_update_rule("/var/log/arik", "*", "*", 1,  1, 2);
	printf("Insert /var/log/arik rc:%d \n", rc);
	rc =  sr_file_hash_update_rule("/var/log/kuku", "*", "*", 1,  1, 2);
	printf("Insert /var/log/arik rc:%d \n", rc);
	rc =  sr_file_hash_update_rule("/var/log/arik", "*", "*", 2,  1, 2);
	printf("Insert /var/log/arik rc:%d \n", rc);
	rc =  sr_file_hash_update_rule("/var/log/arik", "lulu", "pupu", 3,  4, 5);
	printf("Insert /var/log/arik rc:%d \n", rc);
	rc =  sr_file_hash_update_rule("/var/gol/ukuk", "*", "*", 1,  1, 2);
	printf("Insert /var/log/arik rc:%d \n", rc);
	sr_file_hash_print();

	rc = sr_file_hash_exec_for_file("/var/log/arik", handle_rule_ut);
	printf("--- after Get /var/log/arik file rc%d ...\n", rc);

	rc = sr_file_hash_delete_all();
        printf("After delete_all rc:%d \n", rc);
        sr_file_hash_print();
	
	printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX END file hash ut \n");
}
#endif	

SR_BOOL config_ut(void)
{
	//struct sr_file_entry		file_rec = {0};
	//struct sr_net_entry			net_rec = {0};
	struct sr_can_entry			can_rec = {0};
#if 0
	struct sr_phone_record		phone_rec = {0};
	struct sr_email_entry		email_rec = {0};
	struct sr_log_entry			log_rec = {0};
#endif

#ifdef SR_STAT_ANALYSIS_DEBUG
	signal(10, handler);
	signal(12, handler);
#endif

#if 0
	sr_stat_learn_rule_ut();

	net_rec.rulenum = 80;
	net_rec.src_addr = 0x0a0a0a00;
	net_rec.src_netmask = 0x0;
	//net_rec.src_netmask = 0xFFFFFFFF;
	net_rec.dst_addr = 0x0a0a0a00;
	net_rec.dst_netmask = 0xFFFFFFFF;
	net_rec.dst_netmask = 0x0;
	net_rec.action.actions_bitmap = SR_CLS_ACTION_DROP;
	net_rec.action.email_id = 7;
	net_rec.src_port = 0;
	net_rec.dst_port = 22;
	net_rec.proto = SR_PROTO_TCP;
	net_rec.action.log_target = 8;
	net_rec.action.phone_id = 4;
	//net_rec.action.skip_rulenum = 258;
        //net_rec.uid = 13579;
	strncpy(net_rec.process, "/home/arik/arik/client", strlen("/home/arik/arik/client"));
	//strncpy(net_rec.process, "*", strlen("*"));
	net_rec.process_size = strlen(net_rec.process);
	write_config_record(&net_rec, CONFIG_NET_RULE);

	//sr_stat_analysis_ut();

	net_rec.rulenum = 85;
	net_rec.src_addr = 0xc0a8020d;
	net_rec.src_netmask = 0xFFFFFFFF;
	net_rec.dst_addr = 0xc0a80114;
	net_rec.dst_netmask = 0xFFFFFFFF;
	net_rec.action.actions_bitmap = SR_CLS_ACTION_DROP;
	net_rec.action.email_id = 7;
	net_rec.src_port = 0;
	net_rec.dst_port = 22;
	net_rec.proto = SR_PROTO_TCP;
	net_rec.action.log_target = 8;
	net_rec.action.phone_id = 4;
	//net_rec.action.skip_rulenum = 258;
        //net_rec.uid = 13579;
	strncpy(net_rec.process, "/home/arik/arik/server", strlen("/home/arik/arik/server"));
	//strncpy(net_rec.process, "*", strlen("*"));
	net_rec.process_size = strlen(net_rec.process);
	write_config_record(&net_rec, CONFIG_NET_RULE);
	
	file_rec.rulenum=457;	
	file_rec.action.actions_bitmap=SR_CLS_ACTION_DROP;		
	file_rec.uid=-1;
	strncpy(file_rec.filename, "/home/arik/arik/log", strlen("/home/arik/arik/log"));
	strncpy(file_rec.process, "/bin/cat", strlen("/bin/cat"));
	file_rec.process_size = strlen(file_rec.process);
	file_rec.filename_size = strlen(file_rec.filename);
	write_config_record(&file_rec, CONFIG_FILE_RULE);

	file_rec.rulenum=404;	
	file_rec.action.actions_bitmap=SR_CLS_ACTION_DROP;		
	file_rec.uid=-1;
	strncpy(file_rec.filename, "/home/arik/arik/log1", strlen("/home/arik/arik/log1"));
	//strncpy(file_rec.process, "/bin/cat", strlen("/bin/cat"));
	strncpy(file_rec.process, "*", strlen("*"));
	file_rec.process_size = strlen(file_rec.process);
	file_rec.filename_size = strlen(file_rec.filename);
	write_config_record(&file_rec, CONFIG_FILE_RULE);
		
#endif
	can_rec.rulenum=40;	
	can_rec.msg_id=0x123;		
	can_rec.action.actions_bitmap=SR_CLS_ACTION_DROP;	
	can_rec.uid=20;
	strncpy(can_rec.process, "/usr/bin/cansend", strlen("/usr/bin/cansend"));
	//strncpy(can_rec.process, "*", strlen("*"));
	can_rec.process_size = strlen(can_rec.process);
	write_config_record(&can_rec, CONFIG_CAN_RULE);

/*
	//phone_rec.phone_id=17;
	//strncpy(phone_rec.phone_number, "054-7653982", strlen("054-7653982"));
	//write_config_record(&phone_rec, CONFIG_PHONE_ENTRY);

	//email_rec.email_id=38;
	//strncpy(email_rec.email, "shayd@saferide.io", strlen("shayd@saferide.io"));
	//email_rec.email_size = strlen(email_rec.email);
	//write_config_record(&email_rec, CONFIG_EMAIL_ENTRY);
	
	//log_rec.log_id=19;
	//strncpy(log_rec.log_target, "/var/log/syslog", strlen("/var/log/syslog"));
	//log_rec.log_size = strlen(log_rec.log_target);
	//write_config_record(&log_rec, CONFIG_LOG_TARGET);
*/


	//file_hash_ut();
	read_config_file();

	return SR_TRUE;
}
