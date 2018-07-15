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
#include "jsmn.h"
#include <sysrepo.h>
#include "sr_static_policy.h"

#ifdef SR_STAT_ANALYSIS_DEBUG
static int help;

static void handler(int signal)
{
	switch (signal) { 
		case 10:
			sr_learn_rule_connection_hash_print();
			break;
		case 12:
			printf("XXXXXXXXXXXXXX SIGNAL 12 help:%d ", help);
			if ((help & 1) == 0) { 
				printf("PROTECT !!!\n");
				sr_stat_analysis_learn_mode_set(SR_STAT_MODE_PROTECT);
			} else {
				printf("LEARN !!!\n");
				sr_stat_analysis_learn_mode_set(SR_STAT_MODE_LEARN);
			}
			help++;
			//sr_stat_analysis_dump();
			//sr_learn_rule_connection_hash_print();
			//sr_control_util(SR_CONTROL_GARBAGE_COLLECTION);
			//sr_control_util(SR_CONTROL_PRINT_CONNECTIONS);
			//sr_static_policy_db_ready();
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

	usleep(500000);
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
	if (sr_db_action_update_action(action) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=handle action failed act=%s",REASON,
			action->action_name);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

/* XXX TODO - currently on;ly delete action from DB, shoudl also handle rules with this action */
static SR_32 delete_action(action_t *action)
{
	if (sr_db_action_delete_action(action) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
			"%s=delete action failed act=%s",REASON,
			action->action_name);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

static SR_32 convert_action(char *action_name, SR_U16 *actions_bitmap)
{
	action_t *db_action;
	
	db_action = sr_db_action_get_action(action_name);
	if (!db_action) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=convert act not found act=%s",REASON,
			db_action->action_name);
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
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add ip rule failed ad to db",REASON);
		return SR_ERROR;
	}

	if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add ip rule convert action failed",REASON);
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
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=update ip rule failed gettig old %s=%d",REASON,
			RULE_NUM_KEY,rule->rulenum);
		return SR_ERROR;
	}
	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";
	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";
	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";

	if (strncmp(rule->action_name, old_rule->action_name, ACTION_STR_SIZE) != 0) {
		if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=update ip rule convert_action failed",REASON);
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
	    old_rule->tuple.srcnetmask.s_addr != rule->tuple.srcnetmask.s_addr) {
		sr_cls_del_ipv4(old_rule->tuple.srcaddr.s_addr, old_program, old_user, old_rule->tuple.srcnetmask.s_addr, old_rule->rulenum, SR_DIR_SRC);
		sr_cls_add_ipv4(rule->tuple.srcaddr.s_addr, program, user, rule->tuple.srcnetmask.s_addr, rule->rulenum, SR_DIR_SRC);
		old_rule->tuple.srcaddr.s_addr = rule->tuple.srcaddr.s_addr;
	}	
	if (old_rule->tuple.dstaddr.s_addr != rule->tuple.dstaddr.s_addr ||
	    old_rule->tuple.dstnetmask.s_addr != rule->tuple.dstnetmask.s_addr) {
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
	ip_rule_t *old_rule;
	char *old_user, *old_program;

	if (!(old_rule = sr_db_ip_rule_get(rule))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=delete ip rule db get rule failed gettig old %s=%d",REASON,
			RULE_NUM_KEY,rule->rulenum);
		return SR_SUCCESS;
	}

	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";
	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";

	sr_cls_port_del_rule(old_rule->tuple.srcport, old_program, old_user, old_rule->rulenum, SR_DIR_SRC, old_rule->tuple.proto);
	sr_cls_port_del_rule(old_rule->tuple.dstport, old_program, old_user, old_rule->rulenum, SR_DIR_DST, old_rule->tuple.proto);
	sr_cls_del_ipv4(old_rule->tuple.srcaddr.s_addr, old_program, old_user, old_rule->tuple.srcnetmask.s_addr, old_rule->rulenum, SR_DIR_SRC);
	sr_cls_del_ipv4(old_rule->tuple.dstaddr.s_addr, old_program, old_user, old_rule->tuple.dstnetmask.s_addr, old_rule->rulenum, SR_DIR_DST);
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
	
	perms = (SR_U8)atoi(permissions + 2);

	*premisions_bitmaps ^= *premisions_bitmaps;
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
	SR_U8 permissions = (SR_U8)0;
	char *user, *program;

	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";

	if (sr_db_file_rule_add(rule) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add file rule db add rule failed",REASON);
		return SR_ERROR;
	}

	if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add file rule convert_action failed",REASON);
		return SR_ERROR;
	}

	convert_permissions(rule->tuple.permission, &permissions);
	sr_cls_file_add_rule(rule->tuple.filename, program, user, rule->rulenum, (SR_U8)1);
	sr_cls_rule_add(SR_FILE_RULES, rule->rulenum, actions_bitmap, permissions, SR_RATE_TYPE_BYTES, rule->tuple.max_rate, /* net_rule.rate_action */ 0 ,
                         /* net_ruole.action.log_target */ 0 , /* net_rule.tuple.action.email_id */ 0 , /* net_rule.tuple.action.phone_id */ 0 , /* net_rule.action.skip_rulenum */ 0);

	return SR_SUCCESS;
}

static SR_32 update_file_rule(file_rule_t *rule)
{
	SR_U16 actions_bitmap = 0;
	SR_U8 permissions = (SR_U8)0;
	file_rule_t *old_rule;
	char *user, *program, *old_user, *old_program;

	if (!(old_rule = sr_db_file_rule_get(rule))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=update file rule failed gettig old %s=%d",REASON,
			RULE_NUM_KEY,rule->rulenum);
		return SR_ERROR;
	}
	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";
	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";
	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";

	sr_cls_file_del_rule(old_rule->tuple.filename, old_program, old_user, rule->rulenum, (SR_U8)1);
	if (strncmp(rule->action_name, old_rule->action_name, ACTION_STR_SIZE) != 0 || 	
		strncmp(rule->tuple.permission, old_rule->tuple.permission, 4) != 0) {
		convert_permissions(rule->tuple.permission, &permissions);
		if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=update file rule: convert action failed",REASON);
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
	sr_cls_file_add_rule(rule->tuple.filename, program, user, rule->rulenum, (SR_U8)1);

	return SR_SUCCESS;
}

static SR_32 delete_file_rule(file_rule_t *rule)
{
	file_rule_t *old_rule;

	if (!(old_rule = sr_db_file_rule_get(rule))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=delete file rule: failed gettig old %s=%d",REASON,
			rule->rulenum);
		return SR_SUCCESS;
	}

	sr_cls_file_del_rule(old_rule->tuple.filename, *(old_rule->tuple.program) ? old_rule->tuple.program : "*",
		*(old_rule->tuple.user) ? old_rule->tuple.user : "*", old_rule->rulenum, (SR_U8)1);
	sr_db_file_rule_delete(rule);

	return SR_SUCCESS;
}

static SR_U8 convert_can_dir(SR_U8 dir)
{
	switch (dir) { 
		case SENTRY_DIR_IN:
			return SR_CAN_IN;
		case SENTRY_DIR_OUT:
			return SR_CAN_OUT;
		case SENTRY_DIR_BOTH:
			return SR_CAN_BOTH;
		default:
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=Invalid CAN direction:%d",REASON,
				dir);
			break;
	}
	return SR_CAN_BOTH;
}

static SR_32 add_can_rule(can_rule_t *rule)
{
	SR_U16 actions_bitmap = 0;
	char *user, *program;

	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";

	if (sr_db_can_rule_add(rule) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add can rule: add to db failed",REASON);
		return SR_ERROR;
	}

	if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add can rule: convert to action failed",REASON);
		return SR_ERROR;
	}

	sr_cls_canid_add_rule(rule->tuple.msg_id, program, user, rule->rulenum, convert_can_dir(rule->tuple.direction));
	sr_cls_rule_add(SR_CAN_RULES,
					rule->rulenum,
					actions_bitmap, 
					SR_FILEOPS_READ, 
					SR_RATE_TYPE_EVENT, 
					rule->tuple.max_rate, 
					(SR_U16)0 /* net_rule.rate_action */ ,
					(SR_U16)0 /* net_ruole.action.log_target */,
					(SR_U16)0 /* net_rule.tuple.action.email_id */,
					(SR_U16)0 /* net_rule.tuple.action.phone_id */,
					(SR_U16)0/* net_rule.action.skip_rulenum */);

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
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=update can rule: add to db failed",REASON);
		return SR_ERROR;
	}
	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";
	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";
	sr_cls_canid_del_rule(old_rule->tuple.msg_id, old_program, old_user, old_rule->rulenum, convert_can_dir(old_rule->tuple.direction));
	if (strncmp(rule->action_name, old_rule->action_name, ACTION_STR_SIZE)) {
		if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=update can rule: convert_action failed",REASON);
			return SR_ERROR;
		}
		sr_cls_rule_add(SR_CAN_RULES, rule->rulenum, actions_bitmap, SR_FILEOPS_READ, SR_RATE_TYPE_EVENT, rule->tuple.max_rate, /* net_rule.rate_action */ (SR_U16)0 ,
                         /* net_ruole.action.log_target */ (SR_U16)0 , /* net_rule.tuple.action.email_id */ (SR_U16)0 , /* net_rule.tuple.action.phone_id */ (SR_U16)0 ,
			 /* net_rule.action.skip_rulenum */ (SR_U16)0);
		strncpy(old_rule->action_name, rule->action_name, ACTION_STR_SIZE);
	}

	old_rule->tuple.msg_id = rule->tuple.msg_id;
	old_rule->tuple.direction = rule->tuple.direction;
	strncpy(old_rule->tuple.program, rule->tuple.program, PROG_NAME_SIZE);
	strncpy(old_rule->tuple.user, rule->tuple.user, USER_NAME_SIZE);
	sr_cls_canid_add_rule(rule->tuple.msg_id, program, user, rule->rulenum, convert_can_dir(rule->tuple.direction));

	return SR_SUCCESS;
}

static SR_32 delete_can_rule(can_rule_t *rule)
{
	can_rule_t *old_rule;

	if (!(old_rule = sr_db_can_rule_get(rule))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=delete can rule: get from db failed rule:%d",REASON,
			rule->rulenum);
		return SR_SUCCESS;
	}

	sr_cls_canid_del_rule(old_rule->tuple.msg_id, *(old_rule->tuple.program) ? old_rule->tuple.program : "*", *(old_rule->tuple.user) ? old_rule->tuple.user : "*",
		old_rule->rulenum, convert_can_dir(old_rule->tuple.direction));
	sr_db_can_rule_delete(rule);

	return SR_SUCCESS;
}

void sr_config_vsentry_db_cb(int type, int op, void *entry)
{
	switch (type) {
		case SENTRY_ENTRY_ACTION:
			action_display((action_t *)entry);
			switch (op) {
				case SENTRY_OP_CREATE:
				case SENTRY_OP_MODIFY:
					handle_action((action_t *)entry);
					break;
				case SENTRY_OP_DELETE:
					delete_action((action_t *)entry);
					break;
			}
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
		fwrite(net_entry->process, (size_t)net_entry->process_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_FILE_RULE: {
		struct sr_file_record	file_rec;
		struct sr_file_entry*	file_entry;
		memcpy(&file_rec, ptr, sizeof(file_rec));
		file_entry = (struct sr_file_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&file_rec, 1, sizeof(file_rec),conf_file);
		fwrite(file_entry->process, (size_t)file_entry->process_size, sizeof(SR_8),conf_file);
		fwrite(file_entry->filename, (size_t)file_entry->filename_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_CAN_RULE: {
		struct sr_can_record		can_rec;
		struct sr_can_entry*		can_entry;
		memcpy(&can_rec, ptr, sizeof(can_rec));
		can_entry = (struct sr_can_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&can_rec, 1, sizeof(can_rec),conf_file);
		fwrite(can_entry->process, (size_t)can_entry->process_size, sizeof(SR_8),conf_file);
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
		fwrite(email_entry->email, (size_t)email_entry->email_size, sizeof(SR_8),conf_file);
		break;
		}
	case CONFIG_LOG_TARGET: {
		struct sr_log_record		log_rec;
		struct sr_log_entry*		log_entry;
		memcpy(&log_rec, ptr, sizeof(log_rec));
		log_entry = (struct sr_log_entry*)ptr;
		fwrite(&rec_type, 1, sizeof(rec_type),conf_file);
		fwrite(&log_rec, 1, sizeof(log_rec),conf_file);
		fwrite(log_entry->log_target, (size_t)log_entry->log_size, sizeof(SR_8),conf_file);
		break;
		}
	default:
		fclose (conf_file);
		return SR_FALSE;
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
			struct sr_net_record	net_rec = {};
			if (1 != fread(&net_rec, sizeof(net_rec), 1, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			if (net_rec.process_size != fread(&process, sizeof(SR_8), net_rec.process_size, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_port_add_rule(net_rec.src_port, process, "*", net_rec.rulenum, SR_DIR_SRC, net_rec.proto);
			sr_cls_port_add_rule(net_rec.dst_port, process, "*", net_rec.rulenum, SR_DIR_DST, net_rec.proto);
			sr_cls_add_ipv4(htonl(net_rec.src_addr), process, "*", htonl(net_rec.src_netmask), net_rec.rulenum, SR_DIR_SRC);
			sr_cls_add_ipv4(htonl(net_rec.dst_addr), process, "*", htonl(net_rec.dst_netmask), net_rec.rulenum, SR_DIR_DST);
			sr_cls_rule_add(SR_NET_RULES, net_rec.rulenum, net_rec.action.actions_bitmap, 0, SR_RATE_TYPE_EVENT, net_rec.max_rate, net_rec.rate_action,
				net_rec.action.log_target, net_rec.action.email_id, net_rec.action.phone_id, net_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_FILE_RULE: {
			struct sr_file_record	file_rec;
			char					filename[4096];
			if (1 != fread(&file_rec, sizeof(file_rec), 1, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			memset(filename, 0, 4096);
			if (file_rec.process_size != fread(&process, sizeof(SR_8), file_rec.process_size, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			if (file_rec.filename_size != fread(&filename, sizeof(SR_8), file_rec.filename_size, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_file_add_rule(filename, process, "*", file_rec.rulenum, (SR_U8)1);
			sr_cls_rule_add(SR_FILE_RULES, file_rec.rulenum, file_rec.action.actions_bitmap, SR_FILEOPS_READ, SR_RATE_TYPE_EVENT, file_rec.max_rate,
				file_rec.rate_action, file_rec.action.log_target, file_rec.action.email_id, file_rec.action.phone_id, file_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_CAN_RULE: {
			struct sr_can_record	can_rec;
			if (1 != fread(&can_rec, sizeof(can_rec), 1, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(process, 0, 4096);
			if (can_rec.process_size != fread(&process, sizeof(SR_8), can_rec.process_size, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			sr_cls_canid_add_rule(can_rec.msg_id, "*", "*", can_rec.rulenum,can_rec.direction);
			sr_cls_rule_add(SR_CAN_RULES, can_rec.rulenum, can_rec.action.actions_bitmap, 0, SR_RATE_TYPE_EVENT, can_rec.max_rate, can_rec.rate_action, can_rec.action.log_target, can_rec.action.email_id, can_rec.action.phone_id, can_rec.action.skip_rulenum);
			break;
			}
		case CONFIG_PHONE_ENTRY: {
			struct sr_phone_record	phone_rec;
			if (1 != fread(&phone_rec, sizeof(phone_rec), 1, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
				"%s=msg type - phone entry",MESSAGE);
			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
				"%s=phone_id - %d",MESSAGE,
				phone_rec.phone_id);
			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
				"%s=phone_number - %s",MESSAGE,
				phone_rec.phone_number);
			break;
			}
		case CONFIG_EMAIL_ENTRY: {
			struct sr_email_record	email_rec;
			char					email[256];
			if (1 != fread(&email_rec, sizeof(email_rec), 1, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(email, 0, 256);
			if (email_rec.email_size != fread(&email, sizeof(SR_8), email_rec.email_size, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
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
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
				fclose (conf_file);
				return SR_FALSE;
			}
			memset(log_target, 0, 256);
			if (log_rec.log_size != fread(&log_target, sizeof(SR_8), log_rec.log_size, conf_file)) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to read from config file, line %d",REASON,
					__LINE__);
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

SR_32 sr_create_filter_paths(void)
{
	sal_os_t os;
	
	if (sal_get_os(&os) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed getting os",REASON);
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
