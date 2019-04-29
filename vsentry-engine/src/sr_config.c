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
#ifdef BIN_CLS_DB
#include "sr_engine_utils.h"
#include "sr_bin_cls_eng.h"
#include "classifier.h"
#endif

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

#ifdef BIN_CLS_DB
#endif

static SR_32 handle_engine_start_stop(char *engine)
{
	FILE *f;

	usleep(500000);
	f = fopen("/tmp/sec_state", "w");
	if (!strncmp(engine, SR_DB_ENGINE_START, SR_DB_ENGINE_NAME_SIZE)) {
#ifdef BIN_CLS_DB
		printf("enable cls_bin\n");
		bin_cls_enable(true);
#else
		sr_control_set_state(SR_TRUE);
#endif
		fprintf(f, "on");
	} else if (!strncmp(engine, SR_DB_ENGINE_STOP, SR_DB_ENGINE_NAME_SIZE)) {
#ifdef BIN_CLS_DB
		printf("disable cls_bin\n");
		bin_cls_enable(false);
#else
		sr_control_set_state(SR_FALSE);
#endif
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

#ifdef BIN_CLS_DB
	if (cls_action(true, (action->action == ACTION_ALLOW),
			(action->log_facility != LOG_NONE), action->action_name) == SR_ERROR) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=handle action failed act=%s",REASON,
			action->action_name);
		return SR_ERROR;
	}
#endif

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

#ifdef BIN_CLS_DB
	if (cls_action(false, false, false, action->action_name) == SR_ERROR) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=handle action failed act=%s",REASON,
			action->action_name);
		return SR_ERROR;
	}
#endif

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
#ifdef BIN_CLS_DB
	unsigned int uid = UID_ANY, exec_ino = INODE_ANY;
	int ret;
#else
	SR_U16 actions_bitmap = 0;
	char *user, *program;
#endif

	if (sr_db_ip_rule_add(rule) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add ip rule failed ad to db",REASON);
		return SR_ERROR;
	}

#ifdef BIN_CLS_DB
	/* create the rule */
	ret = cls_rule(true, CLS_IP_RULE_TYPE, rule->rulenum, rule->action_name, 0);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to create ip rule %u with action %s",REASON,
			rule->rulenum, rule->action_name);
		return ret;
	}

	/* create the uid rule */
	if (*(rule->tuple.user))
		uid = sal_get_uid(rule->tuple.user);

	ret = cls_uid_rule(true, CLS_IP_RULE_TYPE, rule->rulenum, uid);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add uid %u for ip rule %d",REASON,
			uid, rule->rulenum);
		return ret;
	}

	/* create the exec rule */
	if (*(rule->tuple.program)) {
		ret = sr_get_inode(rule->tuple.program, &exec_ino);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to get prog %s inode",REASON,
				rule->tuple.program);
			return ret;
		}
	}

	ret = cls_prog_rule(true, CLS_IP_RULE_TYPE, rule->rulenum, exec_ino);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add exec_ino %u for ip rule %d",REASON,
			exec_ino, rule->rulenum);
		return ret;
	}

	/* create the src ip rule */
	ret = cls_ip_rule(true, rule->rulenum, rule->tuple.srcaddr.s_addr,
			rule->tuple.srcnetmask.s_addr, CLS_NET_DIR_SRC);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add src ip rule %d",REASON, rule->rulenum);
		return ret;
	}

	/* create the dst ip rule */
	ret = cls_ip_rule(true, rule->rulenum, rule->tuple.dstaddr.s_addr,
			rule->tuple.dstnetmask.s_addr, CLS_NET_DIR_DST);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add dst ip rule %d",REASON, rule->rulenum);
		return ret;
	}

	/* create the ip_proto rule */
	ret = cls_ip_porto_rule(true, rule->rulenum, rule->tuple.proto);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add ipproto %u rule %d",REASON,
			rule->tuple.proto, rule->rulenum);
		return ret;
	}

	/* create the src port rule */
	ret = cls_port_rule(true, rule->rulenum, rule->tuple.srcport,
			rule->tuple.proto, CLS_NET_DIR_SRC);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add src port %u rule %d",REASON,
			rule->tuple.srcport, rule->rulenum);
		return ret;
	}

	/* create the dst port rule */
	ret = cls_port_rule(true, rule->rulenum, rule->tuple.dstport,
			rule->tuple.proto, CLS_NET_DIR_DST);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add dst port %u rule %d",REASON,
			rule->tuple.dstport, rule->rulenum);
		return ret;
	}

#else
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
#endif
	return SR_SUCCESS;
}

static SR_32 delete_ip_rule(ip_rule_t *rule)
{
	ip_rule_t *old_rule;
#ifdef BIN_CLS_DB
	int ret;
	unsigned int uid = UID_ANY, exec_ino = INODE_ANY;
#else
	char *old_user, *old_program;
#endif

	if (!(old_rule = sr_db_ip_rule_get(rule))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=delete ip rule db get rule failed gettig old %s=%d",REASON,
			RULE_NUM_KEY,rule->rulenum);
		return SR_SUCCESS;
	}
#ifdef BIN_CLS_DB
	/* delete the src ip rule */
	ret = cls_ip_rule(false, old_rule->rulenum, old_rule->tuple.srcaddr.s_addr,
			old_rule->tuple.srcnetmask.s_addr, CLS_NET_DIR_SRC);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add src ip rule %d",REASON, old_rule->rulenum);
		return ret;
	}

	/* delete the dst ip rule */
	ret = cls_ip_rule(false, old_rule->rulenum, old_rule->tuple.dstaddr.s_addr,
			old_rule->tuple.dstnetmask.s_addr, CLS_NET_DIR_DST);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add dst ip rule %d",REASON, old_rule->rulenum);
		return ret;
	}

	/* delete the ip_proto rule */
	ret = cls_ip_porto_rule(false, old_rule->rulenum, old_rule->tuple.proto);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add ipproto %u rule %d",REASON,
			old_rule->tuple.proto, old_rule->rulenum);
		return ret;
	}

	/* delete the src port rule */
	ret = cls_port_rule(false, old_rule->rulenum, old_rule->tuple.srcport,
			old_rule->tuple.proto, CLS_NET_DIR_SRC);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add src port %u rule %d",REASON,
			old_rule->tuple.srcport, old_rule->rulenum);
		return ret;
	}

	/* delete the dst port rule */
	ret = cls_port_rule(false, old_rule->rulenum, old_rule->tuple.dstport,
			old_rule->tuple.proto, CLS_NET_DIR_DST);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add dst port %u rule %d",REASON,
			old_rule->tuple.dstport, old_rule->rulenum);
		return ret;
	}

	/* delete the uid rule */
	if (*(old_rule->tuple.user))
		uid = sal_get_uid(old_rule->tuple.user);

	ret = cls_uid_rule(false, CLS_IP_RULE_TYPE, old_rule->rulenum, uid);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to delete uid %u for ip rule %d",REASON,
			uid, old_rule->rulenum);
		return ret;
	}

	/* delete the exec rule */
	if (*(old_rule->tuple.program)) {
		ret = sr_get_inode(old_rule->tuple.program, &exec_ino);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to get prog %s inode",REASON,
				old_rule->tuple.program);
			return ret;
		}
	}

	ret = cls_prog_rule(false, CLS_IP_RULE_TYPE, old_rule->rulenum, exec_ino);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to delete exec_ino %u for ip rule %d",REASON,
			exec_ino, old_rule->rulenum);
		return ret;
	}

	/* delete the rule */
	ret = cls_rule(false, CLS_IP_RULE_TYPE, old_rule->rulenum, old_rule->action_name, 0);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to delete ip rule %d",REASON, old_rule->rulenum);

		return ret;
	}
#else
	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";
	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";

	sr_cls_port_del_rule(old_rule->tuple.srcport, old_program, old_user, old_rule->rulenum, SR_DIR_SRC, old_rule->tuple.proto);
	sr_cls_port_del_rule(old_rule->tuple.dstport, old_program, old_user, old_rule->rulenum, SR_DIR_DST, old_rule->tuple.proto);
	sr_cls_del_ipv4(old_rule->tuple.srcaddr.s_addr, old_program, old_user, old_rule->tuple.srcnetmask.s_addr, old_rule->rulenum, SR_DIR_SRC);
	sr_cls_del_ipv4(old_rule->tuple.dstaddr.s_addr, old_program, old_user, old_rule->tuple.dstnetmask.s_addr, old_rule->rulenum, SR_DIR_DST);
#endif
	sr_db_ip_rule_delete(rule);

	return SR_SUCCESS;
}

static SR_32 update_ip_rule(ip_rule_t *rule)
{
	ip_rule_t *old_rule;
	char *user, *program, *old_user, *old_program;
#ifndef BIN_CLS_DB
	SR_U16 actions_bitmap = 0;
#endif

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

#ifdef BIN_CLS_DB
	if (delete_ip_rule(old_rule) == SR_ERROR) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=update can rule: delete old rule failed",REASON);
		return SR_ERROR;
	}

	if (add_ip_rule(rule) == SR_ERROR) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=update can rule: add updated rule failed",REASON);
		return SR_ERROR;
	}
#else

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
#endif
	if (old_rule->tuple.srcport != rule->tuple.srcport) {
#ifndef BIN_CLS_DB
		sr_cls_port_del_rule(old_rule->tuple.srcport, old_program, old_user, old_rule->rulenum, SR_DIR_SRC, old_rule->tuple.proto);
		sr_cls_port_add_rule(rule->tuple.srcport, program, user, rule->rulenum, SR_DIR_SRC, rule->tuple.proto);
#endif
		old_rule->tuple.srcport = rule->tuple.srcport;
	}	
	if (old_rule->tuple.dstport != rule->tuple.dstport) {
#ifndef BIN_CLS_DB
		sr_cls_port_del_rule(old_rule->tuple.dstport, old_program, old_user, old_rule->rulenum, SR_DIR_DST, old_rule->tuple.proto);
		sr_cls_port_add_rule(rule->tuple.dstport, program, user, rule->rulenum, SR_DIR_DST, rule->tuple.proto);
#endif
		old_rule->tuple.dstport = rule->tuple.dstport;
	}	
	if (old_rule->tuple.srcaddr.s_addr != rule->tuple.srcaddr.s_addr ||
	    old_rule->tuple.srcnetmask.s_addr != rule->tuple.srcnetmask.s_addr) {
#ifndef BIN_CLS_DB
		sr_cls_del_ipv4(old_rule->tuple.srcaddr.s_addr, old_program, old_user, old_rule->tuple.srcnetmask.s_addr, old_rule->rulenum, SR_DIR_SRC);
		sr_cls_add_ipv4(rule->tuple.srcaddr.s_addr, program, user, rule->tuple.srcnetmask.s_addr, rule->rulenum, SR_DIR_SRC);
#endif
		old_rule->tuple.srcaddr.s_addr = rule->tuple.srcaddr.s_addr;
	}	
	if (old_rule->tuple.dstaddr.s_addr != rule->tuple.dstaddr.s_addr ||
	    old_rule->tuple.dstnetmask.s_addr != rule->tuple.dstnetmask.s_addr) {
#ifndef BIN_CLS_DB
		sr_cls_del_ipv4(old_rule->tuple.dstaddr.s_addr, old_program, old_user, old_rule->tuple.dstnetmask.s_addr, old_rule->rulenum, SR_DIR_DST);
		sr_cls_add_ipv4(rule->tuple.dstaddr.s_addr, program, user, rule->tuple.dstnetmask.s_addr, rule->rulenum, SR_DIR_DST);
#endif
		old_rule->tuple.dstaddr.s_addr = rule->tuple.dstaddr.s_addr;
	}	
	if (strncmp(old_program, program, PROG_NAME_SIZE) != 0) {
#ifndef BIN_CLS_DB
		sr_cls_port_del_rule(old_rule->tuple.srcport, old_program, old_user, old_rule->rulenum, SR_DIR_SRC, old_rule->tuple.proto);
		sr_cls_port_add_rule(rule->tuple.srcport, program, user, rule->rulenum, SR_DIR_SRC, rule->tuple.proto);
#endif
		strncpy(old_rule->tuple.program, rule->tuple.program, PROG_NAME_SIZE);
	}	
	if (strncmp(old_user, user, USER_NAME_SIZE) != 0) {
#ifndef BIN_CLS_DB
		sr_cls_port_del_rule(old_rule->tuple.srcport, old_program, old_user, old_rule->rulenum, SR_DIR_SRC, old_rule->tuple.proto);
		sr_cls_port_add_rule(rule->tuple.srcport, program, user, rule->rulenum, SR_DIR_SRC, rule->tuple.proto);
#endif
		strncpy(old_rule->tuple.user, rule->tuple.user, USER_NAME_SIZE);
	}	

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
	char *program = NULL, *user = NULL;

	if (!(old_rule = sr_db_file_rule_get(rule))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=delete file rule: failed gettig old rule=%d",REASON,
			rule->rulenum);
		return SR_SUCCESS;
	}

	// Check if there other tuples in the rules.
	if (!file_rule_tuple_exist_for_field(rule->rulenum, rule->tuple.id, SR_TRUE, *(old_rule->tuple.program) ? old_rule->tuple.program : "*"))
		program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";
	if (!file_rule_tuple_exist_for_field(rule->rulenum, rule->tuple.id, SR_FALSE, *(old_rule->tuple.user) ? old_rule->tuple.user : "*"))
		user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";

	sr_cls_file_del_rule(old_rule->tuple.filename, program, user, old_rule->rulenum, (SR_U8)1);
	sr_db_file_rule_delete(rule);

	return SR_SUCCESS;
}

#ifndef BIN_CLS_DB
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
#endif

static SR_32 add_can_rule(can_rule_t *rule)
{
#ifdef BIN_CLS_DB
	unsigned int uid = UID_ANY, exec_ino = INODE_ANY, if_index = (unsigned int)(-1);
	int ret;
#else
	char *user, *program;
	SR_U16 actions_bitmap = 0;
#endif

	if (sr_db_can_rule_add(rule) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add can rule: add to db failed",REASON);
		return SR_ERROR;
	}

#ifdef BIN_CLS_DB
	ret = cls_rule(true, CLS_CAN_RULE_TYPE, rule->rulenum, rule->action_name, 0);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to create can rule %u with action %s",REASON,
			rule->rulenum, rule->action_name);
		return ret;
	}

	/* create the uid rule */
	if (*(rule->tuple.user))
		uid = sal_get_uid(rule->tuple.user);

	ret = cls_uid_rule(true, CLS_CAN_RULE_TYPE, rule->rulenum, uid);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add uid %u for can rule %d",REASON,
			uid, rule->rulenum);
		return ret;
	}

	/* create the exec rule */
	if (*(rule->tuple.program)) {
		ret = sr_get_inode(rule->tuple.program, &exec_ino);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to get prog %s inode",REASON,
				rule->tuple.program);
			return ret;
		}
	}

	ret = cls_prog_rule(true, CLS_CAN_RULE_TYPE, rule->rulenum, exec_ino);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add exec_ino %u for can rule %d",REASON,
			exec_ino, rule->rulenum);
		return ret;
	}

	/* create the can rule */
	ret = sal_get_interface_id(rule->tuple.interface, (SR_32*)&if_index);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to get if_index for can %s",REASON,
			rule->tuple.interface);
		return ret;
	}

	if (rule->tuple.direction & SENTRY_DIR_IN) {
		ret = cls_can_rule(true, rule->rulenum, rule->tuple.msg_id, DIR_IN, if_index);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to add can rule in",REASON);
			return ret;
		}
	}

	if (rule->tuple.direction & SENTRY_DIR_OUT) {
		ret = cls_can_rule(true, rule->rulenum, rule->tuple.msg_id, DIR_OUT, if_index);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to add can rule out",REASON);
			return ret;
		}
	}

#else
	if (convert_action(rule->action_name, &actions_bitmap) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=add can rule: convert to action failed",REASON);
		return SR_ERROR;
	}

	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";

	sr_cls_canid_add_rule(rule->tuple.msg_id, program, user, rule->rulenum, convert_can_dir(rule->tuple.direction), rule->tuple.interface);
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

#endif
	return SR_SUCCESS;
}

static SR_32 delete_can_rule(can_rule_t *rule)
{
	can_rule_t *old_rule;
#ifdef BIN_CLS_DB
	int ret;
	unsigned int uid = UID_ANY, exec_ino = INODE_ANY, if_index = (unsigned int)(-1);
#else
	char *program = NULL, *user = NULL;
#endif

	if (!(old_rule = sr_db_can_rule_get(rule))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=delete can rule: get from db failed rule:%d",REASON,
			rule->rulenum);
		return SR_ERROR;
	}

#ifdef BIN_CLS_DB
	/* delete the can rule */
	ret = sal_get_interface_id(old_rule->tuple.interface, (SR_32*)&if_index);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to get if_index for can %s",REASON,
			rule->tuple.interface);
		return ret;
	}

	if (old_rule->tuple.direction & SENTRY_DIR_IN) {
		ret = cls_can_rule(false, rule->rulenum, old_rule->tuple.msg_id, DIR_IN, if_index);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to delete can rule in %u mid 0x%x if %u",
				REASON, rule->rulenum, old_rule->tuple.msg_id, if_index);
			return ret;
		}
	}

	if (old_rule->tuple.direction & SENTRY_DIR_OUT) {
		ret = cls_can_rule(false, rule->rulenum, old_rule->tuple.msg_id, DIR_OUT, if_index);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to delete can rule out %u mid 0x%x if %u",
				REASON, rule->rulenum, old_rule->tuple.msg_id, if_index);
			return ret;
		}
	}

	/* delete the uid rule */
	if (*(old_rule->tuple.user))
		uid = sal_get_uid(old_rule->tuple.user);

	ret = cls_uid_rule(false, CLS_CAN_RULE_TYPE, rule->rulenum, uid);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to delete uid %u for can rule %d",REASON,
			uid, rule->rulenum);
		return ret;
	}

	/* delete the exec rule */
	if (*(old_rule->tuple.program)) {
		ret = sr_get_inode(old_rule->tuple.program, &exec_ino);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to get prog %s inode",REASON,
				rule->tuple.program);
			return ret;
		}
	}

	ret = cls_prog_rule(false, CLS_CAN_RULE_TYPE, rule->rulenum, exec_ino);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to delete exec_ino %u for can rule %d",REASON,
			exec_ino, rule->rulenum);
		return ret;
	}

	ret = cls_rule(false, CLS_CAN_RULE_TYPE, rule->rulenum, rule->action_name, 0);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to delete can rule %d",REASON, rule->rulenum);

		return ret;
	}

#else
	// Check if there other tuples in the rules.
	if (!can_rule_tuple_exist_for_field(rule->rulenum, rule->tuple.id, SR_TRUE, *(old_rule->tuple.program) ? old_rule->tuple.program : "*"))
		program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";
	if (!can_rule_tuple_exist_for_field(rule->rulenum, rule->tuple.id, SR_FALSE, *(old_rule->tuple.user) ? old_rule->tuple.user : "*"))
		user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";

	sr_cls_canid_del_rule(old_rule->tuple.msg_id, program, user, old_rule->rulenum,
		convert_can_dir(old_rule->tuple.direction), old_rule->tuple.interface);
#endif

	sr_db_can_rule_delete(rule);

	return SR_SUCCESS;
}

static SR_32 update_can_rule(can_rule_t *rule)
{
	can_rule_t *old_rule;
#ifndef BIN_CLS_DB
	SR_U16 actions_bitmap = 0;
	char *user, *program, *old_user, *old_program;
#endif

	if (!(old_rule = sr_db_can_rule_get(rule))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=update can rule: add to db failed",REASON);
		return SR_ERROR;
	}
#ifdef BIN_CLS_DB
	if (delete_can_rule(old_rule) == SR_ERROR) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=update can rule: delete old rule failed",REASON);
		return SR_ERROR;
	}
	if (add_can_rule(rule) == SR_ERROR) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=update can rule: add updated rule failed",REASON);
		return SR_ERROR;
	}
#else
	user = *(rule->tuple.user) ? rule->tuple.user : "*";
	program = *(rule->tuple.program) ? rule->tuple.program : "*";

	old_user = *(old_rule->tuple.user) ? old_rule->tuple.user : "*";
	old_program = *(old_rule->tuple.program) ? old_rule->tuple.program : "*";
	sr_cls_canid_del_rule(old_rule->tuple.msg_id, old_program, old_user, old_rule->rulenum, convert_can_dir(old_rule->tuple.direction), old_rule->tuple.interface);
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

	sr_cls_canid_add_rule(rule->tuple.msg_id, program, user, rule->rulenum, convert_can_dir(rule->tuple.direction), rule->tuple.interface);
#endif
	old_rule->tuple.msg_id = rule->tuple.msg_id;
	old_rule->tuple.direction = rule->tuple.direction;
	strncpy(old_rule->tuple.program, rule->tuple.program, PROG_NAME_SIZE);
	strncpy(old_rule->tuple.user, rule->tuple.user, USER_NAME_SIZE);
	strncpy(old_rule->tuple.interface, rule->tuple.interface, INTERFACE_SIZE);

	return SR_SUCCESS;
}

static SR_U32 during_modification = SR_FALSE;

SR_U32 sr_config_get_mod_state(void)
{
	return during_modification;
}

void sr_config_vsentry_db_cb(int type, int op, void *entry)
{
	if (!entry) {
		if (during_modification) {
			during_modification = SR_FALSE;
			printf("during_modification %d\n", during_modification);
#ifdef BIN_CLS_DB
			/* modification is completed. update the bin cls with changes */
			if (bin_cls_update(false) != SR_SUCCESS)
				fprintf(stderr, "cls bin update failed\n");
			else
				fprintf(stdout, "cls bin updated\n");
#endif
		}
		return;
	}
	else if (!during_modification) {
		during_modification = SR_TRUE;
		printf("during_modification %d\n", during_modification);
	}

	switch (type) {
		case SENTRY_ENTRY_ACTION:
//			action_display((action_t *)entry);
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
//			ip_rule_display((ip_rule_t *)entry);
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
//			can_rule_display((can_rule_t *)entry);
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
//			file_rule_display((file_rule_t *)entry);
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

static SR_32 parse_addr(char *addr_str, SR_U32 *addr, SR_U32 *netmask)
{
	char *p, *tmp = NULL;
	SR_32 rc = SR_SUCCESS;
	SR_U32 i, n;

	if (!(tmp = strdup(addr_str)))
		return SR_ERROR;

	p = strtok(tmp, "/");
	if (!p) {
		rc = SR_ERROR;
		goto out;
	}
	p = strtok(NULL, "/");
	if (!p) {
		rc = SR_ERROR;
		goto out;
	}
	sal_get_ip_address_from_str(tmp, addr);

	n = atoi(p);

	*netmask = 0;
	for (i = 0 ;i < n; i++) {
		(*netmask) >>= 1;
		(*netmask) |= (1 << 31);
	} 
	sal_to_network_order(netmask);

out:
	if (tmp)
		free(tmp);
	return rc;
} 

#ifdef BIN_CLS_DB
static SR_32 create_program_rule(char *program, SR_U16 rule_num, SR_U32 type) 
{  
        SR_U32 exec_ino = INODE_ANY;
        SR_32 ret;

	if (*(program)) {
		ret = sr_get_inode(program, &exec_ino);
		if (ret != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to get prog %s inode",REASON, program);
			return SR_ERROR;
    		}
	}

	ret = cls_prog_rule(true, type, rule_num, exec_ino);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to add exec_ino %u for ip rule %d",REASON,
					exec_ino, rule_num);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}
#endif

#ifdef BIN_CLS_DB
static SR_32 create_user_rule(char *user, SR_U16 rule_num, SR_U32 type) 
{  
	unsigned int uid = UID_ANY;
	SR_32 ret;

	if (*(user))
		uid = sal_get_uid(user);

	ret = cls_uid_rule(true, type, rule_num, uid);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=failed to add uid %u for ip rule %d",REASON,uid, rule_num);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}
#endif

static void handle_net_rule(sr_net_record_t *net_rule, SR_32 *status)
{
#ifdef BIN_CLS_DB
	SR_U32 src_addr, dst_addr, src_netmask, dst_netmask;
        SR_32 ret;
#endif
	switch (net_rule->net_item.net_item_type) {
		case NET_ITEM_ACTION:
#ifdef BIN_CLS_DB
			/* create the rule */
			ret = cls_rule(true, CLS_IP_RULE_TYPE, net_rule->rulenum, net_rule->net_item.u.action, 0);
			if (ret != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to create ip rule %u with action %s",REASON,
       					net_rule->rulenum, net_rule->net_item.u.action);
				*status = ret;
				return;
        		}
#endif
			break;
		case NET_ITEM_SRC_ADDR:
#ifdef BIN_CLS_DB
			if (parse_addr(net_rule->net_item.u.src_addr, &src_addr, &src_netmask) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=invalid src address rule %u ",REASON, net_rule->rulenum);
				*status = SR_ERROR;
				return;
			}
			/* create the src ip rule */
			ret = cls_ip_rule(true, net_rule->rulenum, src_addr, src_netmask, CLS_NET_DIR_SRC);
			if (ret != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to add src ip rule %d",REASON, net_rule->rulenum);
				*status = ret;
				return;
			}
#endif
			break;
		case NET_ITEM_DST_ADDR:
#ifdef BIN_CLS_DB
			if (parse_addr(net_rule->net_item.u.dst_addr, &dst_addr, &dst_netmask) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=invalid dst address rule %u ",REASON, net_rule->rulenum);
				*status = SR_ERROR;
				return;
			}
			/* create the dst ip rule */
			ret = cls_ip_rule(true, net_rule->rulenum, dst_addr, dst_netmask, CLS_NET_DIR_DST);
			if (ret != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to add dst ip rule %d",REASON, net_rule->rulenum);
				*status = ret;
				return;
			}
#endif
			break;
		case NET_ITEM_PROTO:
#ifdef BIN_CLS_DB
			/* create the ip_proto rule */
			ret = cls_ip_porto_rule(true, net_rule->rulenum, net_rule->net_item.u.proto); 
			if (ret != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to add ipproto %u rule %d",REASON,
					net_rule->net_item.u.proto, net_rule->rulenum);
				*status = ret;
				return;
			}
#endif
			break;
		case NET_ITEM_SRC_PORT:
#ifdef BIN_CLS_DB
			/* create the src port rule */
			ret = cls_port_rule(true, net_rule->rulenum, net_rule->net_item.u.port.port,
				net_rule->net_item.u.port.proto, CLS_NET_DIR_SRC);
			if (ret != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to add src port %u rule %d",REASON,
					net_rule->net_item.u.port.port, net_rule->rulenum);
				printf("EEEEEEEEEEee failed to add src port %u rule %d\n",
					net_rule->net_item.u.port.port, net_rule->rulenum);
				*status = ret;
				return;
			}
#endif
			break;
		case NET_ITEM_DST_PORT:
#ifdef BIN_CLS_DB
			/* create the src port rule */
			ret = cls_port_rule(true, net_rule->rulenum, net_rule->net_item.u.port.port,
				net_rule->net_item.u.port.proto, CLS_NET_DIR_SRC);
			if (ret != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to add dst port %u rule %d",REASON,
					net_rule->net_item.u.port.port, net_rule->rulenum);
				printf("EEEEEEEEEEee failed to add dst port %u rule %d\n",
					net_rule->net_item.u.port.port, net_rule->rulenum);
				*status = ret;
				return;
			}
#endif
			break;
		case NET_ITEM_UP_RL:
			break;
		case NET_ITEM_DOWN_RL:
			break;
		case NET_ITEM_PROGRAM:
#ifdef BIN_CLS_DB
			/* create the exec rule */
			if (create_program_rule(net_rule->net_item.u.program, net_rule->rulenum, CLS_IP_RULE_TYPE) != SR_SUCCESS) {
				*status = SR_ERROR;
				return;
        		}
#endif
			break;
		case NET_ITEM_USER:
#ifdef BIN_CLS_DB
        		/* create the uid rule */
			if (create_user_rule(net_rule->net_item.u.user, net_rule->rulenum, CLS_IP_RULE_TYPE) != SR_SUCCESS) { 
				*status = SR_ERROR;
				return;
        		}
#endif
			break;
		default:
			break;
	}
}

static void handle_can_rule(sr_can_record_t *can_rule, SR_32 *status)
{
#ifdef BIN_CLS_DB
        SR_U32 if_index = (unsigned int)(-1);
        int ret;
#endif

	switch (can_rule->can_item.can_item_type) {
		case CAN_ITEM_ACTION:
			printf(">>>>>>>>>> Add CAN rule rule:%d action:%s \n", can_rule->rulenum, can_rule->can_item.u.action); 
#ifdef BIN_CLS_DB
			ret = cls_rule(true, CLS_CAN_RULE_TYPE, can_rule->rulenum, can_rule->can_item.u.action, 0);
    			if (ret != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to create can rule %u with action %s",REASON,
					can_rule->rulenum, can_rule->can_item.u.action);
				*status = SR_ERROR;
				return;
        		}
#endif
			break;
		case CAN_ITEM_MSG:
#ifdef BIN_CLS_DB
 			/* create the can rule */
			ret = sal_get_interface_id(can_rule->can_item.u.msg.inf, (SR_32*)&if_index);
			if (ret != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to get if_index for can %s",REASON,
						can_rule->can_item.u.msg.inf);
				*status = SR_ERROR;
				return;
        		}
			if (!strcmp(can_rule->can_item.u.msg.dir, "in") || !strcmp(can_rule->can_item.u.msg.dir, "both")) {
				ret = cls_can_rule(true, can_rule->rulenum, can_rule->can_item.u.msg.id, DIR_IN, if_index);
				if (ret != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to add can rule in",REASON);
					*status = SR_ERROR;
					return;
				}
			}
			if (!strcmp(can_rule->can_item.u.msg.dir, "out") || !strcmp(can_rule->can_item.u.msg.dir, "both")) {
				ret = cls_can_rule(true, can_rule->rulenum, can_rule->can_item.u.msg.id, DIR_OUT, if_index);
				if (ret != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to add can rule in",REASON);
					*status = SR_ERROR;
					return;
				}
			}
#if DEBUG
			printf("   >>>>>>>>>CCCCCCCCCCCCCCCCCAAN rule createdu rule:%d mid:%x dir:%s if:%s  \n",
				can_rule->rulenum, can_rule->can_item.u.msg.id, can_rule->can_item.u.msg.dir, can_rule->can_item.u.msg.inf);
#endif
#endif
			break;
		case CAN_ITEM_PROGRAM:
#ifdef BIN_CLS_DB
			/* create the exec rule */
			if (create_program_rule(can_rule->can_item.u.program, can_rule->rulenum, CLS_CAN_RULE_TYPE) != SR_SUCCESS) {
				*status = SR_ERROR;
				return;
        		}
#endif
			break;
		case CAN_ITEM_USER:
#ifdef BIN_CLS_DB
        		/* create the uid rule */
			if (create_user_rule(can_rule->can_item.u.user, can_rule->rulenum, CLS_CAN_RULE_TYPE) != SR_SUCCESS) { 
				*status = SR_ERROR;
				return;
        		}
#endif
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

	*status = SR_SUCCESS;
}

SR_32 sr_config_handle_action(void *data) 
{
	sr_action_record_t *action = (sr_action_record_t *)data;

#ifdef BIN_CLS_DB
	if (cls_action(true, (bool)!!(action->actions_bitmap && SR_CLS_ACTION_ALLOW),
		(action->log_target != LOG_TARGET_NONE), action->name) == SR_ERROR) {
		printf("XXXXX EEEEEEEEEEE Failed add action !!!\n");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=handle action failed act=%s",REASON,
			action->name);
		return SR_ERROR;
        }
#endif

#ifndef DEBUG
	printf(">>>>>> Handle action :%s bm:%d log:%d rl bm:%d rl log:%d \n", action->name,
		action->actions_bitmap,
		action->log_target,
		action->rl_actions_bitmap,
		action->rl_log_target);
#endif

	return SR_SUCCESS;
	
}

void sr_config_handle_rule(void *data, redis_entity_type_t type, SR_32 *status)
{
	sr_net_record_t  *net_rule;
	sr_can_record_t  *can_rule;
	sr_file_record_t  *file_rule;

	*status = SR_SUCCESS;

	switch (type) { 
		case  ENTITY_TYPE_IP_RULE:
			net_rule = (sr_net_record_t *)data;
			handle_net_rule(net_rule, status);
			break;
		case  ENTITY_TYPE_FILE_RULE:
			file_rule = (sr_file_record_t *)data;
			handle_file_rule(file_rule, status);
			break;
		case  ENTITY_TYPE_CAN_RULE:
			can_rule = (sr_can_record_t *)data;
			handle_can_rule(can_rule, status);
			break;
		default:
			*status = SR_ERROR;
			printf("ERROR: entity UNKOWN type :%d \n", type);
			break;
	}
}

