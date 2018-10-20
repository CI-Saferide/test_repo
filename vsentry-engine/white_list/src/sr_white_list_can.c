#include "sr_types.h"
#include "sr_white_list.h"
#include "sr_white_list_can.h"
#include "engine_sal.h"
#include <string.h>
#include "sr_cls_canbus_control.h"
#include "sr_actions_common.h"
#include "sr_cls_rules_control.h"
#include "sysrepo_mng.h"
#include "sr_cls_wl_common.h"
#include "sentry.h"
#include "db_tools.h"

static SR_32 rule_id; 
static sysrepo_mng_handler_t sysrepo_handler;

typedef struct can_rule_info {
	SR_U32  msg_id;
	struct can_rule_info *next;
} can_rule_info_t;

static can_rule_info_t *can_rules_for_if_in[CAN_INTERFACES_MAX];
static can_rule_info_t *can_rules_for_if_out[CAN_INTERFACES_MAX];

SR_32 sr_white_list_canbus(struct sr_ec_can_t *can_info)
{
	sr_white_list_item_t *white_list_item;
	sr_wl_can_item_t **iter;
	
	if (sr_white_list_get_mode() != SR_WL_MODE_LEARN)
		return SR_SUCCESS;
	
	if (!*can_info->exec) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=wl-can: no exec name, pid: %d mid: %x dir: %s",
			REASON, can_info->pid, can_info->msg_id, can_info->dir==SR_CAN_IN?"in":"out");
		return SR_ERROR;
	}

#if 0
	/*debug can print*/	
	struct sr_ec_can_t *wl_can;
	wl_can = can_info;
	char exe[1000];
	sal_get_process_name(wl_can->pid,exe,sizeof(exe));
	printf("*****\n%s PID=%u | ",exe,wl_can->pid);
	printf("MsgID=%03x",wl_can->msg_id);
	printf("%s\n********\n",wl_can->dir==SR_CAN_IN?"IN":"OUT");
#endif		

	if (!(white_list_item = sr_white_list_hash_get(can_info->exec))) {		
		if (sr_white_list_hash_insert(can_info->exec, &white_list_item) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to insert can message to white list, pid: %d mid: %x dir: %d",
				REASON, can_info->pid, can_info->msg_id, can_info->dir==SR_CAN_IN?"in":"out");
			return SR_ERROR;
		}
		
	}	
	
		
		for (iter = &(white_list_item->white_list_can);
			*iter && ((*iter)->msg_id != can_info->msg_id || (*iter)->dir != can_info->dir || (*iter)->if_id != can_info->if_id);
			iter = &((*iter)->next));
			
		//If no such can msg then insert 
		if (!*iter) { 
			SR_Zalloc(*iter, sr_wl_can_item_t *, sizeof(sr_wl_can_item_t));
			if (!*iter) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to allocate memory for white list can message, pid: %d mid: %x dir: %s",
					REASON, can_info->pid, can_info->msg_id, can_info->dir==SR_CAN_IN?"in":"out");
				return SR_ERROR;
			}
			(*iter)->msg_id = can_info->msg_id;
			(*iter)->dir = can_info->dir;
			(*iter)->if_id = can_info->if_id;
		}

	return SR_SUCCESS;
}

void sr_white_list_canbus_print(sr_wl_can_item_t *wl_canbus, void (*print_cb)(char *buf))
{
	sr_wl_can_item_t *iter;
	char interface[CAN_INTERFACES_NAME_SIZE], print_buf[512];
	
	for (iter = wl_canbus; iter; iter = iter->next) {
		if (sal_get_interface_name(iter->if_id, interface) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=can learn rule failed to get interface name for interface id %d", REASON, iter->if_id);
			*interface = 0;
		}
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=mid %08x dir %s if=%s(%d) ",MESSAGE, iter->msg_id,iter->dir==SR_CAN_OUT? "out":"in", interface, iter->if_id);
		sprintf(print_buf, "mid=%08x dir=%s if=%s(%d) \n", iter->msg_id,iter->dir==SR_CAN_OUT? "out":"in", interface, iter->if_id);
		printf("%s", print_buf);
		if (print_cb)
			print_cb(print_buf);
	}
	
}

void sr_white_list_canbus_cleanup(sr_wl_can_item_t *wl_canbus)
{
	sr_wl_can_item_t *iter, *help;

	for (iter = wl_canbus; iter;) {
		help = iter;
		iter = iter->next;
		SR_Free(help);
	}
	
}

static SR_32 create_can_rule_for_exec(SR_U8 dir, SR_32 *rule_id, char *exec)
{ 
	SR_U32 i, tuple_id;
	char interface[CAN_INTERFACES_NAME_SIZE];
	can_rule_info_t **can_rules_arr, *rule_iter;

	can_rules_arr = (dir == SR_CAN_IN) ? can_rules_for_if_in : can_rules_for_if_out;
	for (i = 0 ; i < CAN_INTERFACES_MAX; i++) {
		if (!can_rules_arr[i])
			continue;
		if (*rule_id > SR_CAN_WL_END_RULE_NO) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=can learn rule exeeds list boundary. mid: %x dir: %s exec: %s",
					REASON, rule_iter->msg_id, dir==SR_CAN_OUT? "out":"in", exec);
			return SR_ERROR;
		}
		if (sal_get_interface_name(i, interface) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=can learn rule failed to get interface name for interface id %d", REASON, i);
			continue;
		}
		tuple_id = 0;
		for (rule_iter = can_rules_arr[i]; rule_iter; rule_iter = rule_iter->next) {
#ifdef DEBUG
			printf(">>>>>>> IN Rule:%d tuple:%d exec:%s: if:%s: msgid:%x \n", *rule_id, tuple_id, exec, interface, rule_iter->msg_id);
#endif
			if (sys_repo_mng_create_canbus_rule(&sysrepo_handler, *rule_id, tuple_id, rule_iter->msg_id, interface, exec, "*", WHITE_LIST_ACTION,
				can_dir_convert(dir)) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=fail to create can rule in persistent db. rule id: %d mid:%x dir: %s exec: %s",
						REASON, *rule_id, rule_iter->msg_id, dir==SR_CAN_OUT? "out":"in" ,exec);
			}
			tuple_id++;
		}
		(*rule_id)++;
	}

	return SR_SUCCESS;
}

static void free_rules_tables(SR_U8 dir) 
{
	can_rule_info_t **can_rules_arr, *rule_iter, *help;
	SR_U32 i;

	can_rules_arr = (dir == SR_CAN_IN) ? can_rules_for_if_in : can_rules_for_if_out;
	for (i = 0 ; i < CAN_INTERFACES_MAX; i++) {
		for (rule_iter = can_rules_arr[i]; rule_iter; ) {
			help = rule_iter;
			rule_iter = rule_iter->next;
			SR_Free(help);
		}
		can_rules_arr[i] = NULL;
	}
}

static SR_32 canbus_apply_cb(void *hash_data, void *data)
{
	sr_white_list_item_t *wl_item = (sr_white_list_item_t *)hash_data;	
	sr_wl_can_item_t *iter;
	can_rule_info_t **list, *new_item;

	if (!hash_data)
		return SR_ERROR;

	for (iter = wl_item->white_list_can; iter; iter = iter->next) {
		list = (iter->dir == SR_CAN_IN) ? &can_rules_for_if_in[iter->if_id] : &can_rules_for_if_out[iter->if_id];

		SR_Zalloc(new_item, can_rule_info_t *, sizeof(can_rule_info_t));
		if (!new_item) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to allocate memory for white list ip exec",REASON);
			return SR_ERROR;
		}
		new_item->msg_id = iter->msg_id;
		new_item->next = *list;
		*list = new_item;
	}

	if (create_can_rule_for_exec(SR_CAN_IN, &rule_id, wl_item->exec) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=fail to create inbound can rules exec: %s ",  REASON, wl_item->exec);
		return SR_ERROR;
	}
	if (create_can_rule_for_exec(SR_CAN_OUT, &rule_id, wl_item->exec) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=fail to create outbound can rules exec: %s ",  REASON, wl_item->exec);
		return SR_ERROR;
	}

	free_rules_tables(SR_CAN_IN);
	free_rules_tables(SR_CAN_OUT);
		
	return SR_SUCCESS;
}

SR_32 sr_white_list_canbus_apply(void)
{
	SR_32 rc;
	
	if (sysrepo_mng_session_start(&sysrepo_handler)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=wl can:fail to init persistent db",REASON);
		return SR_ERROR;
	}

	rule_id = SR_CAN_WL_START_RULE_NO;
	
	if ((rc = sr_white_list_hash_exec_for_all(canbus_apply_cb)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=can wl hash exec failed",REASON);
		return SR_ERROR;
	}
	if (sys_repo_mng_commit(&sysrepo_handler) != SR_SUCCESS) { 
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to commit wl can rules from persistent db", REASON);
	}

	sysrepo_mng_session_end(&sysrepo_handler);	

	return SR_SUCCESS;
}
