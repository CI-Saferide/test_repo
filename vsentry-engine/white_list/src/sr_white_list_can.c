#include "sr_types.h"
#include "sr_white_list.h"
#include "sr_white_list_can.h"
#include "engine_sal.h"
#include <string.h>
#include "sr_cls_canbus_control.h"
#include "sr_actions_common.h"
#include "sr_cls_rules_control.h"
#include "sysrepo_mng.h"

#define SR_START_RULE_NO 3072
#define SR_END_RULE_NO 4095

static SR_32 rule_id; 
static sysrepo_mng_handler_t sysrepo_handler;

SR_32 sr_white_list_canbus(struct sr_ec_can_t *can_info)
{
	sr_white_list_item_t *white_list_item;
	char exec[SR_MAX_PATH_SIZE];
	sr_wl_can_item_t **iter;
	
	if (wr_white_list_get_mode() != SR_WL_MODE_LEARN)
		return SR_SUCCESS;
		
		
#if 0
	/*debug can print*/	
	struct sr_ec_can_t *wl_can;
	wl_can = can_info;
	char exe[1000];
	sal_get_process_name(wl_can->pid,exe,sizeof(exe));
	printf("*****\n%s PID=%u | ",exe,wl_can->pid);
	printf("MsgID=%03x",wl_can->msg_id);
	printf("%s\n********\n",wl_can->dir==SR_CAN_IN?"IN":"OUT");
	printf("PID=%u ITER MSG_ID=%x %s %s\n",can_info->pid,(*iter)->msg_id,can_info->dir==SR_CAN_IN?"IN":"OUT",exec);
#endif		

     if (sal_get_process_name(can_info->pid, exec, SR_MAX_PATH_SIZE) != SR_SUCCESS)
		strcpy(exec, "*");

	if (!(white_list_item = sr_white_list_hash_get(exec))) {		
		if (sr_white_list_hash_insert(exec, &white_list_item) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=whilte list insert - failed",REASON);
			return SR_ERROR;
		}
		
	}	
	
		
		for (iter = &(white_list_item->white_list_can);
			*iter && ((*iter)->msg_id != can_info->msg_id && (*iter)->dir == can_info->dir); //check for msg_id and same direction in item
			iter = &((*iter)->next));
			
		//If no such can msg then insert 
		if (!*iter) { 
			SR_Zalloc(*iter, sr_wl_can_item_t *, sizeof(sr_wl_can_item_t));
			if (!*iter) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=learn hash update: memory allocation failed",REASON);
				return SR_ERROR;
			}
			(*iter)->msg_id = can_info->msg_id;
			(*iter)->dir = can_info->dir;
		}

	return SR_SUCCESS;
}

void sr_white_list_canbus_print(sr_wl_can_item_t *wl_canbus)
{
	sr_wl_can_item_t *iter;
	
	for (iter = wl_canbus; iter; iter = iter->next)
		printf("MsgID=%03x dir=%s\n", iter->msg_id,iter->dir==SR_CAN_OUT? "OUT":"IN");
	
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

static SR_32 canbus_unprotect_cb(void *hash_data, void *data)
{
	// TODO : delete rulues.
	/*	
	sr_white_list_item_t *wl_item = (sr_white_list_item_t *)hash_data;
	sr_wl_can_item_t *iter;

	if (!hash_data)
		return SR_ERROR;

	for (iter = wl_item->white_list_can; iter && rule_id <= SR_END_RULE_NO; iter = iter->next) {
		sr_cls_canid_del_rule(iter->msg_id, wl_item->exec, "*", rule_id, iter->dir);
		sr_cls_rule_del(SR_CAN_RULES, rule_id);
		rule_id++;

	}
	*/

	return SR_SUCCESS;
}

static SR_32 canbus_protect_cb(void *hash_data, void *data)
{
	sr_white_list_item_t *wl_item = (sr_white_list_item_t *)hash_data;	
	sr_wl_can_item_t *iter;

	if (!hash_data)
		return SR_ERROR;

	for (iter = wl_item->white_list_can; iter; iter = iter->next) {
		printf("rule=%d msg_id=%03x exec=%s %s\n", rule_id, iter->msg_id, wl_item->exec,iter->dir==SR_CAN_IN?"IN":"OUT");
		if (rule_id > SR_END_RULE_NO) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=canbus learn rule exeeds max number of rules can_msg:%x %s exec:%s",
					REASON, iter->msg_id,iter->dir ,wl_item->exec);
			continue;
		}
		if (sys_repo_mng_create_canbus_rule(&sysrepo_handler, rule_id, iter->msg_id, wl_item->exec, "*", "allow_log", iter->dir) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sys_repo_mng_create_can_rule  fiel rule id:%d ",
					REASON, rule_id);
		}
		rule_id++;

	}
		
	return SR_SUCCESS;
}

SR_32 sr_white_list_canbus_protect(SR_BOOL is_protect)
{
	SR_32 rc;
	
	if (sysrepo_mng_session_start(&sysrepo_handler)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sysrepo_mng_session_start failed",REASON);
		return SR_ERROR;
	}

	rule_id = SR_START_RULE_NO;
	
	if ((rc = sr_white_list_hash_exec_for_all(is_protect ? canbus_protect_cb : canbus_unprotect_cb)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_white_list_hash_exec_for_all failed",REASON);
		return SR_ERROR;
	}
	if (sys_repo_mng_commit(&sysrepo_handler) != SR_SUCCESS) { 
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sys_repo_mng_commit failed ", REASON);
	}

	sysrepo_mng_session_end(&sysrepo_handler);	

	return SR_SUCCESS;
}
