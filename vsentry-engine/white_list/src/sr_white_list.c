#include <sr_gen_hash.h>
#include "sr_white_list.h"
#include "sal_mem.h"
#include "sysrepo_mng.h"
#include "sr_cls_wl_common.h"
#include "sr_config_parse.h"

#define HASH_SIZE 500

static sr_wl_mode_t wl_mode;

static struct sr_gen_hash *white_list_hash;

static SR_32 white_list_comp(void *data_in_hash, void *comp_val)
{
        sr_white_list_item_t *white_list_item = (sr_white_list_item_t *)data_in_hash;
	char *comp_exe = (char *)comp_val;

        if (!data_in_hash)
                return -1;

	return strncmp(white_list_item->exec, comp_exe, SR_MAX_PATH_SIZE);
}

static void white_list_print(void *data_in_hash)
{
	sr_white_list_item_t *white_list_item = (sr_white_list_item_t *)data_in_hash;

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=white list learnt program:%s ", MESSAGE, white_list_item->exec);
	printf("exec:%s: \n", white_list_item->exec);

	sr_white_list_file_print(white_list_item->white_list_file);
	sr_white_list_canbus_print(white_list_item->white_list_can);
}

static SR_U32 white_list_create_key(void *data)
{
	sr_white_list_item_t *white_list_item = (sr_white_list_item_t *)data;
	SR_U32 num = 0, len, i;
	// TODO : Ctreate a better hash key creation function.
	
	len = strlen(white_list_item->exec);
	for (i = 0; i < len; i++)
		num += white_list_item->exec[i]; 

	return num;
}

static void white_list_free(void *data_in_hash)
{
	sr_white_list_item_t *white_list_item = (sr_white_list_item_t *)data_in_hash;

	if (!white_list_item)
		return;

	sr_white_list_file_cleanup(white_list_item->white_list_file);
	sr_white_list_canbus_cleanup(white_list_item->white_list_can);

	SR_Free(white_list_item);
}

static SR_32 sr_white_list_create_action(void)
{
	sysrepo_mng_handler_t sysrepo_handler;
 
        if (sysrepo_mng_session_start(&sysrepo_handler) != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=sysrepo_mng_session_start failed",REASON);
                return SR_ERROR;
        }
                        
	if (sys_repo_mng_create_action(&sysrepo_handler, WHITE_LIST_ACTION, SR_TRUE, SR_FALSE) != SR_ERR_OK) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_white_list_create_action: sys_repo_mng_create_action failed",REASON);
		return SR_ERROR;
	}

	if (sys_repo_mng_commit(&sysrepo_handler) != SR_SUCCESS) { 
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=sys_repo_mng_commit failed ", REASON);
	}

	sysrepo_mng_session_end(&sysrepo_handler);

	return SR_SUCCESS;
}

SR_32 sr_white_list_init(void)
{
	hash_ops_t hash_ops = {};

	if (sr_white_list_file_init() != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_file_init",REASON);
		return SR_ERROR;
	}

	hash_ops.create_key = white_list_create_key;
	hash_ops.comp = white_list_comp;
	hash_ops.print = white_list_print;
	hash_ops.free = white_list_free;
	if (!(white_list_hash = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=file_hash_init: sr_gen_hash_new failed",REASON);
		return SR_ERROR;
	}
	wl_mode = SR_WL_MODE_OFF;

	return SR_SUCCESS;
}

static SR_32 sr_white_list_delete_rules(void)
{
	sysrepo_mng_handler_t sysrepo_handler;

	if (sysrepo_mng_session_start(&sysrepo_handler)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=wl file:fail to init persistent db",REASON);
		return SR_ERROR;
	}

	if (sys_repo_mng_delete_ip_rules(&sysrepo_handler, SR_IP_WL_START_RULE_NO, SR_IP_WL_END_RULE_NO + 1) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=wl file:fail to delete ip rules",REASON);
                return SR_ERROR;
	}
	if (sys_repo_mng_delete_file_rules(&sysrepo_handler, SR_FILE_WL_START_RULE_NO, SR_FILE_WL_END_RULE_NO + 1) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=wl file:fail to delete ip rules",REASON);
                return SR_ERROR;
	}
	if (sys_repo_mng_delete_can_rules(&sysrepo_handler, SR_CAN_WL_START_RULE_NO, SR_CAN_WL_END_RULE_NO + 1) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=wl file:fail to delete ip rules",REASON);
                return SR_ERROR;
	}

	if (sys_repo_mng_commit(&sysrepo_handler) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=failed to commit wl file rules from persistent db", REASON);
	}

	sysrepo_mng_session_end(&sysrepo_handler);

	return SR_SUCCESS;
}

SR_32 sr_white_list_reset(void)
{
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=delete white list rules", MESSAGE);
	sr_white_list_delete_all();
	sr_white_list_ip_delete_all();
	sr_white_list_delete_rules();
 	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=white list rules successfuly deleted", MESSAGE);
	return SR_SUCCESS;
}

SR_32 sr_white_list_set_mode(sr_wl_mode_t new_wl_mode)
{
	SR_32 rc;
	sr_ec_msg_t *msg;
	struct config_params_t *config_params;
	sr_config_msg_t *conf_msg;

	config_params = sr_config_get_param();

	if (wl_mode == new_wl_mode)
		return SR_SUCCESS;
	switch (wl_mode) {
		case SR_WL_MODE_LEARN:
			break;
		case SR_WL_MODE_APPLY:
			// Remove the rules
			if ((rc = sr_white_list_file_apply(SR_FALSE)) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_file_apply failed",REASON);
                		return SR_ERROR;
			}
			if ((rc = sr_white_list_canbus_apply(SR_FALSE)) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_canbus_apply failed",REASON);
                		return SR_ERROR;
			}
			break;
		case SR_WL_MODE_OFF:
			break;
		default:
			return SR_ERROR;
	}
	switch (new_wl_mode) { 
		case SR_WL_MODE_LEARN:
			/* Set default rule to be allow */
 			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=move to mode wl_learn", MESSAGE);
			conf_msg = (sr_config_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
        		if (conf_msg) {
				conf_msg->msg_type = SR_MSG_TYPE_CONFIG;
				conf_msg->sub_msg.cef_max_rate = config_params->cef_max_rate;
				conf_msg->sub_msg.def_file_action = SR_CLS_ACTION_ALLOW;
				conf_msg->sub_msg.def_can_action = SR_CLS_ACTION_ALLOW;
				conf_msg->sub_msg.def_net_action = SR_CLS_ACTION_ALLOW;
				sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(conf_msg));
			} else
 				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to transfer config info to kernel",REASON);
			sr_white_list_reset();
			break;
		case SR_WL_MODE_APPLY:
 			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=move to mode wl_apply", MESSAGE);
			sr_white_list_create_action();
			wl_mode = SR_WL_MODE_APPLY;
			printf("Applying file rules\n");
 			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=applying file rules", MESSAGE);
			if ((rc = sr_white_list_file_apply(SR_TRUE)) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_file_apply failed",REASON);
                		return SR_ERROR;
			}
			printf("Applying file CAN rules\n");
 			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=applying CAN rules", MESSAGE);
			if ((rc = sr_white_list_canbus_apply(SR_TRUE)) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_canbus_apply failed",REASON);
                		return SR_ERROR;
			}
			printf("Applying file IP rules\n");
 			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=applying network rules", MESSAGE);
			if (sr_white_list_ip_apply(SR_TRUE) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_ip_apply failed",REASON);
				return SR_ERROR;
			}
			printf("Finish applying rules\n");
 			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=white list rules applied successfuly", MESSAGE);
			/* Set default rule to be as defined in sr_config */
			conf_msg = (sr_config_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
        		if (conf_msg) {
				conf_msg->msg_type = SR_MSG_TYPE_CONFIG;
				conf_msg->sub_msg.cef_max_rate = config_params->cef_max_rate;
				conf_msg->sub_msg.def_file_action = config_params->default_file_action;
				conf_msg->sub_msg.def_can_action = config_params->default_can_action;
				conf_msg->sub_msg.def_net_action = config_params->default_net_action;
				sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(conf_msg));
			} else
 				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to transfer config info to kernel",REASON);
			break;
		case SR_WL_MODE_OFF:
			break;
		default:
			return SR_ERROR;
	}
	wl_mode = new_wl_mode;

	msg = (sr_ec_msg_t *)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_WL;
		msg->sub_msg.ec_mode = (wl_mode==SR_WL_MODE_LEARN?SR_EC_MODE_ON:SR_EC_MODE_OFF);
		sr_send_msg(ENG2MOD_BUF, sizeof(msg));
	} else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to transfer white list collect data request",REASON);

	return SR_SUCCESS;
}

sr_wl_mode_t sr_white_list_get_mode(void)
{
	return wl_mode;
}

SR_32 sr_white_list_hash_insert(char *exec, sr_white_list_item_t **new_item)
{
	sr_white_list_item_t *white_list_item;
	SR_32 rc;

	if (sr_gen_hash_get(white_list_hash, exec, 0)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                "%s=whilte list insert - item failed",REASON);
		return SR_ERROR;
        }
		
	SR_Zalloc(white_list_item, sr_white_list_item_t *, sizeof(sr_white_list_item_t));
	if (!white_list_item) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=learn hash update: memory allocation failed",REASON);
		return SR_ERROR;
	}
	if (new_item)
		*new_item = white_list_item;
		
	strncpy(white_list_item->exec, exec, SR_MAX_PATH_SIZE);
	if ((rc = sr_gen_hash_insert(white_list_hash, (void *)exec, white_list_item, 0)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                               "%s=%s: sr_gen_hash_insert failed",REASON, __FUNCTION__);
		return SR_ERROR;
	}       

	return SR_SUCCESS;
}

sr_white_list_item_t *sr_white_list_hash_get(char *exec)
{
	sr_white_list_item_t *item;

	if (!(item = sr_gen_hash_get(white_list_hash, exec, 0)))
		return NULL;

	return item;
}

void sr_white_list_uninit(void)
{
	switch (wl_mode) {
		case SR_WL_MODE_LEARN:
			break;
		case SR_WL_MODE_APPLY:
			// Remove the rules
			if (sr_white_list_file_apply(SR_FALSE) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sr_white_list_file_apply failed",REASON);
			}
			if (sr_white_list_canbus_apply(SR_FALSE) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sr_white_list_canbus_apply failed",REASON);
			}
			break;
		case SR_WL_MODE_OFF:
			break;
		default:
			break;
	}
        sr_gen_hash_destroy(white_list_hash);
	sr_white_list_file_uninit();
}

SR_32 sr_white_list_hash_exec_for_all(SR_32 (*cb)(void *hash_data, void *data))
{
	return sr_gen_hash_exec_for_each(white_list_hash, cb, NULL, 0);
}

SR_32 sr_white_list_hash_delete(char *exec)
{
	SR_32 rc;
	
	if ((rc = sr_gen_hash_delete(white_list_hash, exec, 0) != SR_SUCCESS)) {
		return rc;
	}

	return rc;
}

SR_32 sr_white_list_delete_all(void)
{
	return sr_gen_hash_delete_all(white_list_hash, 0);
}

void sr_white_list_hash_print(void)
{
	sr_gen_hash_print(white_list_hash);
}
