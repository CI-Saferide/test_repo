#include <sr_types.h>
#include <sr_gen_hash.h>
#include <sal_linux.h>
#include <sal_mem.h>
#include "sr_stat_analysis_common.h"
#include "sr_stat_analysis.h"
#include "sr_stat_process_connection.h"
#include "sr_cls_network_control.h"
#include "sr_cls_rules_control.h"
#include "sr_sal_common.h"
#include "sr_actions_common.h"
#include "sr_cls_port_control.h"
#include "sal_linux.h"
#include <curl/curl.h>
#include "sr_config_parse.h"
#include "sr_stat_learn_rule.h"
#include "sr_cls_wl_common.h"
#include "redis_mng.h"
#include "sr_engine_main.h"

#define HASH_SIZE 500
#define ACTION_RL "action_rl"

static SR_U16 rule_number = SR_IP_WL_RL_START_RULE_NO;

static struct sr_gen_hash *learn_rule_hash;

static SR_BOOL is_action_created = SR_FALSE;
static SR_BOOL is_update_process = SR_FALSE;

static redisContext *c;

typedef struct learn_rule_item  {
	char exec[SR_MAX_PATH_SIZE];
	sr_stat_con_stats_t counters;
	SR_BOOL is_updated;
	SR_U16 rule_num;
} learn_rule_item_t;

static SR_32 learn_rule_comp(void *data_in_hash, void *comp_val)
{
        learn_rule_item_t *learn_rule_item = (learn_rule_item_t *)data_in_hash;
	char *comp_exe = (char *)comp_val;

        if (!data_in_hash)
                return -1;

	return strncmp(learn_rule_item->exec, comp_exe, SR_MAX_PATH_SIZE);
}

#ifdef SR_STAT_ANALYSIS_DEBUG
static void learn_rule_print(void *data_in_hash)
{
	learn_rule_item_t *learn_rule_item = (learn_rule_item_t *)data_in_hash;

	CEF_log_event(SR_CEF_CID_STAT_IP, "info", SEVERITY_LOW,
		"%s=learn rule %d : updated:%d  %s RX p:%d b:%d TX p:%d b:%d",MESSAGE,
		learn_rule_item->rule_num,
		learn_rule_item->is_updated,
		learn_rule_item->exec, learn_rule_item->counters.rx_msgs,
		learn_rule_item->counters.rx_bytes,
		learn_rule_item->counters.tx_msgs,
		learn_rule_item->counters.tx_bytes);
}
#endif

static SR_U32 learn_rule_create_key(void *data)
{
	learn_rule_item_t *learn_rule_item = (learn_rule_item_t *)data;
	SR_U32 num = 0, len, i;
	// TODO : Ctreate a better hash key creation function.
	
	len = strlen(learn_rule_item->exec);
	for (i = 0; i < len; i++)
		num += learn_rule_item->exec[i]; 

	return num;
}

SR_32 sr_stat_learn_rule_hash_init(void)
{
        hash_ops_t hash_ops = {};

        hash_ops.create_key = learn_rule_create_key;
        hash_ops.comp = learn_rule_comp;
#ifdef SR_STAT_ANALYSIS_DEBUG
        hash_ops.print = learn_rule_print;
#endif
        if (!(learn_rule_hash = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=file_hash_init: sr_gen_hash_new failed",REASON);
                return SR_ERROR;
        }

        return SR_SUCCESS;
}

void sr_stat_learn_rule_hash_uninit(void)
{
        sr_gen_hash_destroy(learn_rule_hash);
}

static SR_32 notify_learning(char *exec, sr_stat_con_stats_t *stats)
{
	CURL *curl;
	CURLcode res;
	struct curl_slist *chunk = NULL;
	char buf[SR_MAX_PATH_SIZE + 200], post_vin[64];
	SR_32 rc = SR_SUCCESS;
	struct config_params_t *config_params;

	if (1) return SR_SUCCESS;

	config_params = sr_config_get_param();

	if (!(*config_params->dynamic_policy_url)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=No dynamic policy URL",REASON);
		return SR_ERROR;
	}

	sprintf(buf, "PROCESS:%s TX:%llu RX:%llu;", exec, 8 * stats->tx_bytes, 8 * stats->rx_bytes);
	CEF_log_event(SR_CEF_CID_STAT_IP, "info", SEVERITY_LOW,
		"%s=learn rule: %s",MESSAGE,
		buf);

	if (!(curl = curl_easy_init())) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=curl_easy_init failed",REASON);
		rc =  SR_ERROR;
		goto out;
	}
	/* First set the URL that is about to receive our POST. This URL can
	just as well be a https:// URL if that is what should receive the
	data. */
	curl_easy_setopt(curl, CURLOPT_URL, config_params->dynamic_policy_url);
	/* Now specify the POST data */
	//curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	chunk = curl_slist_append(chunk, "application/x-www-form-urlencoded");
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);
	snprintf(post_vin, 64, "X-VIN: %s", config_params->vin);
	chunk = curl_slist_append(chunk, post_vin);
	curl_easy_setopt(curl, CURLOPT_HTTPHEADER, chunk);

	curl_easy_setopt(curl, CURLOPT_POSTFIELDS, buf);

	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	/* Check for errors */
	if(res != CURLE_OK)
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=curl_easy_perform() failed: %s", REASON,
			curl_easy_strerror(res));

	curl_easy_cleanup(curl);

out:
	if (chunk)
		curl_slist_free_all(chunk);

	curl_global_cleanup();

	return rc;
}

SR_32 sr_stat_learn_rule_hash_update(char *exec, sr_stat_con_stats_t *con_stats)
{
	learn_rule_item_t *learn_rule_item;
	SR_32 rc;
	SR_BOOL is_notify = SR_FALSE;

	/* If the file exists add the rule to the file. */
        if (!(learn_rule_item = sr_gen_hash_get(learn_rule_hash, exec, 0))) {
		SR_Zalloc(learn_rule_item, learn_rule_item_t *, sizeof(learn_rule_item_t));
		if (!learn_rule_item) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=learn hash update: memory allocation failed",REASON);
			return SR_ERROR;
		}
		strncpy(learn_rule_item->exec, exec, SR_MAX_PATH_SIZE);
		learn_rule_item->counters = *con_stats;
		learn_rule_item->is_updated = SR_TRUE;
		learn_rule_item->rule_num = rule_number;
#ifdef SR_STAT_ANALYSIS_DEBUG
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=learned rule was inserted:%d exec:%s: txb:%d rxb:%d",MESSAGE,
			rule_number, exec, 
			con_stats->tx_bytes,
			con_stats->rx_bytes);
#endif
		// rule for TX and rule for RX
		rule_number += 2;
		/* Add the process */
		if ((rc = sr_gen_hash_insert(learn_rule_hash, (void *)exec, learn_rule_item, 0)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=%s: sr_gen_hash_insert failed",REASON, __FUNCTION__);
			return SR_ERROR;
		}	
		notify_learning(exec, con_stats);
	} else {
		/* Update only bigger counters */
		if (sr_stat_analysis_learn_mode_get() != SR_STAT_MODE_LEARN && 
			(con_stats->rx_msgs > learn_rule_item->counters.rx_msgs * LEARN_RULE_TOLLERANCE ||
			con_stats->rx_bytes > learn_rule_item->counters.rx_bytes * LEARN_RULE_TOLLERANCE ||
			con_stats->tx_msgs > learn_rule_item->counters.tx_msgs * LEARN_RULE_TOLLERANCE ||
			con_stats->tx_bytes > learn_rule_item->counters.tx_bytes * LEARN_RULE_TOLLERANCE)) {
			return SR_SUCCESS;
		}
#ifdef SR_STAT_ANALYSIS_DEBUG
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=learned rule is a candidate to be updated:%d exec:%s: txb:%d rxb:%d",MESSAGE,
			rule_number - 2,
			exec,
			con_stats->tx_bytes,
			con_stats->rx_bytes);
#endif
		if (con_stats->rx_msgs > learn_rule_item->counters.rx_msgs) {
			learn_rule_item->counters.rx_msgs = con_stats->rx_msgs;
			is_notify = learn_rule_item->is_updated = SR_TRUE;
		}
		if (con_stats->rx_bytes > learn_rule_item->counters.rx_bytes) {
			learn_rule_item->counters.rx_bytes = con_stats->rx_bytes;
			is_notify = learn_rule_item->is_updated = SR_TRUE;
		}
		if (con_stats->tx_msgs > learn_rule_item->counters.tx_msgs) {
			learn_rule_item->counters.tx_msgs = con_stats->tx_msgs;
			is_notify = learn_rule_item->is_updated = SR_TRUE;
		}
		if (con_stats->tx_bytes > learn_rule_item->counters.tx_bytes) {
			learn_rule_item->counters.tx_bytes = con_stats->tx_bytes;
			is_notify = learn_rule_item->is_updated = SR_TRUE;
		}
		if (is_notify)
			notify_learning(exec, &(learn_rule_item->counters));
	}

	return SR_SUCCESS;
}

SR_32 sr_stat_learn_rule_hash_exec_for_all(SR_32 (*cb)(void *hash_data, void *data))
{
	return sr_gen_hash_exec_for_each(learn_rule_hash, cb, NULL, 0);
}

SR_32 sr_stat_learn_rule_hash_delete(char *exec)
{
	SR_32 rc;
	
	if ((rc = sr_gen_hash_delete(learn_rule_hash, exec, 0) != SR_SUCCESS)) {
		return rc;
	}

	return rc;
}

SR_32 sr_stat_learn_rule_delete_all(void)
{
	return sr_gen_hash_delete_all(learn_rule_hash, 0);
}

void sr_learn_rule_connection_hash_print(void)
{
	sr_gen_hash_print(learn_rule_hash);
}

static SR_32 sr_stat_learn_rule_update_rule(char *exec, SR_U16 rule_num, sr_stat_con_stats_t *counters)
{
	char rl[128];

	redis_mng_net_rule_t rule_info = {};
	/* Currently supports only UDP, TODO, support TCP, ANY protocl for port match */
#ifdef DEBUG
	printf("UPDATE rule#%d exec:%s RX p:%d b:%d", 
		rule_num,
		exec,
		8 * counters->rx_msgs,
		8 * counters->rx_bytes);
#endif
	CEF_log_event(SR_CEF_CID_STAT_IP, "info", SEVERITY_LOW,
		"UPDATE rule#%d exec:%s RX p:%d b:%d", 
		rule_num,
		exec,
		8 * counters->rx_msgs,
		8 * counters->rx_bytes);

	rule_info.user = "*";
	rule_info.exec = exec;
	rule_info.proto = "udp";
	rule_info.src_port = "0";
	rule_info.dst_port = "0";
	rule_info.action = ACTION_RL;

	// Download 
	rule_info.src_addr_netmask = "0.0.0.0/0"; // source any
	rule_info.dst_addr_netmask = "0.0.0.0/32"; // destination local
	snprintf(rl, sizeof(rl), "%d", (int)(counters->rx_bytes * 1.1));
	rule_info.down_rl = rl;
	rule_info.up_rl = "0";

	if (redis_mng_update_net_rule(c, rule_num, &rule_info) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=redis failed update rule",REASON);
		return SR_ERROR;
	}

	// Upload 
	rule_info.src_addr_netmask = "0.0.0.0/32"; // source local
	rule_info.dst_addr_netmask = "0.0.0.0/0"; // dewstination any
	snprintf(rl, sizeof(rl), "%d", (int)(counters->tx_bytes * 1.1));
	rule_info.up_rl = rl;
	rule_info.down_rl = "0";
        
	if (redis_mng_update_net_rule(c, rule_num + 1, &rule_info) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=redis failed update rule",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
} 

static SR_32 check_if_update_process_rule_cb(void *hash_data, void *data)
{
	learn_rule_item_t *learn_rule_item = (learn_rule_item_t *)hash_data;

	if (learn_rule_item->is_updated)
		is_update_process = SR_TRUE;
		
	return SR_SUCCESS;
}

static SR_32 update_process_rule_cb(void *hash_data, void *data)
{
	learn_rule_item_t *learn_rule_item = (learn_rule_item_t *)hash_data;

	if (!learn_rule_item->is_updated)
		return SR_SUCCESS;
	learn_rule_item->is_updated = SR_FALSE;

	return sr_stat_learn_rule_update_rule(learn_rule_item->exec, learn_rule_item->rule_num, &(learn_rule_item->counters));
}

static SR_32 deploy_process_rule_cb(void *hash_data, void *data)
{
	learn_rule_item_t *learn_rule_item = (learn_rule_item_t *)hash_data;

	learn_rule_item->is_updated = SR_FALSE;

	return sr_stat_learn_rule_update_rule(learn_rule_item->exec, learn_rule_item->rule_num, &(learn_rule_item->counters));
}

static SR_32 create_learn_rl_action()
{
	redis_mng_action_t action_info = {};
	char str_bm[32] = {}, str_rl_bm[32] = {};
	SR_U32 rl_bm = SR_CLS_ACTION_DROP | SR_CLS_ACTION_LOG; 
	SR_U32 bm = SR_CLS_ACTION_RATE;
	SR_32 rc;

	snprintf(str_bm, sizeof(str_bm), "%d", bm);
	snprintf(str_rl_bm, sizeof(str_rl_bm), "%d", rl_bm);
	action_info.action_bm = str_bm;
	action_info.rl_bm = str_rl_bm;
	action_info.rl_log = "vsentry";

	if ((rc = redis_mng_has_action(c, ACTION_RL)) == SR_ERROR) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=redis atrion delete failed",REASON);
		return SR_ERROR;
	}

	if (rc == 1) // Action exists
		return SR_SUCCESS;

	if (redis_mng_add_action(c, ACTION_RL , &action_info)) {
		printf("add action failed \n");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

SR_32 sr_stat_learn_rule_create_process_rules(void)
{
	SR_32 rc = SR_SUCCESS;

	sr_stat_learn_rule_hash_exec_for_all(check_if_update_process_rule_cb);
	if (!is_update_process)
		return SR_SUCCESS;
	is_update_process = SR_FALSE;

	sr_engine_get_db_lock();
	c = redis_mng_session_start();
	if (!c) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=redis session start failed",REASON);
		rc = SR_ERROR;
		goto out;
	}
	if (!is_action_created) {
		is_action_created = SR_TRUE;
		if (create_learn_rl_action() != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=rl action creation failed",REASON);
			rc = SR_ERROR;
			goto out;
		}
	}

	sr_stat_learn_rule_hash_exec_for_all(update_process_rule_cb);

out:
	if (c)
		redis_mng_session_end(c);
	sr_engine_get_db_unlock();

	return rc;
}

static SR_32 delete_process_rule_cb(void *hash_data, void *data)
{
	learn_rule_item_t *learn_rule_item = (learn_rule_item_t *)hash_data;

	CEF_log_event(SR_CEF_CID_STAT_IP, "info", SEVERITY_LOW,
		"%s=delete rule %d %s",MESSAGE,
		learn_rule_item->rule_num,
		learn_rule_item->exec);
	CEF_log_event(SR_CEF_CID_STAT_IP, "info", SEVERITY_LOW,
		"%s= delete rule %d %s",MESSAGE,
		learn_rule_item->rule_num + 1,
		learn_rule_item->exec);

	if (redis_mng_del_net_rule(c, learn_rule_item->rule_num, learn_rule_item->rule_num + 1, SR_TRUE) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=redis failed delete IP rules from:%d to:%d ",REASON, learn_rule_item->rule_num, learn_rule_item->rule_num + 1);
		return SR_ERROR;
	}
	
	return SR_SUCCESS;
}

SR_32 sr_stat_learn_rule_undeploy(void)
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
	sr_stat_learn_rule_hash_exec_for_all(delete_process_rule_cb);

out:
	if (c)
		redis_mng_session_end(c);
	sr_engine_get_db_unlock();

	return rc;
}

SR_32 sr_stat_learn_rule_deploy(void)
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
	if (!is_action_created) {
		is_action_created = SR_TRUE;
		if (create_learn_rl_action() != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=rl action creation failed",REASON);
			rc = SR_ERROR;
			goto out;
		}
	}

	sr_stat_learn_rule_hash_exec_for_all(deploy_process_rule_cb);

out:
	if (c)
		redis_mng_session_end(c);
	sr_engine_get_db_unlock();

	return rc;
}


SR_32 sr_stat_learn_rule_cleanup_process_rules(void)
{
	sr_stat_learn_rule_undeploy();

	// Reset rule number 
	rule_number = SR_IP_WL_RL_START_RULE_NO;

	sr_stat_learn_rule_delete_all();

	return SR_SUCCESS;
}
