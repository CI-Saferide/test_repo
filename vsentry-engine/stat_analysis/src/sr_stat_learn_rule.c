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

#define HASH_SIZE 500
#define START_RULE_NUM 300

static SR_U16 rule_number = START_RULE_NUM;

static struct sr_gen_hash *learn_rule_hash;

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

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"Learn rule#%d : updated:%d  %s RX p:%d b:%d TX p:%d b:%d",  learn_rule_item->rule_num,
		learn_rule_item->is_updated, learn_rule_item->exec, learn_rule_item->counters.rx_msgs, learn_rule_item->counters.rx_bytes,
		learn_rule_item->counters.tx_msgs, learn_rule_item->counters.tx_bytes);
}
#endif

static SR_32 learn_rule_create_key(void *data)
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
        if (!(learn_rule_hash = sr_gen_hash_new(HASH_SIZE, hash_ops))) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"file_hash_init: sr_gen_hash_new failed");
                return SR_ERROR;
        }

        return SR_SUCCESS;
}

void sr_stat_learn_rule_hash_uninit(void)
{
        sr_gen_hash_destroy(learn_rule_hash);
}

SR_32 sr_stat_learn_rule_hash_update(char *exec, sr_stat_con_stats_t *con_stats)
{
	learn_rule_item_t *learn_rule_item;
	SR_32 rc;

	/* If the file exists add the rule to the file. */
        if (!(learn_rule_item = sr_gen_hash_get(learn_rule_hash, exec))) {
		SR_Zalloc(learn_rule_item, learn_rule_item_t *, sizeof(learn_rule_item_t));
		if (!learn_rule_item) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"learn hash update: memory allocation failed");
			return SR_ERROR;
		}
		strncpy(learn_rule_item->exec, exec, SR_MAX_PATH_SIZE);
		learn_rule_item->counters = *con_stats;
		learn_rule_item->is_updated = SR_TRUE;
		learn_rule_item->rule_num = rule_number;
		// rule for TX and rule for RX
		rule_number += 2;
		/* Add the process */
		if ((rc = sr_gen_hash_insert(learn_rule_hash, (void *)exec, learn_rule_item)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"%s: sr_gen_hash_insert failed\n", __FUNCTION__);
			return SR_ERROR;
		}	
	} else {
		/* Update only bigger counters */
		if (con_stats->rx_msgs > learn_rule_item->counters.rx_msgs) {
			learn_rule_item->counters.rx_msgs = con_stats->rx_msgs;
			learn_rule_item->is_updated = SR_TRUE;
		}
		if (con_stats->rx_bytes > learn_rule_item->counters.rx_bytes) {
			learn_rule_item->counters.rx_bytes = con_stats->rx_bytes;
			learn_rule_item->is_updated = SR_TRUE;
		}
		if (con_stats->tx_msgs > learn_rule_item->counters.tx_msgs) {
			learn_rule_item->counters.tx_msgs = con_stats->tx_msgs;
			learn_rule_item->is_updated = SR_TRUE;
		}
		if (con_stats->tx_bytes > learn_rule_item->counters.tx_bytes) {
			learn_rule_item->counters.tx_bytes = con_stats->tx_bytes;
			learn_rule_item->is_updated = SR_TRUE;
		}
	}

	return SR_SUCCESS;
}

SR_32 sr_stat_learn_rule_hash_exec_for_all(SR_32 (*cb)(void *hash_data, void *data))
{
	return sr_gen_hash_exec_for_each(learn_rule_hash, cb, NULL);
}

SR_32 sr_stat_learn_rule_hash_delete(char *exec)
{
	SR_32 rc;
	
	if ((rc = sr_gen_hash_delete(learn_rule_hash, exec) != SR_SUCCESS)) {
		return rc;
	}

	return rc;
}

void sr_learn_rule_connection_hash_print(void)
{
	sr_gen_hash_print(learn_rule_hash);
}

static SR_32 sr_stat_learn_rule_update_rule(char *exec, SR_U16 rule_num, sr_stat_con_stats_t *counters)
{
	SR_U16 actions = SR_CLS_ACTION_RATE, rl_exceed_action = SR_CLS_ACTION_DROP;
	SR_U32 address = sal_get_ip_for_interface(SR_MAIN_INTERFACE);

	/* Currently supports only UDP, TODO, support TCP, ANY protocl for port match */
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"UPDATE rule#%d %s RX p:%d b:%d", 
		rule_num, exec, counters->rx_msgs, counters->rx_bytes);
	sr_cls_add_ipv4(0, exec, "*", 0, rule_num, SR_DIR_SRC);
	sr_cls_add_ipv4(address, exec, "*", 0xffffffff, rule_num, SR_DIR_DST);
	sr_cls_port_add_rule(0, exec, "*", rule_num, SR_DIR_SRC, 17); 
	sr_cls_port_add_rule(0, exec, "*", rule_num, SR_DIR_DST, 17); 
	sr_cls_rule_add(SR_NET_RULES, rule_num, actions, SR_FILEOPS_READ, SR_RATE_TYPE_BYTES, counters->rx_bytes, rl_exceed_action, 0, 0, 0, 0);

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"UPDATE rule#%d %s TX p:%d b:%d", 
		rule_num + 1, exec, counters->tx_msgs, counters->tx_bytes);
	sr_cls_add_ipv4(address, exec, "*", 0xffffffff, rule_num + 1, SR_DIR_SRC);
	sr_cls_add_ipv4(0, exec, "*", 0, rule_num + 1, SR_DIR_DST);
	sr_cls_port_add_rule(0, exec, "*", rule_num + 1, SR_DIR_SRC, 17); 
	sr_cls_port_add_rule(0, exec, "*", rule_num + 1, SR_DIR_DST, 17); 
	sr_cls_rule_add(SR_NET_RULES, rule_num + 1, actions, SR_FILEOPS_READ, SR_RATE_TYPE_BYTES, counters->tx_bytes, rl_exceed_action, 0, 0, 0, 0);

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

SR_32 sr_stat_learn_rule_create_process_rules(void)
{
	sr_stat_learn_rule_hash_exec_for_all(update_process_rule_cb);

	return SR_SUCCESS;
}

#ifdef UNIT_TEST
static SR_32 ut_cb(void *hash_data, void *data)
{
	learn_rule_item_t *learn_rule_item = (learn_rule_item_t *)hash_data;

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"Leran rule ---- %s RX p:%d b:%d TX p:%d b:%d", 
		learn_rule_item->exec, learn_rule_item->counters.rx_msgs, learn_rule_item->counters.rx_bytes, 
		learn_rule_item->counters.tx_msgs, learn_rule_item->counters.tx_bytes);
	
	return SR_SUCCESS;
}

void sr_stat_learn_rule_ut(void)
{
	SR_32 rc;
	sr_stat_con_stats_t con_stats;
	
	printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX sr_stat_process_connection_ut started");

	con_stats.rx_bytes = 500;
	con_stats.rx_msgs = 5;
	con_stats.tx_bytes = 600;
	con_stats.tx_msgs = 6;
	if ((rc = sr_stat_learn_rule_hash_update("/home/arik/arik/client_tcp_inf", &con_stats)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	sr_stat_learn_rule_hash_exec_for_all(ut_cb);

	/* Update counters for the same exec "*/
	con_stats.rx_bytes = 501;
	con_stats.rx_msgs = 6;
	con_stats.tx_bytes = 601;
	con_stats.tx_msgs = 7;
	if ((rc = sr_stat_learn_rule_hash_update("/home/arik/arik/client_tcp_inf", &con_stats)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"--------------------------- Next :");
	sr_stat_learn_rule_hash_exec_for_all(ut_cb);

	/* Add anorther process "*/
	con_stats.rx_bytes = 800000;
	con_stats.rx_msgs = 800;
	con_stats.tx_bytes = 800;
	con_stats.tx_msgs = 8;
	if ((rc = sr_stat_learn_rule_hash_update("/usr/bin/iperf", &con_stats)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"--------------------------- Next :");
	sr_stat_learn_rule_hash_exec_for_all(ut_cb);

	sr_stat_learn_rule_hash_delete("/usr/bin/iperf");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"--------------------------- After delete of iperf :");
	sr_stat_learn_rule_hash_exec_for_all(ut_cb);
}
#endif

