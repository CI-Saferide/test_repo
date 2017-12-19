#include <sr_types.h>
#include <sr_gen_hash.h>
#include <sal_linux.h>
#include <sal_mem.h>
#include "sr_stat_process_connection.h"
#include "sr_stat_learn_rule.h"
#include "sr_stat_analysis_common.h"
#include "sr_stat_analysis.h"

#define HASH_SIZE 500
#define MAX_TOLLERANCE 1.1

static struct sr_gen_hash *process_connection_hash;

typedef struct process_connection_data {
	struct process_connection_data *next;
	sr_stat_connection_info_t connection_info;
} process_connection_data_t;

typedef struct process_connection_item {
	SR_U32 process_id;
	sr_stat_process_sample_t process_sample;
	sr_stat_con_stats_t max_con_stats;
	SR_32 counter;
	process_connection_data_t *process_connection_list;
} process_connection_item_t;

typedef struct counters {
	SR_U64 cons_count;
	SR_U64 rx_p_count;
	SR_U64 rx_b_count;
	SR_U64 tx_p_count;
	SR_U64 tx_b_count;
} counters_t;

static SR_U64 cur_time;
counters_t system_max;
counters_t connection_max;

#if 0
void static print_connection(sr_connection_id_t *con_id)
{
	if (!con_id) return;

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
					"CCCDDD2:%d,%x,%x,%d,%d", 
					con_id->ip_proto, con_id->saddr.v4addr, con_id->daddr.v4addr, con_id->sport, con_id->dport);
}
#endif

static SR_32 process_connection_comp(void *data_in_hash, void *comp_val)
{
        process_connection_item_t *process_connection_item = (process_connection_item_t *)data_in_hash;
	SR_U32 process_id = (SR_32)(long int)comp_val;

        if (!data_in_hash)
                return -1;

	if (process_connection_item->process_id == process_id) {
		return 0;
	}
	return 1;
}

static SR_32 comp_con_id(sr_connection_id_t *con1, sr_connection_id_t *con2)
{
	return memcmp(con1, con2, sizeof(sr_connection_id_t));
}

static void process_connection_free(void *data_in_hash)
{
	process_connection_data_t *ptr, *help;
	process_connection_item_t *process_connection_item = (process_connection_item_t *)data_in_hash;

	for (ptr = process_connection_item->process_connection_list; ptr; ) {
		help = ptr->next;
		SR_Free(ptr);
		ptr = help;
	}
}

static void process_connection_print(void *data_in_hash)
{
	process_connection_data_t *ptr;
	process_connection_item_t *process_connection_item = (process_connection_item_t *)data_in_hash;
	SR_U32 count = 0;
	SR_U64 cur_time;
	char exe[1000];

	cur_time = sal_get_time();

	exe[0] = 0;
	sal_get_process_name(process_connection_item->process_id, exe, sizeof(exe));

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"Process :%d exe:%s num_of_connections:%d max_new_conns:%d max_rx_msgs:%d max_rx_bytes:%d max_tx_msgs:%d max_tx_bytes:%d",
			process_connection_item->process_id,  exe, process_connection_item->counter,
			process_connection_item->process_sample.max_new_cons,
			process_connection_item->max_con_stats.rx_msgs,
			process_connection_item->max_con_stats.rx_bytes,
			process_connection_item->max_con_stats.tx_msgs,
			process_connection_item->max_con_stats.tx_bytes);

	for (ptr = process_connection_item->process_connection_list; ptr; ptr = ptr->next) {
		count++;
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"proto:%d saddr:%x dassdr:%x sport:%d dport:%d rx_msgs:%u rx_bytes:%u tx_mgs:%u tx_bytes:%u time:%lu",
			ptr->connection_info.con_id.ip_proto, 
			ptr->connection_info.con_id.saddr.v4addr, ptr->connection_info.con_id.daddr.v4addr,
			ptr->connection_info.con_id.sport, ptr->connection_info.con_id.dport,
			ptr->connection_info.con_stats.rx_msgs, ptr->connection_info.con_stats.rx_bytes, ptr->connection_info.con_stats.tx_msgs,
			ptr->connection_info.con_stats.tx_bytes, cur_time - ptr->connection_info.time);
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"          max rx p:%d max rx b:%d max tx p:%d max tx b:%d",
			ptr->connection_info.max_con_stats.rx_msgs,
			ptr->connection_info.max_con_stats.rx_bytes,
			ptr->connection_info.max_con_stats.tx_msgs,
			ptr->connection_info.max_con_stats.tx_bytes);
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"%d connections in process:%d", count, process_connection_item->process_id);
}

static SR_U32 process_connection_create_key(void *data)
{
	// TODO : Ctreate a better hash ket creation function.
	return (SR_U32)(long int)data;
}

SR_32 sr_stat_process_connection_hash_init(void)
{
        hash_ops_t hash_ops = {};

        hash_ops.create_key = process_connection_create_key;
        hash_ops.comp = process_connection_comp;
        hash_ops.free = process_connection_free;
        hash_ops.print = process_connection_print;
        if (!(process_connection_hash = sr_gen_hash_new(HASH_SIZE, hash_ops))) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                "file_hash_init: sr_gen_hash_new failed");
                return SR_ERROR;
        }

        return SR_SUCCESS;
}

void sr_stat_process_connection_hash_uninit(void)
{
        sr_gen_hash_destroy(process_connection_hash);
}

static SR_32 update_connection_item(process_connection_item_t *process_connection_item, sr_stat_connection_info_t *connection_info)
{
	process_connection_data_t **iter;

	process_connection_item->process_sample.is_updated = SR_TRUE;
	for (iter = &(process_connection_item->process_connection_list);
		 *iter && comp_con_id(&((*iter)->connection_info.con_id), &(connection_info->con_id)) != 0; iter = &((*iter)->next));
	/* If socket exists increment, otherwise add */
	if (!*iter)  {
		SR_Zalloc(*iter, process_connection_data_t *, sizeof(process_connection_data_t));
		if (!*iter) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"stat update conn item SR_Zalloc failed");
			return SR_ERROR;
		}
		(*iter)->connection_info = *connection_info;
		process_connection_item->counter++;
		process_connection_item->process_sample.new_cons_last_period++;
		(*iter)->connection_info.is_updated = SR_TRUE;
	} else {
		(*iter)->connection_info.con_stats.rx_msgs = connection_info->con_stats.rx_msgs;
		(*iter)->connection_info.con_stats.rx_bytes = connection_info->con_stats.rx_bytes;
		(*iter)->connection_info.con_stats.tx_msgs = connection_info->con_stats.tx_msgs;
		(*iter)->connection_info.con_stats.tx_bytes = connection_info->con_stats.tx_bytes;
		(*iter)->connection_info.is_updated = SR_TRUE;
	}
	(*iter)->connection_info.time = sal_get_time();

	return SR_SUCCESS;
}

SR_32 sr_stat_process_connection_hash_update(SR_U32 process_id, sr_stat_connection_info_t *connection_info)
{
        process_connection_item_t *process_connection_item;
	SR_32 rc;

	/* If the file exists add the rule to the file. */
        if (!(process_connection_item = sr_gen_hash_get(process_connection_hash, (void *)(long int)process_id))) {
		SR_Zalloc(process_connection_item, process_connection_item_t *, sizeof(process_connection_item_t));
		if (!process_connection_item) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"stat conn update memory allocation failed");
			return SR_ERROR;
		}
		process_connection_item->process_id = process_id;
		update_connection_item(process_connection_item, connection_info);
		/* Add the process */
		if ((rc = sr_gen_hash_insert(process_connection_hash, (void *)(long int)process_id, process_connection_item)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"stat conn update sr_gen_hash_insert failed");
			return SR_ERROR;
		}
		
	} else
		update_connection_item(process_connection_item, connection_info);

	return SR_SUCCESS;
}

SR_32 sr_stat_process_connection_hash_delete(SR_U32 process_id)
{
	SR_32 rc;
	
	if ((rc = sr_gen_hash_delete(process_connection_hash, (void *)(long int)process_id) != SR_SUCCESS)) {
		return rc;
	}

	return rc;
}

SR_32 sr_stat_process_connection_hash_exec_for_process(SR_U32 process_id, SR_32 (*cb)(SR_U32 process_id, sr_stat_connection_info_t *connection_info))
{
        process_connection_item_t *process_connection_item;
	process_connection_data_t *iter;
	SR_U32 rc;

        if (!(process_connection_item = sr_gen_hash_get(process_connection_hash, (void *)(long int)process_id)))
		return SR_SUCCESS;
	for (iter = process_connection_item->process_connection_list; iter; iter = iter->next) {
		if ((rc = cb(process_id, &(iter->connection_info))) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"process conn exec: cb failed");
			return SR_ERROR;
		}
	}

	return SR_SUCCESS;
}

SR_32 sr_stat_process_connection_delete_socket(SR_U32 process_id, sr_connection_id_t *con_id)
{
        process_connection_item_t *process_connection_item;
	process_connection_data_t **iter, *help;

        if (!(process_connection_item = sr_gen_hash_get(process_connection_hash, (void *)(long int)process_id)))
		return SR_NOT_FOUND;
	for (iter = &(process_connection_item->process_connection_list);
		 *iter && comp_con_id(&((*iter)->connection_info.con_id), con_id) ; iter = &((*iter)->next));
	if (!*iter)
		return SR_NOT_FOUND;
	help = *iter;
	*iter = (*iter)->next;
	SR_Free(help);
	process_connection_item->counter--;

	return SR_SUCCESS;
}

static SR_32 delete_aged_cb(void *hash_data, void *data)
{
	process_connection_item_t *process_connection_item = (process_connection_item_t *)hash_data;
	process_connection_data_t **iter, *tmp;

	for (iter = &(process_connection_item->process_connection_list); *iter;) {
		if (cur_time - (*iter)->connection_info.time > SR_AGING_TIME) {
			// Needs to delete this connection
			tmp = *iter;
			(*iter) = (*iter)->next;
#if 0
			sr_stat_analysis_send_msg(SR_STAT_ANALYSIS_CONNECTION_DIED, &(tmp->connection_info));
#endif
			SR_Free(tmp);
			process_connection_item->counter--;
		 } else {
			iter = &((*iter)->next);
		}
	}
	
	return SR_SUCCESS;
} 

SR_32 sr_stat_process_connection_delete_aged_connections(void)
{
	cur_time = sal_get_time();

	// Delete all aged connection
	sr_gen_hash_exec_for_each(process_connection_hash, delete_aged_cb, NULL);

	// Delete all process entry with no connections. 
	sr_stat_process_connection_delete_empty_process();

	return SR_SUCCESS;
}

static SR_32 sr_stat_learn_process_rule(SR_32 pid, sr_stat_con_stats_t *stats)
{
	char exec[SR_MAX_PATH_SIZE];

	if (sal_get_process_name(pid, exec, SR_MAX_PATH_SIZE) != SR_SUCCESS) {
                // Process id can not be mapped to exec file, nothing to do....
                return SR_SUCCESS;
	}

#ifdef SR_STAT_ANALYSIS_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"LLLLLLLLLLLLLLLL LERAN RULE -- exec:%s rxp:%d rxb:%d txp:%d txb:%d", exec,
		stats->rx_msgs, stats->rx_bytes, stats->tx_msgs, stats->tx_bytes);
#endif

	if (sr_stat_learn_rule_hash_update(exec, stats) != SR_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}

static SR_32 finish_transmit(void *hash_data, void *data)
{
	process_connection_item_t *process_connection_item = (process_connection_item_t *)hash_data;
	process_connection_data_t *iter;
	SR_U32 diff_rx_p, diff_rx_b, diff_tx_p, diff_tx_b;
	counters_t *system_counters = (counters_t *)data;
	sr_stat_con_stats_t con_stats = {};
	SR_BOOL is_process_updated = SR_FALSE;

	if (!process_connection_item->process_sample.is_updated)
		return SR_SUCCESS;
	if (process_connection_item->process_sample.new_cons_last_period > process_connection_item->process_sample.max_new_cons)
		process_connection_item->process_sample.max_new_cons = process_connection_item->process_sample.new_cons_last_period;
	system_counters->cons_count += process_connection_item->process_sample.new_cons_last_period;

	process_connection_item->process_sample.is_updated = SR_FALSE;
	process_connection_item->process_sample.new_cons_last_period = 0;

	for (iter = process_connection_item->process_connection_list; iter; iter = iter->next) {
		if (!iter->connection_info.is_updated)
			continue;
		diff_rx_p = iter->connection_info.con_stats.rx_msgs - iter->connection_info.prev_con_stats.rx_msgs;
		diff_rx_b = iter->connection_info.con_stats.rx_bytes - iter->connection_info.prev_con_stats.rx_bytes;
		diff_tx_p = iter->connection_info.con_stats.tx_msgs - iter->connection_info.prev_con_stats.tx_msgs;
		diff_tx_b = iter->connection_info.con_stats.tx_bytes - iter->connection_info.prev_con_stats.tx_bytes;

#ifdef SR_STAT_ANALYSIS_DEBUG
		if (iter->connection_info.con_id.sport == 8888 || iter->connection_info.con_id.dport == 8888) { 
			CEF_log_debug(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"PPPPPPPPPPPPPP %s sport:%d dport:%d RX diffs:%d orig:%d prev:%d TX diffs:%d orig:%d prev:%d",
				sr_stat_analysis_learn_mode_get() == SR_STAT_MODE_LEARN ? "Learn" : "Protect",
				iter->connection_info.con_id.sport, iter->connection_info.con_id.dport,
             			diff_rx_b, iter->connection_info.con_stats.rx_bytes, iter->connection_info.prev_con_stats.rx_bytes,
             			diff_tx_b, iter->connection_info.con_stats.tx_bytes, iter->connection_info.prev_con_stats.tx_bytes);
		}
#endif
		con_stats.rx_msgs += diff_rx_p;
		con_stats.rx_bytes += diff_rx_b;
		con_stats.tx_msgs += diff_tx_p;
		con_stats.tx_bytes += diff_tx_b;
		system_counters->rx_p_count += diff_rx_p;
		system_counters->rx_b_count += diff_rx_b;
		system_counters->tx_p_count += diff_tx_p;
		system_counters->tx_b_count += diff_tx_b;
		if (diff_rx_p > iter->connection_info.max_con_stats.rx_msgs)
			iter->connection_info.max_con_stats.rx_msgs = diff_rx_p;
		if (diff_rx_b > iter->connection_info.max_con_stats.rx_bytes)
			iter->connection_info.max_con_stats.rx_bytes = diff_rx_b;
		if (diff_tx_p > iter->connection_info.max_con_stats.tx_msgs)
			iter->connection_info.max_con_stats.tx_msgs = diff_tx_p;
		if (diff_tx_b > iter->connection_info.max_con_stats.tx_bytes)
			iter->connection_info.max_con_stats.tx_bytes = diff_tx_b;
		iter->connection_info.prev_con_stats = iter->connection_info.con_stats;
		iter->connection_info.is_updated = SR_FALSE;
	}

	/* when in protect mode only consider diff with tolerance */
	if (sr_stat_analysis_learn_mode_get() != SR_STAT_MODE_LEARN && 
		((process_connection_item->max_con_stats.rx_msgs && con_stats.rx_msgs > process_connection_item->max_con_stats.rx_msgs * MAX_TOLLERANCE) ||
			(process_connection_item->max_con_stats.rx_bytes && con_stats.rx_bytes > process_connection_item->max_con_stats.rx_bytes * MAX_TOLLERANCE) ||
			(process_connection_item->max_con_stats.tx_msgs && con_stats.tx_msgs > process_connection_item->max_con_stats.tx_msgs * MAX_TOLLERANCE) ||
			(process_connection_item->max_con_stats.tx_bytes && con_stats.tx_bytes > process_connection_item->max_con_stats.tx_bytes * MAX_TOLLERANCE))) {
		return SR_SUCCESS;
	}
	if (con_stats.rx_msgs > process_connection_item->max_con_stats.rx_msgs) {
		process_connection_item->max_con_stats.rx_msgs = con_stats.rx_msgs;
		is_process_updated = SR_TRUE;
	}
	if (con_stats.rx_bytes > process_connection_item->max_con_stats.rx_bytes) {
		process_connection_item->max_con_stats.rx_bytes = con_stats.rx_bytes;
		is_process_updated = SR_TRUE;
	}
	if (con_stats.tx_msgs > process_connection_item->max_con_stats.tx_msgs) {
		process_connection_item->max_con_stats.tx_msgs = con_stats.tx_msgs;
		is_process_updated = SR_TRUE;
	}
	if (con_stats.tx_bytes > process_connection_item->max_con_stats.tx_bytes) {
		process_connection_item->max_con_stats.tx_bytes = con_stats.tx_bytes;
		is_process_updated = SR_TRUE;
	}

	if (is_process_updated)
		sr_stat_learn_process_rule(process_connection_item->process_id, &(process_connection_item->max_con_stats));

	return SR_SUCCESS;
}

SR_32 sr_stat_process_connection_hash_finish_transmit(SR_U32 count)
{
	counters_t system_counters = {};

	sr_gen_hash_exec_for_each(process_connection_hash, finish_transmit, (void *)&system_counters);

	if (system_counters.cons_count > system_max.cons_count)
		system_max.cons_count = system_counters.cons_count;
	if (system_counters.rx_p_count > system_max.rx_p_count)
		system_max.rx_p_count = system_counters.rx_p_count;
	if (system_counters.rx_b_count > system_max.rx_b_count)
		system_max.rx_b_count = system_counters.rx_b_count;
	if (system_counters.tx_p_count > system_max.tx_p_count)
		system_max.tx_p_count = system_counters.rx_p_count;
	if (system_counters.tx_b_count > system_max.tx_b_count)
		system_max.tx_b_count = system_counters.tx_b_count;

	if (sr_stat_analysis_learn_mode_get() != SR_STAT_MODE_LEARN)
		sr_stat_learn_rule_create_process_rules();

	return SR_SUCCESS;
}

SR_32 st_stats_process_connection_protect(void)
{
	sr_stat_learn_rule_create_process_rules();
	
	return SR_SUCCESS;
}

static SR_BOOL is_process_empty(void *hash_data)
{
	process_connection_item_t *process_connection_item = (process_connection_item_t *)hash_data;

	if (!process_connection_item->process_connection_list)
		return SR_TRUE; // Delete the process entry - n o connections.
	return SR_FALSE;
}

SR_32 sr_stat_process_connection_delete_empty_process(void)
{
	sr_gen_hash_delete_all_cb(process_connection_hash, is_process_empty);

	return SR_SUCCESS;
}

void sr_stat_process_connection_hash_print(void)
{
	sr_gen_hash_print(process_connection_hash);
}

SR_32 ut_cb(SR_U32 process_id, sr_stat_connection_info_t *connection_info)
{
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"EEEEEEexec cb process:%d rx_bytes:%d rx_msgs:%d tx_bytes:%d tx_msg:%d \n", 
		process_id, connection_info->con_stats.rx_bytes, connection_info->con_stats.rx_msgs, connection_info->con_stats.tx_bytes, connection_info->con_stats.tx_msgs); 

	return SR_SUCCESS;
}

#ifdef UNIT_TEST
void sr_stat_process_connection_ut(void)
{
	SR_32 rc;
	sr_stat_connection_info_t connection_info = {};
	sr_connection_id_t con_id;
	
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX sr_stat_process_connection_ut started");

	connection_info.con_id.saddr.v4addr = 0xAABBCC01;
	connection_info.con_id.daddr.v4addr = 0xAABBCC02;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4000;
	connection_info.con_id.dport = 5000;
	connection_info.con_stats.rx_bytes = 500;
	connection_info.con_stats.rx_msgs = 5;
	connection_info.con_stats.tx_bytes = 600;
	connection_info.con_stats.tx_msgs = 6;

	if ((rc = sr_stat_process_connection_hash_update(4455, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}

        // Add another counters to the same socket_id
	connection_info.con_id.saddr.v4addr = 0xAABBCC01;
	connection_info.con_id.daddr.v4addr = 0xAABBCC02;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4000;
	connection_info.con_id.dport = 5000;
	connection_info.con_stats.rx_bytes = 100;
	connection_info.con_stats.rx_msgs = 10;
	connection_info.con_stats.tx_bytes = 200;
	connection_info.con_stats.tx_msgs = 20;

	if ((rc = sr_stat_process_connection_hash_update(4455, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"===================================================================================");

	// Add another socket to the same process
	connection_info.con_id.saddr.v4addr = 0xAABBCC03;
	connection_info.con_id.daddr.v4addr = 0xAABBCC04;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4001;
	connection_info.con_id.dport = 5001;
	connection_info.con_stats.rx_bytes = 100;
	connection_info.con_stats.rx_msgs = 10;
	connection_info.con_stats.tx_bytes = 200;
	connection_info.con_stats.tx_msgs = 20;

	if ((rc = sr_stat_process_connection_hash_update(4455, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"v1 Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"v1 Expect connection 4001,5001 rx_msg:10 rx_bytes:100 tx_msgs:20 tx_bytes:200");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"===================================================================================");

	//Add another process
	connection_info.con_id.saddr.v4addr = 0xAABBCC05;
	connection_info.con_id.daddr.v4addr = 0xAABBCC06;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4002;
	connection_info.con_id.dport = 5002;
	connection_info.con_stats.rx_bytes = 400;
	connection_info.con_stats.rx_msgs = 40;
	connection_info.con_stats.tx_bytes = 500;
	connection_info.con_stats.tx_msgs = 50;

	if ((rc = sr_stat_process_connection_hash_update(4456, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"4455 Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"4455 Expect connection 4001,5001 rx_msg:10 rx_bytes:100 tx_msgs:20 tx_bytes:200");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"4456 Expect connection 4002,5002 rx_msg:40 rx_bytes:400 tx_msgs:50 tx_bytes:500");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"===================================================================================");

        // Add connnection to 4556 
	connection_info.con_id.saddr.v4addr = 0xAABBCC05;
	connection_info.con_id.daddr.v4addr = 0xAABBCC06;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4003;
	connection_info.con_id.dport = 5003;
	connection_info.con_stats.rx_bytes = 70;
	connection_info.con_stats.rx_msgs = 7;
	connection_info.con_stats.tx_bytes = 50;
	connection_info.con_stats.tx_msgs = 5;

	if ((rc = sr_stat_process_connection_hash_update(4456, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"4455 Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"4455 Expect connection 4001,5001 rx_msg:10 rx_bytes:100 tx_msgs:20 tx_bytes:200");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"4456 Expect connection 4002,5002 rx_msg:40 rx_bytes:400 tx_msgs:50 tx_bytes:500");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"4456 Expect connection 4003,5003 rx_msg:7  rx_bytes:70  tx_msgs:5 tx_bytes:50");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
	"===================================================================================");

	// Add counters to connection 4003,5003
	connection_info.con_id.saddr.v4addr = 0xAABBCC05;
	connection_info.con_id.daddr.v4addr = 0xAABBCC06;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4003;
	connection_info.con_id.dport = 5003;
	connection_info.con_stats.rx_bytes = 10;
	connection_info.con_stats.rx_msgs = 1;
	connection_info.con_stats.tx_bytes = 10;
	connection_info.con_stats.tx_msgs = 1;

	if ((rc = sr_stat_process_connection_hash_update(4456, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"4455 Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"4455 Expect connection 4001,5001 rx_msg:10 rx_bytes:100 tx_msgs:20 tx_bytes:200");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"4456 Expect connection 4002,5002 rx_msg:40 rx_bytes:400 tx_msgs:50 tx_bytes:500");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"4456 Expect connection 4003,5003 rx_msg:8  rx_bytes:80  tx_msgs:6 tx_bytes:60");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");

	// Add another 2 processes
	connection_info.con_id.saddr.v4addr = 0xAABBCC07;
	connection_info.con_id.daddr.v4addr = 0xAABBCC08;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4004;
	connection_info.con_id.dport = 5004;
	connection_info.con_stats.rx_bytes = 10;
	connection_info.con_stats.rx_msgs = 1;
	connection_info.con_stats.tx_bytes = 10;
	connection_info.con_stats.tx_msgs = 1;

	if ((rc = sr_stat_process_connection_hash_update(4460, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}

	connection_info.con_id.saddr.v4addr = 0xAABBCC09;
	connection_info.con_id.daddr.v4addr = 0xAABBCC0A;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4005;
	connection_info.con_id.dport = 5005;
	connection_info.con_stats.rx_bytes = 10;
	connection_info.con_stats.rx_msgs = 1;
	connection_info.con_stats.tx_bytes = 10;
	connection_info.con_stats.tx_msgs = 1;

	if ((rc = sr_stat_process_connection_hash_update(4461, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	
	// Add a process that resides in the same bucket as 4455
	connection_info.con_id.saddr.v4addr = 0xAABBCC0B;
	connection_info.con_id.daddr.v4addr = 0xAABBCC0C;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4006;
	connection_info.con_id.dport = 5006;
	connection_info.con_stats.rx_bytes = 19;
	connection_info.con_stats.rx_msgs = 5;
	connection_info.con_stats.tx_bytes = 20;
	connection_info.con_stats.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===============================================================================");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"======================= EXEC ==================================================");
	if ((rc = sr_stat_process_connection_hash_exec_for_process(4455, ut_cb)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"sr_stat_process_connection_hash_exec_for_process FAILED !!!");
		return;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"====== start DELETE ==============================================");
	// Delete the first prrocess, There are 2 processes in the same bucket
	if ((rc = sr_stat_process_connection_hash_delete(4455)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"sr_stat_process_connection__hash_delete_process FAILED !!!");
		return;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"====== After delete process 4455 ==============================================");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");

	// Delete a process from the midle
	if ((rc = sr_stat_process_connection_hash_delete(4460)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"sr_stat_process_connection__hash_delete_process FAILED !!!");
		return;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"====== After delete process 4460 ==============================================");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");

	// Delete the last process
	if ((rc = sr_stat_process_connection_hash_delete(4461)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection__hash_delete_process FAILED !!!\n");
		return;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"====== After delete process 4461 the last ==============================================");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"========  Before Delete connections ===============================================");

	// Check deletion of socket.
 	// Add 3 sockets to a process
	// Add a process that resides inn the same bucket as 4455
	connection_info.con_id.saddr.v4addr = 0xAABBCC0D;
	connection_info.con_id.daddr.v4addr = 0xAABBCC0E;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4007;
	connection_info.con_id.dport = 5007;
	connection_info.con_stats.rx_bytes = 19;
	connection_info.con_stats.rx_msgs = 5;
	connection_info.con_stats.tx_bytes = 20;
	connection_info.con_stats.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	connection_info.con_id.saddr.v4addr = 0xAABBCC0F;
	connection_info.con_id.daddr.v4addr = 0xAABBCC10;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4008;
	connection_info.con_id.dport = 5008;
	connection_info.con_stats.rx_bytes = 19;
	connection_info.con_stats.rx_msgs = 5;
	connection_info.con_stats.tx_bytes = 20;
	connection_info.con_stats.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	connection_info.con_id.saddr.v4addr = 0xAABBCC11;
	connection_info.con_id.daddr.v4addr = 0xAABBCC12;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4009;
	connection_info.con_id.dport = 5009;
	connection_info.con_stats.rx_bytes = 19;
	connection_info.con_stats.rx_msgs = 5;
	connection_info.con_stats.tx_bytes = 20;
	connection_info.con_stats.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	connection_info.con_id.saddr.v4addr = 0xAABBCC13;
	connection_info.con_id.daddr.v4addr = 0xAABBCC14;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4010;
	connection_info.con_id.dport = 5010;
	connection_info.con_stats.rx_bytes = 19;
	connection_info.con_stats.rx_msgs = 5;
	connection_info.con_stats.tx_bytes = 20;
	connection_info.con_stats.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===============================================================================");
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"============ Delete the first connection  ===========================================");
	con_id.saddr.v4addr = 0xAABBCC0D;
	con_id.daddr.v4addr = 0xAABBCC0E;
	con_id.ip_proto = 6;
	con_id.sport = 4007;
	con_id.dport = 5007;
	rc = sr_stat_process_connection_delete_socket(5455, &con_id);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"After delete rc:%d \n", rc);
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"============ Delete a midle connection  ===========================================");
	con_id.saddr.v4addr = 0xAABBCC0F;
	con_id.daddr.v4addr = 0xAABBCC10;
	con_id.ip_proto = 6;
	con_id.sport = 4008;
	con_id.dport = 5008;
	sr_stat_process_connection_delete_socket(5455, &con_id);
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"============ Delete the last connection  ===========================================");
	con_id.saddr.v4addr = 0xAABBCC13;
	con_id.daddr.v4addr = 0xAABBCC14;
	con_id.ip_proto = 6;
	con_id.sport = 4010;
	con_id.dport = 5010;
	sr_stat_process_connection_delete_socket(5455, &con_id);
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"============ Delete the connection 4009,5009  ===========================================");
	con_id.saddr.v4addr = 0xAABBCC11;
	con_id.daddr.v4addr = 0xAABBCC12;
	con_id.ip_proto = 6;
	con_id.sport = 4009;
	con_id.dport = 5009;
	sr_stat_process_connection_delete_socket(5455, &con_id);
	sr_stat_process_connection_hash_print();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"============ Delete the lonly connection 4006,5006 ===========================================");
	con_id.saddr.v4addr = 0xAABBCC0B;
	con_id.daddr.v4addr = 0xAABBCC0C;
	con_id.ip_proto = 6;
	con_id.sport = 4006;
	con_id.dport = 5006;
	sr_stat_process_connection_delete_socket(5455, &con_id);
	sr_stat_process_connection_hash_print();

	connection_info.con_id.saddr.v4addr = 0xAABBCC13;
	connection_info.con_id.daddr.v4addr = 0xAABBCC14;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 7000;
	connection_info.con_id.dport = 8000;
	connection_info.con_stats.rx_bytes = 19;
	connection_info.con_stats.rx_msgs = 5;
	connection_info.con_stats.tx_bytes = 20;
	connection_info.con_stats.tx_msgs = 7;
	if ((rc = sr_stat_process_connection_hash_update(7788, &connection_info)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,"sr_stat_process_connection_hash_update_process FAILED !!!");
		return;
	}
	sr_stat_process_connection_delete_socket(7788, &connection_info.con_id);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===================================================================================");
	sr_stat_process_connection_hash_print();
	if ((rc = sr_stat_process_connection_hash_delete(7788)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"sr_stat_process_connection__hash_delete_process FAILED !!!");
		return;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===== After delete ================================================================");
	sr_stat_process_connection_hash_print();
	sr_stat_process_connection_delete_empty_process();
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,"===== After delete  process ================================================================");
	sr_stat_process_connection_hash_print();
}
#endif

