#include <sr_types.h>
#include <sr_gen_hash.h>
#include <sal_linux.h>
#include <sal_mem.h>
#include "sr_stat_process_connection.h"
#include "sr_stat_learn_rule.h"
#include "sr_stat_analysis_common.h"
#include "sr_stat_analysis.h"

#define HASH_SIZE 500
#define NUM_OF_SAMPLES 5
#define MAX_LEARN 1250000

static struct sr_gen_hash *process_connection_hash;

typedef struct counters {
	SR_U64 cons_count;
	SR_U64 rx_p_count;
	SR_U64 rx_b_count;
	SR_U64 tx_p_count;
	SR_U64 tx_b_count;
} counters_t;

typedef struct traffic_sample {
	SR_U64 time;
	counters_t counters;
} traffic_sample_t;

typedef struct process_connection_data {
	struct process_connection_data *next;
	sr_stat_connection_info_t connection_info;
} process_connection_data_t;

typedef struct process_connection_item {
	SR_U32 process_id;
	sr_stat_process_sample_t process_sample;
	SR_U32 sample_ind;
	traffic_sample_t traffic_samples[NUM_OF_SAMPLES];
	sr_stat_con_stats_t max_con_stats;
	SR_32 counter;
	process_connection_data_t *process_connection_list;
} process_connection_item_t;

static SR_U64 cur_time;
static counters_t system_max;

static SR_BOOL is_finish_transmit_in_progress = SR_FALSE;
static SR_BOOL is_connection_update_in_progress = SR_FALSE;

#if 0
void static print_connection(sr_connection_id_t *con_id)
{
	if (!con_id) return;

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=%s %s=%d %s=%x %s=%x %s=%d %s=%d", MESSAGE,
		__FUNC__,
		TRANSPORT_PROTOCOL,con_id->ip_proto,
		DEVICE_SRC_IP,con_id->saddr.v4addr,
		DEVICE_DEST_IP,con_id->daddr.v4addr,
		DEVICE_SRC_PORT,con_id->sport,
		DEVICE_DEST_PORT,con_id->dport);
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
	SR_Free(process_connection_item);
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

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"process :%d exe:%s num_of_connections:%d max_new_conns:%d",
		process_connection_item->process_id,
		exe,
		process_connection_item->counter,
		process_connection_item->process_sample.max_new_cons);

	for (ptr = process_connection_item->process_connection_list; ptr; ptr = ptr->next) {
		count++;
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"proto:%d saddr:%x dassdr:%x sport:%d dport:%d rx_msgs:%u rx_bytes:%u tx_mgs:%u tx_bytes:%u time:%lu",
			ptr->connection_info.con_id.ip_proto, 
			ptr->connection_info.con_id.saddr.v4addr,
			ptr->connection_info.con_id.daddr.v4addr,
			ptr->connection_info.con_id.sport,
			ptr->connection_info.con_id.dport,
			ptr->connection_info.con_stats.rx_msgs,
			ptr->connection_info.con_stats.rx_bytes,
			ptr->connection_info.con_stats.tx_msgs,
			ptr->connection_info.con_stats.tx_bytes,
			cur_time - ptr->connection_info.time);

	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=%d connections in process:%d",MESSAGE,
		count,
		process_connection_item->process_id);
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
        if (!(process_connection_hash = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=file_hash_init: sr_gen_hash_new failed",REASON);
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
				"%s=stat update conn item SR_Zalloc failed",REASON);
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
		(*iter)->connection_info.transmit_time = connection_info->transmit_time;
		(*iter)->connection_info.is_updated = SR_TRUE;
	}
	(*iter)->connection_info.time = sal_get_time();

	return SR_SUCCESS;
}

SR_32 sr_stat_process_connection_hash_update(SR_U32 process_id, sr_stat_connection_info_t *connection_info)
{
	process_connection_item_t *process_connection_item;
	SR_32 rc= SR_SUCCESS;

	if (sr_stat_analysis_learn_mode_get() == SR_STAT_MODE_HALT) {
		return SR_SUCCESS;
	}
	is_connection_update_in_progress = SR_TRUE;

	/* If the file exists add the rule to the file. */
        if (!(process_connection_item = sr_gen_hash_get(process_connection_hash, (void *)(long int)process_id, 0))) {
		SR_Zalloc(process_connection_item, process_connection_item_t *, sizeof(process_connection_item_t));
		if (!process_connection_item) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=stat conn update memory allocation failed",REASON);
			rc = SR_ERROR;
			goto out;
		}
		process_connection_item->process_id = process_id;
		update_connection_item(process_connection_item, connection_info);
		/* Add the process */
		if ((rc = sr_gen_hash_insert(process_connection_hash, (void *)(long int)process_id, process_connection_item, 0)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=stat conn update sr_gen_hash_insert failed",REASON);
			rc = SR_ERROR;
			goto out;
		}
		
	} else
		update_connection_item(process_connection_item, connection_info);

out:
	is_connection_update_in_progress = SR_FALSE;
	return rc;
}

SR_32 sr_stat_process_connection_hash_delete(SR_U32 process_id)
{
	return sr_gen_hash_delete(process_connection_hash, (void *)(long int)process_id, 0);
}

SR_32 sr_stat_process_connection_hash_exec_for_process(SR_U32 process_id, SR_32 (*cb)(SR_U32 process_id, sr_stat_connection_info_t *connection_info))
{
        process_connection_item_t *process_connection_item;
	process_connection_data_t *iter;
	SR_U32 rc;

        if (!(process_connection_item = sr_gen_hash_get(process_connection_hash, (void *)(long int)process_id, 0)))
		return SR_SUCCESS;
	for (iter = process_connection_item->process_connection_list; iter; iter = iter->next) {
		if ((rc = cb(process_id, &(iter->connection_info))) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=process conn exec: cb failed",REASON);
			return SR_ERROR;
		}
	}

	return SR_SUCCESS;
}

SR_32 sr_stat_process_connection_delete_socket(SR_U32 process_id, sr_connection_id_t *con_id)
{
        process_connection_item_t *process_connection_item;
	process_connection_data_t **iter, *help;

        if (!(process_connection_item = sr_gen_hash_get(process_connection_hash, (void *)(long int)process_id, 0)))
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
	sr_gen_hash_exec_for_each(process_connection_hash, delete_aged_cb, NULL, 0);

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
	printf("LLLLLLLLLLLLLLLLLLL sr_stat_learn_process_rule exec:%s: rx:%d \n", exec, stats->rx_bytes);
#endif
	if (sr_stat_learn_rule_hash_update(exec, stats) != SR_SUCCESS)
		return SR_ERROR;

	return SR_SUCCESS;
}


static SR_BOOL is_new_connection(traffic_sample_t traffic_samples[], SR_32 ind) {
	SR_32 i;

	for (i = ind; i > 0; i--) { 
		if (traffic_samples[ind].counters.rx_b_count < traffic_samples[i].counters.rx_b_count ||
		    traffic_samples[ind].counters.tx_b_count < traffic_samples[i].counters.tx_b_count) {
			return SR_TRUE;
		}
	}
	return SR_FALSE;
}

static SR_BOOL is_data_learned_qualified(traffic_sample_t traffic_samples[], SR_32 size)
{
	SR_32 i, b, avarage = 0;
	float time_diff = 0;

	for (i = 1; i < size; i++) {
		time_diff = (traffic_samples[i].time - traffic_samples[i - 1].time) / (float)1000000;
		b = (traffic_samples[i].counters.rx_b_count - traffic_samples[i - 1].counters.rx_b_count) / time_diff;
		avarage += b;
#ifdef SR_STAT_ANALYSIS_DEBUG
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"i:%d time:%llu rx bytes:%d tx_bytes :%d time:%f b:%d",
			i,
			traffic_samples[i].time,
			traffic_samples[i].counters.rx_b_count,
			traffic_samples[i].counters.tx_b_count,
			time_diff,
			b * 8);
#endif
        }
	avarage /= (size - 1);

	for (i = 1; i < size; i++) {
		time_diff = (traffic_samples[i].time - traffic_samples[i - 1].time) / (float)1000000;
		b = (traffic_samples[i].counters.rx_b_count - traffic_samples[i - 1].counters.rx_b_count) / time_diff;
		if (b > 1.2 * avarage)
			return SR_FALSE;
	}

	return SR_TRUE;
}

static SR_32 finish_transmit(void *hash_data, void *data)
{
	process_connection_item_t *process_connection_item = (process_connection_item_t *)hash_data;
	process_connection_data_t *iter;
	counters_t *system_counters = (counters_t *)data;
	sr_stat_mode_t stat_mode;
	SR_32 rc = SR_SUCCESS, i;
	SR_U64 rx_diff, tx_diff;
	float time_diff = 0;

	if (!process_connection_item->process_id)
		return SR_SUCCESS;

	stat_mode = sr_stat_analysis_learn_mode_get();
	if (stat_mode == SR_STAT_MODE_HALT || stat_mode == SR_STAT_MODE_OFF) {
		process_connection_item->sample_ind = 0;
		return SR_SUCCESS;
	}

	is_finish_transmit_in_progress = SR_TRUE;

	if (!process_connection_item->process_sample.is_updated)
		goto out;
	if (process_connection_item->process_sample.new_cons_last_period > process_connection_item->process_sample.max_new_cons)
		process_connection_item->process_sample.max_new_cons = process_connection_item->process_sample.new_cons_last_period;
	system_counters->cons_count += process_connection_item->process_sample.new_cons_last_period;

	process_connection_item->process_sample.is_updated = SR_FALSE;
	process_connection_item->process_sample.new_cons_last_period = 0;

	process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.rx_p_count = 0;
	process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.rx_b_count = 0;
	process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.tx_p_count = 0;
	process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.tx_b_count = 0;
	for (iter = process_connection_item->process_connection_list; iter; iter = iter->next) {
		if (!iter->connection_info.is_updated)
			continue;
		process_connection_item->traffic_samples[process_connection_item->sample_ind].time = iter->connection_info.transmit_time;
		process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.rx_p_count += iter->connection_info.con_stats.rx_msgs;
		process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.rx_b_count += iter->connection_info.con_stats.rx_bytes;
		process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.tx_p_count += iter->connection_info.con_stats.tx_msgs;
		process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.tx_b_count += iter->connection_info.con_stats.tx_bytes;

#ifdef SR_STAT_ANALYSIS_DEBUG
		if (iter->connection_info.con_id.sport == 5001 || iter->connection_info.con_id.dport == 5001) { 
			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"PPPPPPPPPPPPPP state:%s time:%llu sport:%d dport:%d RX:%d TX:%d --------------",
				stat_mode == SR_STAT_MODE_LEARN ? "Learn" : "Protect", iter->connection_info.transmit_time,
				iter->connection_info.con_id.sport, iter->connection_info.con_id.dport,
             			 iter->connection_info.con_stats.rx_bytes, iter->connection_info.con_stats.tx_bytes);
			printf(">>>>>>>------------------------ state:%s time:%llu sport:%d dport:%d RX:%d TX:%d --------------\n",
				stat_mode == SR_STAT_MODE_LEARN ? "Learn" : "Protect", iter->connection_info.transmit_time,
				iter->connection_info.con_id.sport, iter->connection_info.con_id.dport,
             			 iter->connection_info.con_stats.rx_bytes, iter->connection_info.con_stats.tx_bytes);
		}
#endif
		iter->connection_info.is_updated = SR_FALSE;
	}

	if (process_connection_item->sample_ind && is_new_connection(process_connection_item->traffic_samples, process_connection_item->sample_ind)) { 
		process_connection_item->traffic_samples[0].counters.rx_b_count = 
		process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.rx_b_count;
		process_connection_item->traffic_samples[0].counters.tx_b_count = 
		process_connection_item->traffic_samples[process_connection_item->sample_ind].counters.tx_b_count;
		process_connection_item->sample_ind = 1;
		goto out;
	}

	if (process_connection_item->sample_ind < NUM_OF_SAMPLES - 1) {
		process_connection_item->sample_ind++;
		goto out;
	}
	if (stat_mode != SR_STAT_MODE_LEARN) {
		goto out;
	}
	if (!is_data_learned_qualified(process_connection_item->traffic_samples, NUM_OF_SAMPLES)) {
		// start a anew learning
		process_connection_item->sample_ind = 0;
		goto out;
	}

	rx_diff = process_connection_item->traffic_samples[NUM_OF_SAMPLES - 1].counters.rx_b_count - process_connection_item->traffic_samples[1].counters.rx_b_count;  
	tx_diff = process_connection_item->traffic_samples[NUM_OF_SAMPLES - 1].counters.tx_b_count - process_connection_item->traffic_samples[1].counters.tx_b_count;  
	time_diff = process_connection_item->traffic_samples[NUM_OF_SAMPLES - 1].time - process_connection_item->traffic_samples[1].time;
	time_diff /= (float)1000000;
	process_connection_item->max_con_stats.rx_bytes = rx_diff / time_diff;
	process_connection_item->max_con_stats.tx_bytes = tx_diff / time_diff;

	/* Protection: If learn more then MAX alter and start over !!!! */

	if (process_connection_item->max_con_stats.rx_bytes > MAX_LEARN || 
	    process_connection_item->max_con_stats.tx_bytes > MAX_LEARN) { 
			
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"PROCESS:%d learned to much",
			process_connection_item->process_id);
			
		for (i = 0; i < NUM_OF_SAMPLES; i++) {
			SR_32 b = 0;
			if (i > 0) {
				time_diff = (( process_connection_item->traffic_samples[i].time - process_connection_item->traffic_samples[i - 1].time));
				time_diff /= (float)1000000;
				b = (process_connection_item->traffic_samples[i].counters.rx_b_count -
					process_connection_item->traffic_samples[i - 1].counters.rx_b_count) / time_diff;
			}
			CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
				"i:%d time:%llu rx bytes:%llu tx_bytes :%llu time:%f b:%d", 
				i, 
				process_connection_item->traffic_samples[i].time,
				process_connection_item->traffic_samples[i].counters.rx_b_count,
				process_connection_item->traffic_samples[i].counters.tx_b_count, 
				time_diff,
				b * 8);
		}
		process_connection_item->sample_ind = 0;
		goto out;
	}

	/* Fix the array */
	for (i = 0 ; i < NUM_OF_SAMPLES - 1; i++)
		process_connection_item->traffic_samples[i] = process_connection_item->traffic_samples[i + 1];

	sr_stat_learn_process_rule(process_connection_item->process_id, &(process_connection_item->max_con_stats));
out:
	is_finish_transmit_in_progress = SR_FALSE;
	return rc;
}

SR_32 sr_stat_process_connection_hash_finish_transmit(SR_U32 count)
{
	counters_t system_counters = {};

	sr_gen_hash_exec_for_each(process_connection_hash, finish_transmit, (void *)&system_counters, 0);

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

	if (sr_stat_analysis_learn_mode_get() == SR_STAT_MODE_PROTECT)
		sr_stat_learn_rule_create_process_rules();

	return SR_SUCCESS;
}

SR_32 st_stats_process_connection_protect(void)
{
	sr_stat_learn_rule_create_process_rules();
	
	return SR_SUCCESS;
}

SR_32 st_stats_process_connection_learn(void)
{
	// Wait for previous transmmit to finish processing, It was advised to halt. 
	while (is_finish_transmit_in_progress || is_connection_update_in_progress)
		usleep(100000);

	// clean up all learning rules fron kernel
	sr_gen_hash_delete_all(process_connection_hash, 0);
	sr_stat_learn_rule_cleanup_process_rules();
	memset(&system_max, 0, sizeof(system_max));
	
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
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=exec cb %s=%d %s=%d rx_msgs=%d %s=%d tx_msgs=%d",MESSAGE,
		DEVICE_PROCESS_NAME,process_id,
		BYTES_INBOUNT,connection_info->con_stats.rx_bytes,
		connection_info->con_stats.rx_msgs,
		BYTES_OUT,connection_info->con_stats.tx_bytes,
		connection_info->con_stats.tx_msgs); 

	return SR_SUCCESS;
}
