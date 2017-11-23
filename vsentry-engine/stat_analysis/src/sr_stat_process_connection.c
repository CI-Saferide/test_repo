#include <sr_types.h>
#include <sr_gen_hash.h>
#include <sal_linux.h>
#include <sal_mem.h>
#include "sr_stat_process_connection.h"
#include "sr_stat_analysis_common.h"
#include "sr_stat_analysis.h"

#define HASH_SIZE 500

static struct sr_gen_hash *process_connection_hash;

typedef struct process_connection_data {
	struct process_connection_data *next;
	sr_stat_connection_info_t connection_info;
} process_connection_data_t;

typedef struct process_connection_item {
   SR_U32 process_id;
   process_connection_data_t *process_connection_list;
} process_connection_item_t;

static SR_U64 cur_time;

#if 0
void static print_connection(sr_connection_id_t *con_id)
{
	if (!con_id) return;

	printf("CCCDDD2:%d,%x,%x,%d,%d\n", 
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

	cur_time = sal_get_time();

	sal_printf("Process :%d \n", process_connection_item->process_id);
	for (ptr = process_connection_item->process_connection_list; ptr; ptr = ptr->next) {
		count++;
		sal_printf("proto:%d saddr:%x dassdr:%x sport:%d dport:%d rx_msgs:%u rx_bytes:%u tx_mgs:%u tx_bytes:%u time:%lu\n",
			ptr->connection_info.con_id.ip_proto, 
			ptr->connection_info.con_id.saddr.v4addr, ptr->connection_info.con_id.daddr.v4addr,
			ptr->connection_info.con_id.sport, ptr->connection_info.con_id.dport,
			ptr->connection_info.rx_msgs, ptr->connection_info.rx_bytes, ptr->connection_info.tx_msgs,
			ptr->connection_info.tx_bytes, cur_time - ptr->connection_info.time);
	}
	sal_printf("%d connections in process:%d \n", count, process_connection_item->process_id);
}

static SR_32 process_connection_create_key(void *data)
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
                sal_printf("file_hash_init: sr_gen_hash_new failed\n");
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

	for (iter = &(process_connection_item->process_connection_list);
		 *iter && comp_con_id(&((*iter)->connection_info.con_id), &(connection_info->con_id)) != 0; iter = &((*iter)->next));
	/* If socket exists increment, otherwise add */
	if (!*iter)  {
		SR_Zalloc(*iter, process_connection_data_t *, sizeof(process_connection_data_t));
		if (!*iter) {
			sal_printf("%s: SR_Zalloc failed\n", __FUNCTION__);
			return SR_ERROR;
		}
		(*iter)->connection_info = *connection_info;
	} else {
		(*iter)->connection_info.rx_msgs += connection_info->rx_msgs;
		(*iter)->connection_info.rx_bytes += connection_info->rx_bytes;
		(*iter)->connection_info.tx_msgs += connection_info->tx_msgs;
		(*iter)->connection_info.tx_bytes += connection_info->tx_bytes;
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
			sal_printf("%s: memory allocation failed\n", __FUNCTION__);
			return SR_ERROR;
		}
		process_connection_item->process_id = process_id;
		update_connection_item(process_connection_item, connection_info);
		/* Add the process */
		if ((rc = sr_gen_hash_insert(process_connection_hash, (void *)(long int)process_id, process_connection_item)) != SR_SUCCESS) {
			sal_printf("%s: sr_gen_hash_insert failed\n", __FUNCTION__);
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
			sal_printf("%s: exec cb failed\n", __FUNCTION__);
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
	sal_printf("EEEEEEexec cb process:%d rx_bytes:%d rx_msgs:%d tx_bytes:%d tx_msg:%d \n", 
		process_id, connection_info->rx_bytes, connection_info->rx_msgs, connection_info->tx_bytes, connection_info->tx_msgs); 

	return SR_SUCCESS;
}

void sr_stat_process_connection_ut(void)
{
	SR_32 rc;
	sr_stat_connection_info_t connection_info = {};
	sr_connection_id_t con_id;
	
	printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX sr_stat_process_connection_ut started\n");

	connection_info.con_id.saddr.v4addr = 0xAABBCC01;
	connection_info.con_id.daddr.v4addr = 0xAABBCC02;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4000;
	connection_info.con_id.dport = 5000;
	connection_info.rx_bytes = 500;
	connection_info.rx_msgs = 5;
	connection_info.tx_bytes = 600;
	connection_info.tx_msgs = 6;

	if ((rc = sr_stat_process_connection_hash_update(4455, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}

        // Add another counters to the same socket_id
	connection_info.con_id.saddr.v4addr = 0xAABBCC01;
	connection_info.con_id.daddr.v4addr = 0xAABBCC02;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4000;
	connection_info.con_id.dport = 5000;
	connection_info.rx_bytes = 100;
	connection_info.rx_msgs = 10;
	connection_info.tx_bytes = 200;
	connection_info.tx_msgs = 20;

	if ((rc = sr_stat_process_connection_hash_update(4455, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}

	sal_printf("Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800\n");
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");

	// Add another socket to the same process
	connection_info.con_id.saddr.v4addr = 0xAABBCC03;
	connection_info.con_id.daddr.v4addr = 0xAABBCC04;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4001;
	connection_info.con_id.dport = 5001;
	connection_info.rx_bytes = 100;
	connection_info.rx_msgs = 10;
	connection_info.tx_bytes = 200;
	connection_info.tx_msgs = 20;

	if ((rc = sr_stat_process_connection_hash_update(4455, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}

	sal_printf("v1 Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800\n");
	sal_printf("v1 Expect connection 4001,5001 rx_msg:10 rx_bytes:100 tx_msgs:20 tx_bytes:200\n");
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");

	//Add another process
	connection_info.con_id.saddr.v4addr = 0xAABBCC05;
	connection_info.con_id.daddr.v4addr = 0xAABBCC06;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4002;
	connection_info.con_id.dport = 5002;
	connection_info.rx_bytes = 400;
	connection_info.rx_msgs = 40;
	connection_info.tx_bytes = 500;
	connection_info.tx_msgs = 50;

	if ((rc = sr_stat_process_connection_hash_update(4456, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}

	sal_printf("4455 Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800\n");
	sal_printf("4455 Expect connection 4001,5001 rx_msg:10 rx_bytes:100 tx_msgs:20 tx_bytes:200\n");
	sal_printf("4456 Expect connection 4002,5002 rx_msg:40 rx_bytes:400 tx_msgs:50 tx_bytes:500\n");
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");

        // Add connnection to 4556 
	connection_info.con_id.saddr.v4addr = 0xAABBCC05;
	connection_info.con_id.daddr.v4addr = 0xAABBCC06;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4003;
	connection_info.con_id.dport = 5003;
	connection_info.rx_bytes = 70;
	connection_info.rx_msgs = 7;
	connection_info.tx_bytes = 50;
	connection_info.tx_msgs = 5;

	if ((rc = sr_stat_process_connection_hash_update(4456, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}

	sal_printf("4455 Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800\n");
	sal_printf("4455 Expect connection 4001,5001 rx_msg:10 rx_bytes:100 tx_msgs:20 tx_bytes:200\n");
	sal_printf("4456 Expect connection 4002,5002 rx_msg:40 rx_bytes:400 tx_msgs:50 tx_bytes:500\n");
	sal_printf("4456 Expect connection 4003,5003 rx_msg:7  rx_bytes:70  tx_msgs:5 tx_bytes:50\n");
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");

	// Add counters to connection 4003,5003
	connection_info.con_id.saddr.v4addr = 0xAABBCC05;
	connection_info.con_id.daddr.v4addr = 0xAABBCC06;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4003;
	connection_info.con_id.dport = 5003;
	connection_info.rx_bytes = 10;
	connection_info.rx_msgs = 1;
	connection_info.tx_bytes = 10;
	connection_info.tx_msgs = 1;

	if ((rc = sr_stat_process_connection_hash_update(4456, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}

	sal_printf("4455 Expect connection 4000,5000 rx_msg:15 rx_bytes:600 tx_msgs:26 tx_bytes:800\n");
	sal_printf("4455 Expect connection 4001,5001 rx_msg:10 rx_bytes:100 tx_msgs:20 tx_bytes:200\n");
	sal_printf("4456 Expect connection 4002,5002 rx_msg:40 rx_bytes:400 tx_msgs:50 tx_bytes:500\n");
	sal_printf("4456 Expect connection 4003,5003 rx_msg:8  rx_bytes:80  tx_msgs:6 tx_bytes:60\n");
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");

	// Add another 2 processes
	connection_info.con_id.saddr.v4addr = 0xAABBCC07;
	connection_info.con_id.daddr.v4addr = 0xAABBCC08;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4004;
	connection_info.con_id.dport = 5004;
	connection_info.rx_bytes = 10;
	connection_info.rx_msgs = 1;
	connection_info.tx_bytes = 10;
	connection_info.tx_msgs = 1;

	if ((rc = sr_stat_process_connection_hash_update(4460, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}

	connection_info.con_id.saddr.v4addr = 0xAABBCC09;
	connection_info.con_id.daddr.v4addr = 0xAABBCC0A;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4005;
	connection_info.con_id.dport = 5005;
	connection_info.rx_bytes = 10;
	connection_info.rx_msgs = 1;
	connection_info.tx_bytes = 10;
	connection_info.tx_msgs = 1;

	if ((rc = sr_stat_process_connection_hash_update(4461, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}
	
	// Add a process that resides in the same bucket as 4455
	connection_info.con_id.saddr.v4addr = 0xAABBCC0B;
	connection_info.con_id.daddr.v4addr = 0xAABBCC0C;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4006;
	connection_info.con_id.dport = 5006;
	connection_info.rx_bytes = 19;
	connection_info.rx_msgs = 5;
	connection_info.tx_bytes = 20;
	connection_info.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}
	sal_printf("===============================================================================\n");
	sr_stat_process_connection_hash_print();
	sal_printf("===================================================================================\n");

	sal_printf("======================= EXEC ==================================================\n");
	if ((rc = sr_stat_process_connection_hash_exec_for_process(4455, ut_cb)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_exec_for_process FAILED !!!\n");
		return;
	}

	sal_printf("====== start DELETE ==============================================\n");
	// Delete the first prrocess, There are 2 processes in the same bucket
	if ((rc = sr_stat_process_connection_hash_delete(4455)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection__hash_delete_process FAILED !!!\n");
		return;
	}
	sal_printf("====== After delete process 4455 ==============================================\n");
	sr_stat_process_connection_hash_print();
	sal_printf("===================================================================================\n");

	// Delete a process from the midle
	if ((rc = sr_stat_process_connection_hash_delete(4460)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection__hash_delete_process FAILED !!!\n");
		return;
	}
	sal_printf("====== After delete process 4460 ==============================================\n");
	sr_stat_process_connection_hash_print();
	sal_printf("===================================================================================\n");

	// Delete the last process
	if ((rc = sr_stat_process_connection_hash_delete(4461)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection__hash_delete_process FAILED !!!\n");
		return;
	}
	sal_printf("====== After delete process 4461 the last ==============================================\n");
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");
	sal_printf("========  Before Delete connections ===============================================\n");

	// Check deletion of socket.
 	// Add 3 sockets to a process
	// Add a process that resides inn the same bucket as 4455
	connection_info.con_id.saddr.v4addr = 0xAABBCC0D;
	connection_info.con_id.daddr.v4addr = 0xAABBCC0E;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4007;
	connection_info.con_id.dport = 5007;
	connection_info.rx_bytes = 19;
	connection_info.rx_msgs = 5;
	connection_info.tx_bytes = 20;
	connection_info.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}
	connection_info.con_id.saddr.v4addr = 0xAABBCC0F;
	connection_info.con_id.daddr.v4addr = 0xAABBCC10;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4008;
	connection_info.con_id.dport = 5008;
	connection_info.rx_bytes = 19;
	connection_info.rx_msgs = 5;
	connection_info.tx_bytes = 20;
	connection_info.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}
	connection_info.con_id.saddr.v4addr = 0xAABBCC11;
	connection_info.con_id.daddr.v4addr = 0xAABBCC12;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4009;
	connection_info.con_id.dport = 5009;
	connection_info.rx_bytes = 19;
	connection_info.rx_msgs = 5;
	connection_info.tx_bytes = 20;
	connection_info.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}
	connection_info.con_id.saddr.v4addr = 0xAABBCC13;
	connection_info.con_id.daddr.v4addr = 0xAABBCC14;
	connection_info.con_id.ip_proto = 6;
	connection_info.con_id.sport = 4010;
	connection_info.con_id.dport = 5010;
	connection_info.rx_bytes = 19;
	connection_info.rx_msgs = 5;
	connection_info.tx_bytes = 20;
	connection_info.tx_msgs = 7;

	if ((rc = sr_stat_process_connection_hash_update(5455, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}

	sal_printf("===============================================================================\n");
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");

	sal_printf("============ Delete the first connection  ===========================================\n");
	con_id.saddr.v4addr = 0xAABBCC0D;
	con_id.daddr.v4addr = 0xAABBCC0E;
	con_id.ip_proto = 6;
	con_id.sport = 4007;
	con_id.dport = 5007;
	rc = sr_stat_process_connection_delete_socket(5455, &con_id);
	printf("After delete rc:%d \n", rc);
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");
	sal_printf("============ Delete a midle connection  ===========================================\n");
	con_id.saddr.v4addr = 0xAABBCC0F;
	con_id.daddr.v4addr = 0xAABBCC10;
	con_id.ip_proto = 6;
	con_id.sport = 4008;
	con_id.dport = 5008;
	sr_stat_process_connection_delete_socket(5455, &con_id);
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");
	sal_printf("============ Delete the last connection  ===========================================\n");
	con_id.saddr.v4addr = 0xAABBCC13;
	con_id.daddr.v4addr = 0xAABBCC14;
	con_id.ip_proto = 6;
	con_id.sport = 4010;
	con_id.dport = 5010;
	sr_stat_process_connection_delete_socket(5455, &con_id);
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");
	sal_printf("============ Delete the connection 4009,5009  ===========================================\n");
	con_id.saddr.v4addr = 0xAABBCC11;
	con_id.daddr.v4addr = 0xAABBCC12;
	con_id.ip_proto = 6;
	con_id.sport = 4009;
	con_id.dport = 5009;
	sr_stat_process_connection_delete_socket(5455, &con_id);
	sr_stat_process_connection_hash_print();
	printf("===================================================================================\n");
	sal_printf("============ Delete the lonly connection 4006,5006 ===========================================\n");
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
	connection_info.rx_bytes = 19;
	connection_info.rx_msgs = 5;
	connection_info.tx_bytes = 20;
	connection_info.tx_msgs = 7;
	if ((rc = sr_stat_process_connection_hash_update(7788, &connection_info)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection_hash_update_process FAILED !!!\n");
		return;
	}
	sr_stat_process_connection_delete_socket(7788, &connection_info.con_id);
	printf("===================================================================================\n");
	sr_stat_process_connection_hash_print();
	if ((rc = sr_stat_process_connection_hash_delete(7788)) != SR_SUCCESS) {
		sal_printf("sr_stat_process_connection__hash_delete_process FAILED !!!\n");
		return;
	}
	printf("===== After delete ================================================================\n");
	sr_stat_process_connection_hash_print();
	sr_stat_process_connection_delete_empty_process();
	printf("===== After delete  process ================================================================\n");
	sr_stat_process_connection_hash_print();
}
#ifdef UNIT_TEST
#endif

