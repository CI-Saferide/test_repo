#include "sr_special_hash.h"
#include "sr_stat_connection.h"
#include "sal_linux.h"
#include "sr_event_collector.h"
#include "sr_stat_port.h"
#include "sr_stat_analysis.h"
#include "sr_shmem.h"

#define LRU_ALLOCATION_SIZE 500
#define LRU_ALLOCATION_MAX_SIZE 2000
#define LRU_ADD_SIZE 100

static sr_special_hash_table_t *connection_table;

typedef struct LRU_container {
	SR_ATOMIC ind;
	SR_ATOMIC ref_count;
	SR_U32 size;
	sr_connection_data_t **objects;
} LRU_container_t;

static LRU_container_t *LRU_update, *LRU_transmit;
static SR_BOOL LRU_allocate_more, LRU_allocate_more2;

void con_debug_print(sr_connection_id_t *con)
{
	if ((con->dport > 7700 && con->dport < 7800) ||
			(con->sport > 7000 && con->sport < 8000)) {
		sal_printf("Connection: proto:%d saddr:%x dassdr:%x sport:%d dport:%d \n",
                	con->ip_proto,
                	con->saddr.v4addr,
                	con->daddr.v4addr,
                	con->sport,
                	con->dport);
	}
}

void old_print(sr_connection_data_t *con)
{
	if ((jiffies - con->time_count) /  HZ > 300 && !con->pid) { 
		sal_printf("PPPPPP3 Connection: proto:%d saddr:%x dassdr:%x sport:%d dport:%d pid:%d time:%d\n",
                	con->con_id.ip_proto,
                	con->con_id.saddr.v4addr,
                	con->con_id.daddr.v4addr,
                	con->con_id.sport,
                	con->con_id.dport,
                	con->pid,
			(jiffies - con->time_count) /  HZ);
	}
}

static SR_U32 sr_connection_create_key(void *key)
{
	sr_connection_id_t *con_id = (sr_connection_id_t *)key;
	SR_U32 sum;

	sum = con_id->ip_proto + con_id->saddr.v4addr + con_id->daddr.v4addr +
		con_id->sport + con_id->dport;
	
	return sum; // TODO: create a better distribution by replacing function
}

static SR_U32 sr_connection_increase_LRU_arr(LRU_container_t *LRU_container, SR_U32 size)
{
	sr_connection_data_t **tmp;

	if (LRU_container->size >= LRU_ALLOCATION_MAX_SIZE) {
		sal_kernel_print_alert("LRU reached it maximum size\n");
		return SR_ERROR;
	}

	tmp = LRU_container->objects;
	if (!(LRU_container->objects = SR_ZALLOC(sizeof(sr_connection_data_t *) * LRU_container->size))) {
		sal_kernel_print_alert("Error: Failed to resize memory\n");
		return SR_ERROR;
	}
	LRU_container->size += size;
	SR_FREE(tmp);

	return SR_SUCCESS;
}

SR_U32 sr_connection_transmit(void)
{
	LRU_container_t *LRU_tmp;
   	SR_U32 i, ind, count = 0;
	struct sr_ec_connection_stat_t con = {};
	struct sr_ec_connection_transmit_t con_tran;

	LRU_tmp = LRU_update;
	LRU_update = LRU_transmit;
	LRU_transmit = LRU_tmp;

	// wait for ref count 0
	while (SR_ATOMIC_READ(&(LRU_transmit->ref_count))) {
#ifdef SR_STAT_ANALYSIS_DEBUG
		printk("STAT DEBUG connection transmit WAIT ref count\n");
#endif
		sal_schedule_timeout(100000);
	}

	ind = SR_ATOMIC_READ(&(LRU_transmit->ind));
	// The last item in the array will be NULL in order to be able to stop even if the ind was increaed beyond size of array.
   	for (i = 0; i <= ind && LRU_transmit->objects[i]; i++) { 
		con.con_id.ip_proto = LRU_transmit->objects[i]->con_id.ip_proto;
		con.con_id.source_addr.v4addr = LRU_transmit->objects[i]->con_id.saddr.v4addr;
		con.con_id.remote_addr.v4addr = LRU_transmit->objects[i]->con_id.daddr.v4addr;
		con.con_id.sport = LRU_transmit->objects[i]->con_id.sport;
		con.con_id.dport = LRU_transmit->objects[i]->con_id.dport;
		if (con.con_id.ip_proto == IPPROTO_UDP && !LRU_transmit->objects[i]->pid) {
			con.pid = sr_stat_port_find_pid(con.con_id.sport); 
		} else
			con.pid = LRU_transmit->objects[i]->pid;
		con.rx_msgs= LRU_transmit->objects[i]->rx_msgs;
		con.rx_bytes= LRU_transmit->objects[i]->rx_bytes;
		con.tx_msgs= LRU_transmit->objects[i]->tx_msgs;
		con.tx_bytes= LRU_transmit->objects[i]->tx_bytes;
		count++;
		sr_ec_send_event(MOD2STAT_BUF, SR_EVENT_STATS_CONNECTION, &con);
	}
	con_tran.count = count;
	sr_ec_send_event(MOD2STAT_BUF, SR_EVENT_STATS_CONNECTION_TRANSMIT, &con_tran);
	SR_ATOMIC_SET(&(LRU_transmit->ind), -1);
	if (LRU_allocate_more2) {
#ifdef SR_STAT_ANALYSIS_DEBUG
	sal_printf("LRU DEBUG LRU_allocate_more2\n");
#endif
		if (sr_connection_increase_LRU_arr(LRU_transmit, LRU_ADD_SIZE) != SR_SUCCESS) {
			sal_printf("sr_connection_increase_LRU_arr failed to resize LRU array\n");
			return SR_ERROR;
		}
		LRU_allocate_more = SR_FALSE;
		LRU_allocate_more2 = SR_FALSE;
	} else if (LRU_allocate_more) {
#ifdef SR_STAT_ANALYSIS_DEBUG
	sal_printf("LRU DEBUG LRU_allocate_more\n");
#endif
		if (sr_connection_increase_LRU_arr(LRU_transmit, LRU_ADD_SIZE) != SR_SUCCESS) {
			sal_printf("sr_connection_increase_LRU_arr failed to resize LRU array\n");
			return SR_ERROR;
		}
		LRU_allocate_more2 = SR_TRUE;
	} else {
		memset(LRU_transmit->objects, 0, sizeof(sr_connection_data_t *) * LRU_transmit->size);
	}
	
	return SR_SUCCESS;
}

static void sr_connection_print_LRU(void)
{
	SR_U32 i,ind = SR_ATOMIC_READ(&(LRU_update->ind));

	for (i = 0; i <= ind; i++) { 
		if (!LRU_update->objects[i]) {
			sal_printf("ERROR NULL in ind:%d \n", i);
			break;
		}
		sal_printf("------- LRU saddr:%x daddr:%x proto:%d sport:%d dport:%d rxbytes:%d rxmsgs:%d txbytes:%d txmsgs:%d \n",
		LRU_update->objects[i]->con_id.saddr.v4addr, LRU_update->objects[i]->con_id.daddr.v4addr,
		LRU_update->objects[i]->con_id.ip_proto, LRU_update->objects[i]->con_id.sport, 
		LRU_update->objects[i]->con_id.dport, LRU_update->objects[i]->rx_bytes, LRU_update->objects[i]->rx_msgs,
		LRU_update->objects[i]->tx_bytes, LRU_update->objects[i]->tx_msgs);
	}
}

static SR_U32 sr_connection_comp(void *data, void *key)
{
	sr_connection_data_t *con_data = (sr_connection_data_t *)data;
	sr_connection_id_t *con_id = (sr_connection_id_t *)key;

	 if (con_data->con_id.saddr.v4addr == con_id->saddr.v4addr &&
             con_data->con_id.daddr.v4addr == con_id->daddr.v4addr &&
             con_data->con_id.ip_proto == con_id->ip_proto &&
             con_data->con_id.sport == con_id->sport &&
             con_data->con_id.dport == con_id->dport) {
                return 0;
        }

        return 1;
}

static void sr_connection_print(void *data)
{
	sr_connection_data_t *con = (sr_connection_data_t *)data;

        //con_debug_print(&(con->con_id));
        old_print(con);
/*
	sal_printf("Connection: proto:%d saddr:%x dassdr:%x sport:%d dport:%d pid:%d rx_msgs:%u rx_bytes:%u tx_mgs:%u tx_bytes:%u \n",
                con->con_id.ip_proto,
                con->con_id.saddr.v4addr,
                con->con_id.daddr.v4addr,
                con->con_id.sport,
                con->con_id.dport,
                con->pid,
                con->rx_msgs,
                con->rx_bytes,
                con->tx_msgs,
                con->tx_bytes);
	}
*/
}

static LRU_container_t *create_LRU(void)
{
	LRU_container_t *LRU_container;

	if (!(LRU_container = SR_ZALLOC(sizeof(LRU_container_t)))) {
            sal_kernel_print_alert("Error: Failed to allocate memory\n");
            return NULL;
	}
	LRU_container->size = LRU_ALLOCATION_SIZE;
	SR_ATOMIC_SET(&(LRU_container->ind), -1);
	SR_ATOMIC_SET(&(LRU_container->ref_count), 0);
	if (!(LRU_container->objects = SR_ZALLOC(sizeof(sr_connection_data_t *) * LRU_ALLOCATION_SIZE))) {
            sal_kernel_print_alert("Error: Failed to allocate memory\n");
            return NULL;
	}

	return LRU_container;
}

static void free_LRU(LRU_container_t *lru)
{
	if (lru && lru->objects)
		SR_FREE(lru->objects);
	if (lru)
		SR_FREE(lru);
}

static SR_U32 add_object_LRU(sr_connection_data_t *con)
{
	LRU_container_t *LRU_ptr = LRU_update;
	SR_U32 ind;

	SR_ATOMIC_INC(&(LRU_ptr->ref_count));
	ind = SR_ATOMIC_INC_RETURN(&(LRU_ptr->ind));
	if (ind >= LRU_ptr->size - 1) {
		// No more space at buffer, buffer is allocated at next iterration, stats are lost 
		LRU_allocate_more = SR_TRUE;
		goto out;
	}
	LRU_ptr->objects[ind] = con;
	con->LRU_ptr = LRU_ptr;

out:
	SR_ATOMIC_DEC(&(LRU_ptr->ref_count));
	return SR_SUCCESS;
}

SR_U32 sr_stat_connection_init(void)
{
	sr_special_hash_ops_t ops = {};

	ops.create_key = sr_connection_create_key;
	ops.comp = sr_connection_comp;
	ops.print = sr_connection_print;
	if (!(connection_table = sr_special_hash_new_table(8192, &ops)))
        if (!connection_table) {
                sal_kernel_print_alert("Failed to allocate hash table!\n");
                return SR_ERROR;
        }
	if (!(LRU_update = create_LRU())) {
		sal_kernel_print_alert("Failed create LRU!\n");
		return SR_ERROR;
        }
	if (!(LRU_transmit = create_LRU())) {
		sal_kernel_print_alert("Failed create LRU!\n");
		return SR_ERROR;
        }

        return SR_SUCCESS;
}

void sr_stat_connection_uninit(void)
{
	sr_special_hash_free_table(connection_table);
	free_LRU(LRU_update);
	free_LRU(LRU_transmit);
}

SR_U32 sr_stat_connection_insert(sr_connection_data_t *con_data, SR_U16 flags)
{
	sr_connection_data_t *hash_con_data;
	SR_BOOL is_atomic = SR_FALSE, is_blocking = SR_TRUE;
#ifdef SR_STAT_ANALYSIS_DEBUG
	static SR_U32 count;
#endif

	// Do not insert new connections when user mode is not runnig.
	if (!sr_stat_analysis_um_is_running()) {
		return SR_SUCCESS;
	}

	if (!con_data)
		return SR_ERROR;

	if (!con_data->con_id.saddr.v4addr || !con_data->con_id.daddr.v4addr ||
		!con_data->con_id.sport || !con_data->con_id.dport) {
		return SR_SUCCESS;
	}

	if (flags & SR_CONNECTION_ATOMIC)
		is_atomic = SR_TRUE;
	if (flags & SR_CONNECTION_NONBLOCKING)
		is_blocking = SR_FALSE;

	hash_con_data = SR_KZALLOC_ATOMIC_SUPPORT(is_atomic, sr_connection_data_t);
	if (!hash_con_data) {
            sal_kernel_print_alert("Error: Failed to allocate memory\n");
            return SR_ERROR;
        }
	memcpy(hash_con_data, con_data, sizeof(sr_connection_data_t));

#ifdef SR_STAT_ANALYSIS_DEBUG
	count++;
	if (count % 100 == 0) {
		printk("STATS DEBUG Create connection:%d --- proto:%d saddr:%x daddr:%x sport:%d dport:%d \n", count, 
			con_data->con_id.ip_proto,
			con_data->con_id.saddr.v4addr,
			con_data->con_id.daddr.v4addr,
			con_data->con_id.sport,
			con_data->con_id.dport);
	}
#endif
	if (sr_special_hash_insert(connection_table, &(hash_con_data->con_id), hash_con_data, is_blocking, is_atomic) != SR_SUCCESS) {
            sal_kernel_print_alert("Error: Failed sr_special_hash_insert\n");
            return SR_ERROR;
        }
	sal_update_time_counter(&(hash_con_data->time_count));
	add_object_LRU(hash_con_data);

	return SR_SUCCESS;
}

sr_connection_data_t *sr_stat_connection_lookup(sr_connection_id_t *con)
{
	return (sr_connection_data_t *)sr_special_hash_lookup(connection_table, con);
}

SR_U32 sr_stat_connection_update_counters(sr_connection_data_t *con_data, SR_U32 pid, SR_U32 rx_bytes, SR_U32 rx_msgs, SR_U32 tx_bytes, SR_U32 tx_msgs)
{
	if (!con_data)
		return SR_ERROR;
	if (pid && !con_data->pid)
		con_data->pid = pid;
	con_data->rx_bytes += rx_bytes;
	con_data->rx_msgs += rx_msgs;
	con_data->tx_bytes += tx_bytes;
	con_data->tx_msgs += tx_msgs;
	sal_update_time_counter(&(con_data->time_count));
	if (con_data->LRU_ptr != LRU_update)
		add_object_LRU(con_data);
		
	return SR_SUCCESS;	
}

void sr_stat_connection_soft_delete(sr_connection_id_t *con)
{
	sr_special_hash_soft_delete(connection_table, con);
}

void sr_stat_connection_garbage_collection(void)
{
	sr_special_hash_garbage_collection(connection_table);
}

void sr_stat_connection_print(SR_BOOL is_print_LRU)
{
	SR_U32 count;

	sal_printf("connection HASH:\n");
	count = sr_special_hash_print_table(connection_table);
	if (is_print_LRU) {
		sal_printf("LRU:\n");
		sr_connection_print_LRU();
	}
	sal_printf("Connection HASH count:%d\n", count);
}

static SR_BOOL delete_old_connection(void *data)
{
	sr_connection_data_t *con_data = (sr_connection_data_t *)data;

	return sal_elapsed_time_secs(con_data->time_count) > SR_CONNECTIOLN_AGED_THRESHHOLD;
}

void sr_stat_connection_aging_cleanup(void)
{
#ifdef SR_STAT_ANALYSIS_DEBUG
	printk("CCCCCCCCCCCCCC Aging cleanup\n");
#endif

	sr_special_hash_soft_cleanup(connection_table, delete_old_connection);
}


void sr_stat_connection_ut(void)
{
	sr_connection_data_t con, *conp;
	sr_connection_id_t con_id = {};
        
	SR_U32 rc;

	sal_printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX connection UT !!!!\n");

        con.con_id.saddr.v4addr = 0xAAAAAAAA;
        con.con_id.daddr.v4addr = 0xBBBBBBBB;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6666;
        con.con_id.dport = 7777;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA1;
        con.con_id.daddr.v4addr = 0xBBBBBBB1;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6661;
        con.con_id.dport = 7771;
        con.pid = 12341;
        con.rx_msgs = 101;
        con.rx_bytes = 1001;
        con.tx_msgs = 201;
        con.tx_bytes = 2001;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}

        con.con_id.saddr.v4addr = 0xAAAAAAA2;
        con.con_id.daddr.v4addr = 0xBBBBBBB2;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
	sr_stat_connection_print(SR_FALSE);
	
        con_id.saddr.v4addr = 0xAAAAAAAA;
        con_id.daddr.v4addr = 0xBBBBBBBB;
        con_id.ip_proto = 6;
        con_id.sport = 6666;
        con_id.dport = 7777;
	conp = sr_stat_connection_lookup(&con_id);
	if (!conp)
		sal_printf("Fail fetching connection !!!!\n");
	else {
		sal_printf("SUSSCESS fetching connection:\n");
		sr_connection_print(conp);
	}
	conp->rx_bytes += 1010;
	conp->rx_msgs += 2;
	sal_printf("----- Increment rx bytes by 1010 ans msgsx by 2\n"); 

        con_id.saddr.v4addr = 0xAAAAAAAA;
        con_id.daddr.v4addr = 0xBBBBBBBB;
        con_id.ip_proto = 6;
        con_id.sport = 6666;
        con_id.dport = 7777;
	conp = sr_stat_connection_lookup(&con_id);
	if (!conp)
		sal_printf("Fail fetching connection !!!!\n");
	else {
		sal_printf("SUSSCESS fetching connection:\n");
		sr_connection_print(conp);
	}

	sr_stat_connection_soft_delete(&con_id);
	sal_printf("----- Soft Delete con 0xAAAAAAAA 0xBBBBBBBB 6 6666 7777\n"); 
	sr_stat_connection_print(SR_FALSE);

        con_id.saddr.v4addr = 0xAAAAAAA1;
        con_id.daddr.v4addr = 0xBBBBBBB1;
        con_id.ip_proto = 6;
        con_id.sport = 6661;
        con_id.dport = 7771;
	conp = sr_stat_connection_lookup(&con_id);
	if (!conp)
		sal_printf("Fail fetching connection !!!!\n");
	sr_stat_connection_update_counters(conp, 1000, 10, 1, 20, 2);
	sal_printf("Printing LRU expect :\n");
	sal_printf("LRU saddr:aaaaaaaa daddr:bbbbbbbb proto:6 sport:6666 dport:7777\n");
	sal_printf("LRU saddr:aaaaaaa1 daddr:bbbbbbb1 proto:6 sport:6661 dport:7771 rxbytes:2021 rxmsgs:203 txbytes:1011 txmsgs:102\n"); 
	sal_printf("LRU saddr:aaaaaaab daddr:bbbbbbba proto:6 sport:6667 dport:7776\n"); 
	sr_connection_print_LRU();

        con.con_id.saddr.v4addr = 0xAAAAAAA3;
        con.con_id.daddr.v4addr = 0xBBBBBBB3;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
	sr_connection_print_LRU();

	sr_connection_transmit();

	/* Update an old connection */
        con_id.saddr.v4addr = 0xAAAAAAA1;
        con_id.daddr.v4addr = 0xBBBBBBB1;
        con_id.ip_proto = 6;
        con_id.sport = 6661;
        con_id.dport = 7771;
	conp = sr_stat_connection_lookup(&con_id);
	if (!conp)
		sal_printf("Fail fetching connection !!!!\n");
	sr_stat_connection_update_counters(conp, 1000, 10, 1, 20, 2);

	sal_printf("Printing LRU expect :\n");
	sal_printf("LRU saddr:aaaaaaa1 daddr:bbbbbbb1 proto:6 sport:6661 dport:7771 rxbytes:2041 rxmsgs:205 txbytes:1021 txmsgs:103\n"); 
	sr_connection_print_LRU();

	sr_connection_transmit();

        con.con_id.saddr.v4addr = 0xAAAAAAA1;
        con.con_id.daddr.v4addr = 0xBBBBBBB1;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA2;
        con.con_id.daddr.v4addr = 0xBBBBBBB2;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA3;
        con.con_id.daddr.v4addr = 0xBBBBBBB3;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA4;
        con.con_id.daddr.v4addr = 0xBBBBBBB4;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA5;
        con.con_id.daddr.v4addr = 0xBBBBBBB5;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
	printk("XXXXXXXXXXXXXXXXX print LRU with 5\n");
	sr_connection_print_LRU();

	sr_connection_transmit();
        con.con_id.saddr.v4addr = 0xAAAAAAA1;
        con.con_id.daddr.v4addr = 0xBBBBBBB1;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA2;
        con.con_id.daddr.v4addr = 0xBBBBBBB2;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA3;
        con.con_id.daddr.v4addr = 0xBBBBBBB3;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA4;
        con.con_id.daddr.v4addr = 0xBBBBBBB4;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
        con.con_id.saddr.v4addr = 0xAAAAAAA5;
        con.con_id.daddr.v4addr = 0xBBBBBBB5;
        con.con_id.ip_proto = 6;
        con.con_id.sport = 6667;
        con.con_id.dport = 7776;
        con.pid = 12345;
        con.rx_msgs = 100;
        con.rx_bytes = 1000;
        con.tx_msgs = 200;
        con.tx_bytes = 2000;
	if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
 		sal_printf("ERROR failed sr_stat_connection_insert\n");
		return;
	}
	printk("XXXXXXXXXXXXXXXXX print LRU with 5\n");
	sr_connection_print_LRU();
}
