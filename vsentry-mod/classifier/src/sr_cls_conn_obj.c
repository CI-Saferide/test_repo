#include "sr_cls_conn_obj.h"
#include "sr_gen_hash.h"
#include "sal_mem.h"
#include "sal_linux.h"
#include "sr_cls_network_common.h"
#include "sr_event_collector.h"

#define CON_OBJS_HASH_SIZE 1024
#define SR_CONN_OBJ_AGED_TIME 30
static struct sr_gen_hash *conn_obj_hash;

SR_32 conn_obj_comp(void *data_in_hash, void *comp_val)
{
	sr_conn_obj_item_t *conn_obj_item = (sr_conn_obj_item_t *)data_in_hash;
	sr_connection_id_t *con_id = (sr_connection_id_t *)comp_val;

	if (conn_obj_item->con_id.saddr.v4addr == con_id->saddr.v4addr &&
		conn_obj_item->con_id.daddr.v4addr == con_id->daddr.v4addr &&
		conn_obj_item->con_id.sport == con_id->sport &&
		conn_obj_item->con_id.dport == con_id->dport &&
		conn_obj_item->con_id.ip_proto == con_id->ip_proto) {
		return 0;
	}

	return 1;
}

static SR_U32 conn_obj_create_key(void *data)
{
	sr_connection_id_t *con_id = (sr_connection_id_t *)data;

	return (SR_U32)(con_id->saddr.v4addr + con_id->daddr.v4addr +con_id->sport + con_id->dport + con_id->ip_proto);
}

static void conn_obj_print(void *data_in_hash)
{
	sr_conn_obj_item_t *conn_obj_item = (sr_conn_obj_item_t *)data_in_hash;

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
                "%s=ip learned saddr:%x daddr:%x ip proto:%d sport:%d dport:%d",MESSAGE,
		conn_obj_item->con_id.saddr.v4addr,
		conn_obj_item->con_id.daddr.v4addr,
		conn_obj_item->con_id.ip_proto,
		conn_obj_item->con_id.sport,
		conn_obj_item->con_id.dport);
}

static void conn_obj_free(void *data_in_hash)
{
        if (!data_in_hash)
                return;

        SR_Free(data_in_hash);
}

static SR_BOOL check_aged_cb(void *hash_data)
{
	sr_conn_obj_item_t *conn_obj_item = (sr_conn_obj_item_t *)hash_data;

	return (sal_elapsed_time_secs(conn_obj_item->time_stamp) > SR_CONN_OBJ_AGED_TIME);
}

SR_32 sr_conn_obj_cleanup(void)
{
	return sr_gen_hash_cond_delete_all(conn_obj_hash, check_aged_cb);                
}

SR_32 sr_conn_obj_init(void)
{
	hash_ops_t conn_obj_hash_ops = {};

	conn_obj_hash_ops.create_key = conn_obj_create_key;
	conn_obj_hash_ops.comp = conn_obj_comp;
	conn_obj_hash_ops.print = conn_obj_print;
	conn_obj_hash_ops.free = conn_obj_free;
	if (!(conn_obj_hash = sr_gen_hash_new(CON_OBJS_HASH_SIZE, conn_obj_hash_ops, SR_GEN_HASH_WRITE_LOCK | SR_GEN_HASH_READ_LOCK | SR_GEN_HASH_SLEEPLES_LOCK))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=failed to create hash table for connection objects",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

void sr_conn_obj_uninit(void)
{
	sr_gen_hash_destroy(conn_obj_hash);
}

SR_32 sr_con_obj_hash_delete_all(void)
{
	return sr_gen_hash_delete_all(conn_obj_hash, 0);
}

SR_32 sr_conn_obj_hash_insert(sr_connection_id_t *con_id, SR_BOOL is_try_lock)
{
	sr_conn_obj_item_t *conn_obj_item;
	SR_U8 hash_flags = 0;

	if (get_collector_state() == SR_TRUE)
		return SR_SUCCESS;

        SR_Zalloc(conn_obj_item, sr_conn_obj_item_t *, sizeof(sr_conn_obj_item_t));
        if (!conn_obj_item) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=learn hash update: memory allocation failed", REASON);
                return SR_ERROR;
        }

	if (is_try_lock)
		hash_flags |= SR_GEN_HASH_TRY_LOCK;
	memcpy(&(conn_obj_item->con_id), con_id, sizeof(sr_connection_id_t));
	sal_update_time_counter(&(conn_obj_item->time_stamp));
        if (sr_gen_hash_insert(conn_obj_hash, (void *)con_id, conn_obj_item, hash_flags) != SR_SUCCESS) {
				SR_Free(conn_obj_item);
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                               "%s=%s: sr_gen_hash_insert failed",REASON, __FUNCTION__);
                return SR_ERROR;
        }

        return SR_SUCCESS;
}

sr_conn_obj_item_t *sr_conn_obj_hash_get(sr_connection_id_t *con_id, SR_BOOL is_try_lock)
{
	SR_U8 hash_flags = 0;
	sr_conn_obj_item_t *conn_obj_item;

	if (is_try_lock)
		hash_flags |= SR_GEN_HASH_TRY_LOCK;
	if (!(conn_obj_item = sr_gen_hash_get(conn_obj_hash, con_id, hash_flags)))
		return NULL;
	sal_update_time_counter(&(conn_obj_item->time_stamp));
	
	return conn_obj_item;
}

void sr_conn_obj_hash_print(void)
{
	sr_gen_hash_print(conn_obj_hash);
}

SR_32 sr_con_obj_exec_for_each(SR_32 (*cb)(void *hash_data, void *data), SR_BOOL is_try_lock)
{
	SR_U8 hash_flags = 0;

	if (is_try_lock)
		hash_flags |= SR_GEN_HASH_TRY_LOCK;

	return sr_gen_hash_exec_for_each(conn_obj_hash, cb, NULL, hash_flags);
}
