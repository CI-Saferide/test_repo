#include "sr_cls_sk_process.h"
#include "sr_gen_hash.h"
#include "sal_mem.h"
#include "sal_linux.h"

#define SK_PROCESS_HASH_SIZE 500
#define SR_SK_PROCESS_AGED_TIME 120
static struct sr_gen_hash *sk_process_hash;

SR_32 sk_process_comp(void *data_in_hash, void *comp_val)
{
	sk_process_item_t *sk_process_item = (sk_process_item_t *)data_in_hash;

	if (sk_process_item->sk == comp_val)
		return 0;

	return 1;
}

static SR_U32 sk_process_create_key(void *data)
{
	return (SR_U32)(long int)data;
}

void sk_process_print(void *data_in_hash)
{
	sk_process_item_t* ptr = (sk_process_item_t*)data_in_hash;

	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=sk proces sk %p pid %d uid %d",REASON,
		ptr->sk, ptr->process_info.pid, ptr->process_info.uid);
}

static SR_BOOL check_aged_cb(void *hash_data)
{
	sk_process_item_t *sk_process_item = (sk_process_item_t *)hash_data;

 	if (!hash_data)
		return SR_FALSE;
#ifdef SR_DEBUG
	if (sk_process_item->process_info.pid == 67333) { 
	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
		"%s= in sk aged cb sk:%p pid:%d uid:%d elpsed rime:%d", REASON,
		sk_process_item->sk, 
		sk_process_item->process_info.pid, 
		sk_process_item->process_info.uid, 
		sal_elapsed_time_secs(sk_process_item->process_info.time_stamp));
	}
#endif

	return (sal_elapsed_time_secs(sk_process_item->process_info.time_stamp) > SR_SK_PROCESS_AGED_TIME);
}

SR_32 sr_sk_process_cleanup(void)
{
	return sr_gen_hash_cond_delete_all(sk_process_hash, check_aged_cb);                
}

SR_32 sr_cls_sk_process_hash_init(void)
{
	hash_ops_t sk_process_hash_ops = {};

	sk_process_hash_ops.create_key = sk_process_create_key;
	sk_process_hash_ops.comp = sk_process_comp;
	sk_process_hash_ops.print = sk_process_print;
	if (!(sk_process_hash = sr_gen_hash_new(SK_PROCESS_HASH_SIZE, sk_process_hash_ops, SR_GEN_HASH_WRITE_LOCK | SR_GEN_HASH_SLOW_DELETE))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=failed to gen new hash table for sk process",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

void sr_cls_sk_process_hash_uninit(void)
{
	sr_gen_hash_destroy(sk_process_hash);
}

SR_32 sr_cls_sk_process_hash_delete_all(void)
{
	return sr_gen_hash_delete_all(sk_process_hash, 0);
}

SR_32 sr_cls_sk_process_hash_update(void *sk, sk_process_info_t *process_info)
{
	sk_process_item_t *sk_process_item;

	if (!(sk_process_item = sr_gen_hash_get(sk_process_hash, sk, 0))) {
		SR_Zalloc(sk_process_item, sk_process_item_t *, sizeof(sk_process_item_t));
		if (!sk_process_item) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to allocate buffer for sk process item enforce",REASON);
			return SR_ERROR;
		}
		sk_process_item->sk = sk;
		sk_process_item->process_info.pid = process_info->pid;
		sk_process_item->process_info.uid = process_info->uid;
		sal_update_time_counter(&(sk_process_item->process_info.time_stamp));
		if ((sr_gen_hash_insert(sk_process_hash, sk , sk_process_item, 0)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to insert mid to sk_process enforce table",REASON);
				return SR_ERROR;
		}
	} else {
		sal_update_time_counter(&(sk_process_item->process_info.time_stamp));
		sk_process_item->process_info.pid = process_info->pid;
		sk_process_item->process_info.uid = process_info->uid;
	}

	return SR_SUCCESS;
}

sk_process_item_t *sr_cls_sk_process_hash_get(void *sk)
{
	return sr_gen_hash_get(sk_process_hash, sk, 0);
}

void sr_cls_sk_process_hash_print(void)
{
	sr_gen_hash_print(sk_process_hash);
}

SR_32 ut_cb(void *hash_data, void *data) 
{
	sk_process_item_t *sk_process_item = (sk_process_item_t *)data;
	
	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=sk %p pid %d uid %d",REASON,
		sk_process_item->sk, 
		sk_process_item->process_info.pid, 
		sk_process_item->process_info.uid);
	
	return SR_SUCCESS;
}

SR_32 sr_cls_sk_process_exec_for_each(SR_32 (*cb)(void *hash_data, void *data))
{
	return sr_gen_hash_exec_for_each(sk_process_hash, cb, NULL, 0);
}
