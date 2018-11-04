#ifndef __SR_CLS_SK_PROCESS_
#define __SR_CLS_SK_PROCESS_

#include "sr_types.h"
#include "dispatcher.h"

typedef struct sk_process_info {
	SR_32 	pid;
	SR_32 	uid;
	SR_U8 	exec[SR_MAX_PATH_SIZE];
	SR_TIME_COUNT time_stamp;
} sk_process_info_t;

typedef struct sk_process_item {
	void *sk;
	sk_process_info_t process_info;
} sk_process_item_t;

void sr_cls_sk_process_hash_uninit(void);
SR_32 sr_cls_sk_process_hash_init(void);
SR_32 sr_cls_sk_process_hash_update(void *sk, sk_process_info_t *process_info);
SR_32 sr_cls_sk_process_hash_delete(void *sk);
sk_process_item_t *sr_cls_sk_process_hash_get(void *sk);
SR_32 sr_cls_process_hash_delete_all(void);
void sr_cls_sk_process_hash_print(void);
void sr_cls_sl_process_hash_ut(void);
SR_32 sr_cls_sk_process_exec_for_each(SR_32 (*cb)(void *hash_data, void *data));
SR_32 sr_sk_process_cleanup(void);


#endif
