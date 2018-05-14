#ifndef __SR_CLS_CONN_OBJ_H_
#define __SR_CLS_CONN_OBJ_H_ 

#include "sal_linux.h"
#include "sr_cls_network_common.h"

typedef struct sr_conn_obj_item {
        sr_connection_id_t con_id;
        SR_TIME_COUNT time_stamp;
} sr_conn_obj_item_t;

SR_32 sr_conn_obj_init(void);
void sr_conn_obj_uninit(void);
SR_32 sr_con_obj_hash_delete_all(void);
SR_32 sr_conn_obj_insert(sr_connection_id_t *con_id, SR_BOOL is_try);
sr_conn_obj_item_t *sr_con_obj_hash_get(sr_connection_id_t *con_id, SR_BOOL is_try);
void sr_conn_obj_hash_print(void);
SR_32 sr_con_obj_exec_for_each(SR_32 (*cb)(void *hash_data, void *data), SR_BOOL is_try);

#endif
