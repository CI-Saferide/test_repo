#ifndef __PROCESS_CONNECTION__
#define __PROCESS_CONNECTION__

//#include "sr_ec_common.h"
#include "sr_cls_network_common.h"
#include "sr_types.h"

typedef struct sr_stat_connection_info {
	sr_connection_id_t con_id;
	SR_U32 rx_msgs;
	SR_U32 rx_bytes;
	SR_U32 tx_msgs;
	SR_U32 tx_bytes;
	SR_U64 time;
} sr_stat_connection_info_t;

SR_32 sr_stat_process_connection_hash_init(void);
void sr_stat_process_connection_hash_uninit(void);
void sr_stat_process_connection_hash_print(void);
SR_32 sr_stat_process_connection_hash_update(SR_U32 process_id, sr_stat_connection_info_t *connection_info);
SR_32 sr_stat_process_connection_hash_delete(SR_U32 process_id);
SR_32 sr_stat_process_connection_hash_exec_for_process(SR_U32 process_id, SR_32 (*cb)(SR_U32 process_id, sr_stat_connection_info_t *connection_info));
SR_32 sr_stat_process_connection_delete_socket(SR_U32 process_id, sr_connection_id_t *con_id);
SR_32 sr_stat_process_connection_delete_aged_connections(void);
SR_32 sr_stat_process_connection_delete_empty_process(void);
void sr_stat_process_connection_ut(void);
#ifdef UNIT_TEST
#endif

#endif
