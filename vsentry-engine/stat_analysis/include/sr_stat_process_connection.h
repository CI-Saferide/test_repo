#ifndef __PROCESS_CONNECTION__
#define __PROCESS_CONNECTION__

//#include "sr_ec_common.h"
#include "sr_cls_network_common.h"
#include "sr_types.h"

typedef struct sr_stat_con_stats {
	SR_U64 rx_msgs;
	SR_U64 rx_bytes;
	SR_U64 tx_msgs;
	SR_U64 tx_bytes;
} sr_stat_con_stats_t;

typedef struct sr_stat_connection_info {
	sr_connection_id_t con_id;
	SR_U64 time;
	SR_U64 transmit_time;
	SR_BOOL is_updated;
	sr_stat_con_stats_t con_stats;
	sr_stat_con_stats_t prev_con_stats;
	sr_stat_con_stats_t max_con_stats;
} sr_stat_connection_info_t;

typedef struct sr_stat_process_sample {
	SR_BOOL is_updated;
	SR_U32 new_cons_last_period;
	SR_U32 max_new_cons;
} sr_stat_process_sample_t;

SR_32 sr_stat_process_connection_hash_init(void);
void sr_stat_process_connection_hash_uninit(void);
void sr_stat_process_connection_hash_print(void);
SR_32 sr_stat_process_connection_hash_update(SR_U32 process_id, sr_stat_connection_info_t *connection_info);
SR_32 sr_stat_process_connection_hash_delete(SR_U32 process_id);
SR_32 sr_stat_process_connection_hash_exec_for_process(SR_U32 process_id, SR_32 (*cb)(SR_U32 process_id, sr_stat_connection_info_t *connection_info));
SR_32 sr_stat_process_connection_delete_socket(SR_U32 process_id, sr_connection_id_t *con_id);
SR_32 sr_stat_process_connection_delete_aged_connections(void);
SR_32 sr_stat_process_connection_delete_empty_process(void);
SR_32 sr_stat_process_connection_hash_finish_transmit(SR_U32 count);
SR_32 st_stats_process_connection_protect(void);
SR_32 st_stats_process_connection_learn(void);
void sr_stat_process_connection_ut(void);

#endif
