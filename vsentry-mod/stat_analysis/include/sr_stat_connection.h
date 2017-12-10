#ifndef  __SR_CONNECTION__
#define  __SR_CONNECTION__
 
#include "sal_linux.h"
#include "sr_cls_network_common.h"

#define SR_CONNECTION_NONBLOCKING (1 << 0)
#define SR_CONNECTION_ATOMIC (1 << 1)

#define SR_CONNECTIOLN_AGED_THRESHHOLD 300 /* In seconds */

typedef struct sr_connection_data {
	sr_connection_id_t con_id;
	SR_U32 pid;
	SR_U32 rx_msgs;
	SR_U32 rx_bytes;
	SR_U32 tx_msgs;
	SR_U32 tx_bytes;
	void *LRU_ptr;
	SR_TIME_COUNT time_count;
} sr_connection_data_t;

SR_U32 sr_stat_connection_init(void);
void sr_stat_connection_uninit(void);
SR_U32 sr_stat_connection_insert(sr_connection_data_t *con_data, SR_U16 flags);
void sr_stat_connection_soft_delete(sr_connection_id_t *con);
sr_connection_data_t *sr_stat_connection_lookup(sr_connection_id_t *con);
SR_U32 sr_stat_connection_update_counters(sr_connection_data_t *con_data, SR_U32 pid, SR_U32 rx_bytes, SR_U32 rx_msgs, SR_U32 tx_bytes, SR_U32 tx_msgs);
void sr_stat_connection_print(SR_BOOL is_print_LRU);
SR_U32 sr_connection_transmit(void);
void sr_stat_connection_garbage_collection(void);
void sr_stat_connection_aging_cleanup(void);
void sr_stat_connection_ut(void);

#endif
