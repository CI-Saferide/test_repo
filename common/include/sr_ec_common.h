#ifndef SR_EC_COMMON_H
#define SR_EC_COMMON_H

#include "sr_types.h"
#include "sr_sal_common.h"

typedef enum {
        SR_EC_MODE_ON,
        SR_EC_MODE_OFF,
} sr_ec_mode_t;

struct sr_ec_msg{
	sr_ec_mode_t ec_mode;
};

enum sr_event_type {
        SR_EVENT_FILE_CREATED,
        SR_EVENT_PROCESS_DIED,
        SR_EVENT_MAX_EVENT
};

enum sr_sync_type {
        SR_SYNC_GATHER_INFO,
        SR_SYNC_ENGINE,
};

#ifdef CONFIG_STAT_ANALYSIS
enum sr_event_stats_type {
        SR_EVENT_STATS_CONNECTION,
        SR_EVENT_STATS_CONNECTION_TRANSMIT,
        SR_EVENT_STATS_FILE_OPEN,
        SR_EVENT_STATS_NEW_CONNECTION,
        SR_EVENT_STATS_CANBUS,
        SR_EVENT_STATS_MAX_EVENT
};
#endif

#pragma pack(push, 1)
struct sr_ec_new_connection_t{
        SR_U32 pid;
        SR_U32 uid;
        union {
                SR_U32 v4addr;
                // FUTURE struct in6_addr v6addr;
        } source_addr;
        union {
                SR_U32 v4addr;
                // FUTURE struct in6_addr v6addr;
        } remote_addr;
        SR_U16 dport;
        SR_U16 sport;
        SR_U8 ip_proto;
        // TODO: do we need the classification result ?
};
#pragma pack(pop)

#pragma pack(push, 1)
struct sr_ec_file_t{
	unsigned char name[SR_MAX_PATH_SIZE];  
};
#pragma pack(pop)

#ifdef CONFIG_STAT_ANALYSIS
#pragma pack(push, 1)
struct sr_ec_connection_stat_t{
	struct sr_ec_new_connection_t con_id;
	SR_U32 pid;
	SR_U32 rx_msgs;
	SR_U32 rx_bytes;
	SR_U32 tx_msgs;
	SR_U32 tx_bytes;
	SR_U64 curr_time;
	SR_BOOL is_outgoing;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct sr_ec_can_t{
	SR_U32 pid;
    SR_U32 	msg_id;
	SR_U8 	dir; //inbound/outbound msg
};
#pragma pack(pop)

#pragma pack(push, 1)
struct sr_ec_process_died_t{
	SR_U32 pid;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct sr_ec_connection_transmit_t{
	SR_U32 count;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct sr_ec_file_open_t{
	SR_8 file[SR_MAX_PATH_SIZE];
	SR_U32 pid;
	SR_U8  fileop;
	SR_U8  dev_type;
};
#pragma pack(pop)
#endif

#endif /* SR_EC_COMMON_H */
