#ifndef SR_EC_COMMON_H
#define SR_EC_COMMON_H

#include "sr_types.h"
#include "sr_sal_common.h"

enum sr_event_type {
        SR_EVENT_NEW_CONNECTION,
        SR_EVENT_FILE_CREATED,
        SR_EVENT_MAX_EVENT
};

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




#endif /* SR_EC_COMMON_H */
