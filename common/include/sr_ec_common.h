#ifndef SR_EC_COMMON_H
#define SR_EC_COMMON_H

#include "sr_types.h"
#include "sr_sal_common.h"

enum sr_ec_event_type {
        SR_EC_NEW_CONNECTION,
        SR_EC_MAX_EVENT
};

#pragma pack(push, 1)
struct sr_ec_new_connection_t{
        SR_U32 pid;
        union {
                SR_U32 v4addr;
                // FUTURE struct in6_addr v6addr;
        } remote_addr;
        SR_U8 ip_proto;
        SR_U16 dport;
        // TODO: do we need the classification result ?
};
#pragma pack(pop)


#endif /* SR_EC_COMMON_H */
