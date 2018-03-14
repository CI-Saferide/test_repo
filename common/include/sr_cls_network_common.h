#ifndef SR_CLS_NETWORK_COMMON_H
#define SR_CLS_NETWORK_COMMON_H
#include "sr_types.h"

#define PORT_ANY 0

typedef enum {
	SR_CLS_IPV4_DEL_RULE = 0,
	SR_CLS_IPV4_ADD_RULE,
	SR_CLS_IPV6_DEL_RULE,
	SR_CLS_IPV6_ADD_RULE,
	SR_CLS_NETWORK_MAX = SR_CLS_IPV6_ADD_RULE,
	SR_CLS_NETOWRK_TOTAL = (SR_CLS_NETWORK_MAX + 1),
} sr_network_verb_t;

enum {
	SR_PROTO_TCP = 6,
	SR_PROTO_UDP = 17,
};

struct sr_cls_network_msg {
	sr_network_verb_t  msg_type;
	SR_U8   dir; // SR_DIR_SRC/DST
	SR_U16	rulenum;
	SR_U32	addr;
	SR_U32  netmask;
	SR_U32  exec_inode;
	SR_32  uid;
};

typedef struct sr_connection_id {
        union {
                SR_U32 v4addr;
                // FUTURE struct in6_addr v6addr;
        } saddr;
        union {
                SR_U32 v4addr;
                // FUTURE struct in6_addr v6addr;
        } daddr;
        SR_U16 dport;
        SR_U16 sport;
        SR_U8 ip_proto;
} sr_connection_id_t;


#endif /* SR_CLS_NETWORK_COMMON_H */
