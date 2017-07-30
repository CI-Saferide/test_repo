#ifndef SR_CLS_NETWORK_COMMON_H
#define SR_CLS_NETWORK_COMMON_H
#include "sr_types.h"

#define SR_DIR_SRC 0
#define SR_DIR_DST 1

enum {
	SR_CLS_IPV4_DEL_RULE = 0,
	SR_CLS_IPV4_ADD_RULE,
	SR_CLS_IPV6_DEL_RULE,
	SR_CLS_IPV6_ADD_RULE,
	SR_CLS_NETWORK_MAX = SR_CLS_IPV6_ADD_RULE,
	SR_CLS_NETOWRK_TOTAL = (SR_CLS_NETWORK_MAX + 1),
};

enum {
	SR_PROTO_TCP = 6,
	SR_PROTO_UDP = 17,
};

struct sr_cls_network_msg {
	SR_U8 	msg_type;
	SR_U8   dir; // SR_DIR_SRC/DST
	SR_U16	rulenum;
	SR_U32	addr;
	SR_U32  netmask;
};

#endif /* SR_CLS_NETWORK_COMMON_H */
