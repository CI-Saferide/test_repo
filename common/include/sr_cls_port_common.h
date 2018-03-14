#ifndef SR_CLS_PORT_COMMON_H
#define SR_CLS_PORT_COMMON_H
#include "sr_types.h"

#define SR_PROTO_SELECTOR(proto) (proto==IPPROTO_UDP)?1:0

typedef enum {
	SR_CLS_PORT_DEL_RULE = 0,
	SR_CLS_PORT_ADD_RULE,
} sr_port_verb_t;

struct sr_cls_port_msg {
	sr_port_verb_t msg_type;
	SR_U32 port;
	SR_U16	rulenum;
	SR_U8   dir; // SR_DIR_SRC/DST
	SR_U8 proto;
	SR_U32 exec_inode;
	SR_32 uid;
};

#endif /* SR_CLS_PORT_COMMON_H */
