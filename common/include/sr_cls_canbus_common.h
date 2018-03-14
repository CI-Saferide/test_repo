#ifndef SR_CLS_CANBUS_COMMON_H
#define SR_CLS_CANBUS_COMMON_H
#include "sr_types.h"

#define MSGID_ANY -1

#define SR_CAN_IN (SR_U8)0
#define SR_CAN_OUT (SR_U8)1
#define SR_CAN_BOTH (SR_U8)2

typedef enum {
	SR_CLS_CANID_DEL_RULE = 0,
	SR_CLS_CANID_ADD_RULE,
} sr_canbus_verb_t;

struct sr_cls_canbus_msg {
	sr_canbus_verb_t  msg_type;
	SR_U32	rulenum;
	SR_U32  canid;
	SR_U8   dir; // SR_CAN_IN/SR_CAN_OUT
	SR_U32  exec_inode;
	SR_32   uid;
};

#endif /* SR_CLS_CANBUS_COMMON_H */
