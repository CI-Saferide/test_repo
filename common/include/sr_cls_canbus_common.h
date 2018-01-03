#ifndef SR_CLS_CANBUS_COMMON_H
#define SR_CLS_CANBUS_COMMON_H
#include "sr_types.h"

#define MSGID_ANY -1

#define SR_CAN_IN 0
#define SR_CAN_OUT 1
#define SR_CAN_BOTH 2

enum {
	SR_CLS_CANID_DEL_RULE = 0,
	SR_CLS_CANID_ADD_RULE,
};

struct sr_cls_canbus_msg {
	SR_U8 	msg_type;
	SR_U32	rulenum;
	SR_32  canid;
	SR_U8   dir; // SR_CAN_IN/SR_CAN_OUT
	SR_U32  exec_inode;
	SR_32   uid;
};

#endif /* SR_CLS_CANBUS_COMMON_H */
