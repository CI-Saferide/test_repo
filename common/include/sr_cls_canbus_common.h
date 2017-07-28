#ifndef SR_CLS_CANBUS_COMMON_H
#define SR_CLS_CANBUS_COMMON_H
#include "sr_types.h"

enum {
	SR_CLS_CANID_DEL_RULE = 0,
	SR_CLS_CANID_ADD_RULE,
};

struct sr_cls_canbus_msg {
	SR_U8 	msg_type;
	SR_U32	rulenum;
	SR_U32  canid;
};

#endif /* SR_CLS_CANBUS_COMMON_H */
