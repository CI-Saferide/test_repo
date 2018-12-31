#ifndef SR_CLS_UID_COMMON_H
#define SR_CLS_UID_COMMON_H
#include "sr_types.h"
#include "sr_actions_common.h" 

#define UID_ANY -1
#define UID_NONE -2

typedef enum {
	SR_CLS_UID_DEL_RULE = 0,
	SR_CLS_UID_ADD_RULE,
} sr_uid_verb_t;

struct sr_cls_uid_msg {
	sr_uid_verb_t msg_type;
	SR_U32	rulenum;
	enum sr_rule_type rule_type;
	SR_U32  uid;
};

#endif /* SR_CLS_CANBUS_COMMON_H */
