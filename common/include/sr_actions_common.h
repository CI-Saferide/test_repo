#ifndef SR_ACTIONS_COMMON_H
#define SR_ACTIONS_COMMON_H

#include "sr_types.h"

#define SR_FILEOPS_READ  (SR_U8)(1<<0)
#define SR_FILEOPS_WRITE (SR_U8)(1<<1)
#define SR_FILEOPS_EXEC  (SR_U8)(1<<2)

enum sr_rule_type{
        SR_NET_RULES = 0,
        SR_FILE_RULES,
        SR_CAN_RULES,
        SR_RULES_TYPE_MAX,
};

typedef enum {
        SR_RATE_TYPE_EVENT,
        SR_RATE_TYPE_BYTES,
} sr_rate_type_t;

typedef enum {
	SR_CLS_RULES_DEL = 0,
	SR_CLS_RULES_ADD,
} sr_rule_verb_t;

// rules actions are a bitmap - some rules are not mutually exclusive - e.g. drop + SMS...
// enum defines actions as bits. 
enum cls_actions{
	SR_CLS_ACTION_NOOP = (1<<0), // Fallthrough
	SR_CLS_ACTION_ALLOW = (1<<1),
	SR_CLS_ACTION_DROP=(1<<2),
	SR_CLS_ACTION_RATE=(1<<3),
	SR_CLS_ACTION_WL=(1<<4),
	SR_CLS_ACTION_BL=(1<<5), // Redundant with DROP ?
	SR_CLS_ACTION_LOG=(1<<6),
	SR_CLS_ACTION_SMS=(1<<7),
	SR_CLS_ACTION_EMAIL=(1<<8),
	SR_CLS_ACTION_TERMINATE=(1<<9), // e.g. kill the process that initiated this violation
	SR_CLS_ACTION_SKIP_RULE=(1<<10),
	SR_CLS_ACTION_MAX		// MUST not be more than 8K - this is stored in a 13 bits variable
};

struct sr_cls_rules_msg {
	sr_rule_verb_t msg_type;
	SR_32 rule_type; 
	SR_U16 rulenum; 
	SR_U16 actions;
	SR_U8 file_ops;
	sr_rate_type_t rate_type;
	SR_U32 rl_max_rate;
	SR_U16 rl_exceed_action;
	SR_U16 log_target;
	SR_U16 email_id;
	SR_U16 phone_id; 
	SR_U16 skip_rulenum;
};

#endif /* SR_ACTIONS_COMMON_H */
