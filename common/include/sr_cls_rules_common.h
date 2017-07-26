#ifndef SR_CLS_RULES_COMMON_H
#define SR_CLS_RULES_COMMON_H
#include "sr_types.h"

enum {
	SR_CLS_RULES_DEL = 0,
	SR_CLS_RULES_ADD,
};

enum sr_cls_rule_type{
        _SR_NET_RULES = 0,
        _SR_FILE_RULES,
        _SR_CAN_RULES,
        _SR_RULES_TYPE_MAX,
};


// rules actions are a bitmap - some rules are not mutually exclusive - e.g. drop + SMS...
// enum defines actions as bits. 
enum _sr_cls_actions{
	_SR_ACTION_NOOP = (1<<0), // Fallthrough
	_SR_ACTION_ALLOW = (1<<1),
	_SR_ACTION_DROP=(1<<2),
	_SR_ACTION_RATE=(1<<3),
	_SR_ACTION_WL=(1<<4),
	_SR_ACTION_BL=(1<<5), // Redundant with DROP ?
	_SR_ACTION_LOG=(1<<6),
	_SR_ACTION_SMS=(1<<7),
	_SR_ACTION_EMAIL=(1<<8),
	_SR_ACTION_TERMINATE=(1<<9), // e.g. kill the process that initiated this violation
	_SR_ACTION_SKIP_RULE=(1<<10),
	_SR_ACTION_MAX		// MUST not be more than 8K - this is stored in a 13 bits variable
};

#define _SR_FILEOPS_READ  (1<<0)
#define _SR_FILEOPS_WRITE (1<<1)
#define _SR_FILEOPS_EXEC  (1<<2)



struct sr_cls_rules_msg {
	SR_U8 	msg_type;
	SR_32 rule_type; 
	SR_U16 rulenum; 
	SR_U16 actions;
	SR_8 file_ops;
	SR_U32 rl_max_rate;
	SR_U16 rl_exceed_action;
	SR_U16 log_target;
	SR_U16 email_id;
	SR_U16 phone_id; 
	SR_U16 skip_rulenum;
};

#endif /* SR_CLS_RULES_COMMON_H */
