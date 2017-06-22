#ifndef SR_CLASSIFIER_H
#define SR_CLASSIFIER_H
#include <asm/atomic.h>

#define SR_MAX_RULES 4096

int sr_classifier_init(void);
int sr_cls_inode_add_rule(SR_U32 inode, SR_U32 rulenum);
int sr_cls_inode_del_rule(SR_U32 inode, SR_U32 rulenum);
int sr_cls_inode_inherit(SR_U32 from, SR_U32 to);
void sr_cls_inode_remove(SR_U32 inode);
void sr_classifier_uninit(void);
void sr_cls_rules_init(void);

// rules actions are a bitmap - some rules are not mutually exclusive - e.g. drop + SMS...
// enum defines actions as bits. 
enum cls_actions{
	SR_CLS_ACTION_ALLOW = 1,
	SR_CLS_ACTION_DROP=2,
	SR_CLS_ACTION_RATE=4,
	SR_CLS_ACTION_WL=8,
	SR_CLS_ACTION_BL=16, // Redundant with DROP ?
	SR_CLS_ACTION_LOG=32,
	SR_CLS_ACTION_SMS=64,
	SR_CLS_ACTION_EMAIL=128,
	SR_CLS_ACTION_TERMINATE=256, // e.g. kill the process that initiated this violation
	SR_CLS_ACTION_SKIP_RULE=512,
	SR_CLS_ACTION_MAX		// MUST not be more than 64K - this is stored in a 16 bits variable
};

struct sr_rl_t{ // rate limit tracking
	SR_U32 max_rate; 	// max allowable rate per timestamp period
	atomic_t count;   	// lapsed counter since last timestamp
	SR_U32 timestamp; 	// timestamp of last counter clear (jiffies?)
	SR_U8  exceed_action;   // What to do upon exceeding the limit
};

struct cls_rule_action_t{
	SR_U16 actions;
	struct sr_rl_t rate;
	// TODO: consider using a union. some fields are not mutually exclusive though... (email/sms)
	SR_U16 skip_rulenum; // for skip action
	SR_U16 log_target; // syslog facility etc for log action
	SR_U16 email_id;   // store an index to a list of email addresses
	SR_U16 phone_id;   // store an index to a list of phone numbers for sms actions
};

// Rate Limits related functions
void sr_cls_rl_init(struct sr_rl_t *rl);
enum cls_actions sr_cls_rl_check(struct sr_rl_t *rl, SR_U32 timestamp);
void sr_cls_rule_add(SR_U16 rulenum, SR_U16 actions, SR_U32 rl_max_rate, SR_U16 rl_exceed_action, SR_U16 log_target, SR_U16 email_id, SR_U16 phone_id, SR_U16 skip_rulenum);
void sr_cls_rule_del(SR_U16 rulenum);

#endif

