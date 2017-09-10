#ifndef SR_CLASSIFIER_H
#define SR_CLASSIFIER_H

#include "sr_types.h"
#include "dispatcher.h"
#include "sr_cls_port.h"
#include "sr_cls_uid.h"
#include "sr_cls_exec_file.h"
#include "sr_cls_process.h"
#include "sr_cls_file.h"
#include "sr_cls_network.h"
#include "sr_cls_canid.h"
#include "sal_bitops.h"
#include "sr_actions_common.h"

SR_32 sr_classifier_init(void);
SR_32 sr_cls_inode_add_rule(SR_U32 inode, SR_U32 rulenum);
SR_32 sr_cls_inode_del_rule(SR_U32 inode, SR_U32 rulenum);
SR_32 sr_cls_inode_inherit(SR_U32 from, SR_U32 to);
void sr_cls_inode_remove(SR_U32 inode);
void sr_classifier_uninit(void);
void sr_cls_rules_init(void);

SR_32 sr_classifier_network(disp_info_t* info);
SR_32 sr_classifier_file(disp_info_t* info);
SR_32 sr_classifier_canbus(disp_info_t* info);

struct sr_rl_t{ // rate limit tracking
	SR_U32 max_rate; 	// max allowable rate per timestamp period
	SR_ATOMIC count;   	// lapsed counter since last timestamp
	SR_U32 timestamp; 	// timestamp of last counter clear (jiffies?)
	SR_U8  exceed_action;   // What to do upon exceeding the limit
};

struct cls_rule_action_t{
	SR_U16 actions:13,
	       file_ops:3; // read/write/excute
	struct sr_rl_t rate;
	struct sr_rl_t log_rate;
	// TODO: consider using a union. some fields are not mutually exclusive though... (email/sms)
	SR_U16 skip_rulenum; // for skip action
	SR_U16 log_target; // syslog facility etc for log action
	SR_U16 email_id;   // store an index to a list of email addresses
	SR_U16 phone_id;   // store an index to a list of phone numbers for sms actions
};

// Rate Limits related functions
void sr_cls_rl_init(struct sr_rl_t *rl);
enum cls_actions sr_cls_rl_check(struct sr_rl_t *rl, SR_U32 timestamp);
void sr_cls_rule_add(SR_32 rule_type, SR_U16 rulenum, SR_U16 actions, SR_8 file_ops, SR_U32 rl_max_rate, SR_U16 rl_exceed_action, SR_U16 log_target, SR_U16 email_id, SR_U16 phone_id, SR_U16 skip_rulenum);
void sr_cls_rule_del(SR_32 rule_type, SR_U16 rulenum);
enum cls_actions sr_cls_network_rule_match(SR_U16 rulenum);
enum cls_actions sr_cls_file_rule_match(SR_8 fileop, SR_U16 rulenum);
enum cls_actions sr_cls_can_rule_match(SR_U16 rulenum);
SR_8 sr_cls_rules_msg_dispatch(struct sr_cls_rules_msg *msg);
void sr_classifier_empty_tables(SR_BOOL is_lock);

#endif
