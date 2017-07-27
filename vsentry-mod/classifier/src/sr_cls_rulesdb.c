#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_cls_rules_common.h"

struct cls_rule_action_t sr_rules_db[SR_RULES_TYPE_MAX][SR_MAX_RULES];

void sr_cls_rules_init(void)
{
	int i,j;

	if (unlikely(SR_CLS_ACTION_MAX>=(8192))) { // too many actions to fit a 13 bit
		sal_kernel_print_alert("Too many actions defined !\n");
		BUG();
	}
	memset(sr_rules_db, 0, sizeof(sr_rules_db));
	for (j=0; j<SR_RULES_TYPE_MAX; j++) {
		for (i=0; i<SR_MAX_RULES; i++) {
			sr_cls_rl_init(&sr_rules_db[j][i].rate);
			sr_rules_db[j][i].actions = SR_CLS_ACTION_ALLOW;
		}
	}
}
void sr_cls_rl_init(struct sr_rl_t *rl)
{
	if (likely(rl)) {
		SR_ATOMIC_SET(&rl->count, 0);
	}
}
void sr_cls_rule_del(SR_32 rule_type, SR_U16 rulenum)
{
	sr_cls_rl_init(&sr_rules_db[rule_type][rulenum].rate);
	sr_rules_db[rule_type][rulenum].actions = SR_CLS_ACTION_ALLOW;
}
void sr_cls_rule_add(SR_32 rule_type, SR_U16 rulenum, SR_U16 actions, SR_8 file_ops, SR_U32 rl_max_rate, SR_U16 rl_exceed_action, SR_U16 log_target, SR_U16 email_id, SR_U16 phone_id, SR_U16 skip_rulenum)
{
	if (unlikely(rulenum>=SR_MAX_RULES)){
		sal_kernel_print_alert("sr_cls_rule_add: Invalid rule ID %u\n", rulenum);
		return;
	}
	sr_rules_db[rule_type][rulenum].actions = actions;
	if (rule_type == SR_FILE_RULES) {
		if (file_ops > 7) {
			sal_kernel_print_alert("sr_cls_rule_add: Invalid fileops for rule ID %u\n", rulenum);
			return;
		}
		sr_rules_db[rule_type][rulenum].file_ops = file_ops;
	}
	if (actions & SR_CLS_ACTION_RATE) {
		sr_cls_rl_init(&sr_rules_db[rule_type][rulenum].rate);
		sr_rules_db[rule_type][rulenum].rate.max_rate = rl_max_rate;
		sr_rules_db[rule_type][rulenum].rate.exceed_action = rl_exceed_action;
	}
	if (actions & SR_CLS_ACTION_LOG) {
		sr_rules_db[rule_type][rulenum].log_target = log_target;
	}
	if (actions & SR_CLS_ACTION_SMS) {
		sr_rules_db[rule_type][rulenum].phone_id = phone_id;
	}
	if (actions & SR_CLS_ACTION_EMAIL) {
		sr_rules_db[rule_type][rulenum].email_id = email_id;
	}
	if (actions & SR_CLS_ACTION_SKIP_RULE) {
		sr_rules_db[rule_type][rulenum].skip_rulenum = skip_rulenum;
	}
}
enum cls_actions sr_cls_rl_check(struct sr_rl_t *rl, SR_U32 timestamp)
{
	if (!rl) {
		return SR_CLS_ACTION_ALLOW;
	}
	if (timestamp > rl->timestamp) { // new measurement period
		SR_ATOMIC_SET(&rl->count, 1);
		rl->timestamp = timestamp;
		return SR_CLS_ACTION_ALLOW;
	}
	if (SR_ATOMIC_INC_RETURN(&rl->count) > rl->max_rate) {
		sal_kernel_print_alert("sr_cls_rl_check: Rate exceeds configured rate\n");
		return rl->exceed_action;
	}
	return SR_CLS_ACTION_ALLOW;
}

enum cls_actions sr_cls_network_rule_match(SR_U16 rulenum)
{
	SR_U16 action;

	if (sr_rules_db[SR_NET_RULES][rulenum].actions & SR_CLS_ACTION_RATE) { 
		action = sr_cls_rl_check(&sr_rules_db[SR_NET_RULES][rulenum].rate, jiffies);
	} else {
		action = sr_rules_db[SR_NET_RULES][rulenum].actions;
	}
	// non-finite actions should be handled here rather than by the caller, so that 
	// there's no need to expose the whole rule structure including emails IDs etc
	// to callers.
	if (sr_rules_db[SR_NET_RULES][rulenum].actions & SR_CLS_ACTION_LOG) {
		// TODO
	}
	if (sr_rules_db[SR_NET_RULES][rulenum].actions & SR_CLS_ACTION_EMAIL) {
		// TODO
	}
	if (sr_rules_db[SR_NET_RULES][rulenum].actions & SR_CLS_ACTION_SMS) {
		// TODO
	}
	return action;
}

enum cls_actions sr_cls_file_rule_match(SR_8 fileop, SR_U16 rulenum)
{
	SR_U16 action;

	switch (fileop) {
		case SR_FILEOPS_READ:
		case SR_FILEOPS_WRITE:
		case SR_FILEOPS_EXEC:
			if (!(sr_rules_db[SR_FILE_RULES][rulenum].file_ops & fileop)) { // not really a match
				return SR_CLS_ACTION_NOOP;
			}
			break;
		default:
			sal_kernel_print_info("sr_cls_file_rule_match: Invalid file op\n");
			return SR_CLS_ACTION_NOOP;
	}
	if (sr_rules_db[SR_FILE_RULES][rulenum].actions & SR_CLS_ACTION_RATE) { 
		action = sr_cls_rl_check(&sr_rules_db[SR_FILE_RULES][rulenum].rate, jiffies);
	} else {
		action = sr_rules_db[SR_FILE_RULES][rulenum].actions;
	}
	// non-finite actions should be handled here rather than by the caller, so that 
	// there's no need to expose the whole rule structure including emails IDs etc
	// to callers.
	if (sr_rules_db[SR_FILE_RULES][rulenum].actions & SR_CLS_ACTION_LOG) {
		// TODO
	}
	if (sr_rules_db[SR_FILE_RULES][rulenum].actions & SR_CLS_ACTION_EMAIL) {
		// TODO
	}
	if (sr_rules_db[SR_FILE_RULES][rulenum].actions & SR_CLS_ACTION_SMS) {
		// TODO
	}
	return action;
}

enum cls_actions sr_cls_can_rule_match(SR_U16 rulenum)
{
	SR_U16 action;

	if (sr_rules_db[SR_CAN_RULES][rulenum].actions & SR_CLS_ACTION_RATE) { 
		action = sr_cls_rl_check(&sr_rules_db[SR_CAN_RULES][rulenum].rate, jiffies);
	} else {
		action = sr_rules_db[SR_CAN_RULES][rulenum].actions;
	}
	// non-finite actions should be handled here rather than by the caller, so that 
	// there's no need to expose the whole rule structure including emails IDs etc
	// to callers.
	if (sr_rules_db[SR_CAN_RULES][rulenum].actions & SR_CLS_ACTION_LOG) {
		// TODO
	}
	if (sr_rules_db[SR_CAN_RULES][rulenum].actions & SR_CLS_ACTION_EMAIL) {
		// TODO
	}
	if (sr_rules_db[SR_CAN_RULES][rulenum].actions & SR_CLS_ACTION_SMS) {
		// TODO
	}
	return action;
}
	
SR_8 sr_cls_rules_msg_dispatch(struct sr_cls_rules_msg *msg)
{

	switch (msg->msg_type) {
		case SR_CLS_RULES_DEL:
			sal_kernel_print_alert("SR_CLS_RULES_DEL\n");
			sr_cls_rule_del(msg->rule_type, msg->rulenum);
			break;
		case SR_CLS_RULES_ADD:
			sal_kernel_print_alert("SR_CLS_RULES_ADD\n");
			sr_cls_rule_add(msg->rule_type,
			msg->rulenum,
			msg->actions,
			msg->file_ops,
			msg->rl_max_rate,
			msg->rl_exceed_action,
			msg->log_target,
			msg->email_id,
			msg->phone_id,
			msg->skip_rulenum);
			break;
		default:
			break;
	}
	return SR_SUCCESS;
}
