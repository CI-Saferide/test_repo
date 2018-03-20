#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_actions_common.h"
#include "sr_control.h"

static struct rule_database sr_db;

struct rule_database* get_sr_rules_db(void)
{
	return &sr_db;
}

void sr_cls_rules_init(void)
{
	int i,j;

	if (unlikely(SR_CLS_ACTION_MAX>=(8192))) { // too many actions to fit a 13 bit
		sal_kernel_print_err("Too many actions defined !\n");
		BUG();
	}
	memset(sr_db.sr_rules_db, 0, sizeof(sr_db.sr_rules_db));
	for (j=0; j<SR_RULES_TYPE_MAX; j++) {
		for (i=0; i<SR_MAX_RULES; i++) {
			sr_cls_rl_init(&sr_db.sr_rules_db[j][i].rate);
			sr_cls_rl_init(&sr_db.sr_rules_db[j][i].log_rate);
			sr_db.sr_rules_db[j][i].actions = SR_CLS_ACTION_ALLOW;
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
	sr_cls_rl_init(&sr_db.sr_rules_db[rule_type][rulenum].rate);
	sr_db.sr_rules_db[rule_type][rulenum].actions = SR_CLS_ACTION_ALLOW;
}
void sr_cls_rule_add(SR_32 rule_type, SR_U16 rulenum, SR_U16 actions, SR_8 file_ops, sr_rate_type_t rate_type, SR_U32 rl_max_rate, SR_U16 rl_exceed_action,
		SR_U16 log_target, SR_U16 email_id, SR_U16 phone_id, SR_U16 skip_rulenum)
{
	struct config_params_t *config_params;

	config_params = sr_control_config_params();

	if (unlikely(rulenum>=SR_MAX_RULES)){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to add rule, invalid rule id (%u)", rulenum);
		return;
	}
	sr_db.sr_rules_db[rule_type][rulenum].actions = actions;
	if (rule_type == SR_FILE_RULES) {
		if (file_ops > 7) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"failed to add rule, invalid rule id (%u)", rulenum);
			return;
		}
		sr_db.sr_rules_db[rule_type][rulenum].file_ops = file_ops;
	}
	if (actions & SR_CLS_ACTION_RATE) {
		sr_cls_rl_init(&sr_db.sr_rules_db[rule_type][rulenum].rate);
		sr_db.sr_rules_db[rule_type][rulenum].rate.max_rate = rl_max_rate;
		sr_db.sr_rules_db[rule_type][rulenum].rate.exceed_action = rl_exceed_action;
		sr_db.sr_rules_db[rule_type][rulenum].rate.rate_type = rate_type;
	}
	if (actions & SR_CLS_ACTION_LOG) {
		sr_db.sr_rules_db[rule_type][rulenum].log_target = log_target;
	}
	if (actions & SR_CLS_ACTION_SMS) {
		sr_db.sr_rules_db[rule_type][rulenum].phone_id = phone_id;
	}
	if (actions & SR_CLS_ACTION_EMAIL) {
		sr_db.sr_rules_db[rule_type][rulenum].email_id = email_id;
	}
	if (actions & SR_CLS_ACTION_SKIP_RULE) {
		sr_db.sr_rules_db[rule_type][rulenum].skip_rulenum = skip_rulenum;
	}
	sr_cls_rl_init(&sr_db.sr_rules_db[rule_type][rulenum].log_rate);
	sr_db.sr_rules_db[rule_type][rulenum].log_rate.max_rate = config_params->cef_max_rate;
	sr_db.sr_rules_db[rule_type][rulenum].log_rate.rate_type = SR_RATE_TYPE_EVENT;
}

enum cls_actions sr_cls_rl_check(struct sr_rl_t *rl, SR_U32 timestamp, SR_U32 size)
{
	if (!rl) {
		return SR_CLS_ACTION_ALLOW;
	}
	if (timestamp > rl->timestamp) { // new measurement period
		SR_ATOMIC_SET(&rl->count, 1);
		rl->timestamp = timestamp;
		return SR_CLS_ACTION_ALLOW;
	}
	if (rl->rate_type == SR_RATE_TYPE_EVENT && SR_ATOMIC_INC_RETURN(&rl->count) > rl->max_rate) {
		//sal_kernel_print_alert("sr_cls_rl_check: Rate exceeds configured rate\n");
		return rl->exceed_action;
	}
	if (rl->rate_type == SR_RATE_TYPE_BYTES && rl->max_rate && SR_ATOMIC_ADD_RETURN(size, &rl->count) > rl->max_rate) {
		return rl->exceed_action;
	}
	return SR_CLS_ACTION_ALLOW;
}

enum cls_actions sr_cls_network_rule_match(SR_U16 rulenum, SR_U32 size)
{
	SR_U16 action = 0, should_log;

	if (sr_db.sr_rules_db[SR_NET_RULES][rulenum].actions & SR_CLS_ACTION_RATE) { 
		action = sr_cls_rl_check(&sr_db.sr_rules_db[SR_NET_RULES][rulenum].rate, jiffies / HZ, size);
	} else {
		action = sr_db.sr_rules_db[SR_NET_RULES][rulenum].actions;
	}
	// if action is drop - set log implicitly
	if (action&(SR_CLS_ACTION_LOG|SR_CLS_ACTION_DROP)) {
		should_log = (SR_CLS_ACTION_ALLOW == sr_cls_rl_check(&sr_db.sr_rules_db[SR_NET_RULES][rulenum].log_rate, jiffies/HZ, 1));
		if (should_log) { // set or clear the log bit accordingly
			action |= SR_CLS_ACTION_LOG;
		} else {
			action &= (~SR_CLS_ACTION_LOG);
		}
	}
	// Log action must be handled by caller, since all of the event metadata exists only there.
	return action;
}

enum cls_actions sr_cls_file_rule_match(SR_8 fileop, SR_U16 rulenum)
{
	SR_U16 action, should_log;

	if (!(fileop & (SR_FILEOPS_READ | SR_FILEOPS_WRITE | SR_FILEOPS_EXEC))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to match rule, invalid file op");
		return SR_CLS_ACTION_NOOP;
	}
	if (!(sr_db.sr_rules_db[SR_FILE_RULES][rulenum].file_ops & fileop)) { // not really a match
		return SR_CLS_ACTION_NOOP;
	}
	if (sr_db.sr_rules_db[SR_FILE_RULES][rulenum].actions & SR_CLS_ACTION_RATE) { 
		action = sr_cls_rl_check(&sr_db.sr_rules_db[SR_FILE_RULES][rulenum].rate, jiffies, 1);
	} else {
		action = sr_db.sr_rules_db[SR_FILE_RULES][rulenum].actions;
	}
	// if action is drop - set log implicitly
	if (action&(SR_CLS_ACTION_LOG|SR_CLS_ACTION_DROP)) {
		should_log = (SR_CLS_ACTION_ALLOW == sr_cls_rl_check(&sr_db.sr_rules_db[SR_NET_RULES][rulenum].log_rate, jiffies/HZ, 1));
		if (should_log) { // set or clear the log bit accordingly
			action |= SR_CLS_ACTION_LOG;
		} else {
			action &= (~SR_CLS_ACTION_LOG);
		}
	}
	// Log action must be handled by caller, since all of the event metadata exists only there.
	return action;
}

enum cls_actions sr_cls_can_rule_match(SR_U16 rulenum)
{
	SR_U16 action, should_log;

	if (sr_db.sr_rules_db[SR_CAN_RULES][rulenum].actions & SR_CLS_ACTION_RATE) { 
		action = sr_cls_rl_check(&sr_db.sr_rules_db[SR_CAN_RULES][rulenum].rate, jiffies, 1);
	} else {
		action = sr_db.sr_rules_db[SR_CAN_RULES][rulenum].actions;
	}
	// if action is drop - set log implicitly
	if (action&(SR_CLS_ACTION_LOG|SR_CLS_ACTION_DROP)) {
		should_log = (SR_CLS_ACTION_ALLOW == sr_cls_rl_check(&sr_db.sr_rules_db[SR_NET_RULES][rulenum].log_rate, jiffies/HZ, 1));
		if (should_log) { // set or clear the log bit accordingly
			action |= SR_CLS_ACTION_LOG;
		} else {
			action &= (~SR_CLS_ACTION_LOG);
		}
	}
	// Log action must be handled by caller, since all of the event metadata exists only there.
	return action;
}
	
SR_8 sr_cls_rules_msg_dispatch(struct sr_cls_rules_msg *msg)
{

	switch (msg->msg_type) {
		case SR_CLS_RULES_DEL:
			CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
							"del rule on ruledc");
			sr_cls_rule_del(msg->rule_type, msg->rulenum);
			break;
		case SR_CLS_RULES_ADD:
			CEF_log_debug(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
							"add rule on ruledb");
			sr_cls_rule_add(msg->rule_type,
			msg->rulenum,
			msg->actions,
			msg->file_ops,
			msg->rate_type,
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
