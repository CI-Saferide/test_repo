
#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"


void sr_classifier_ut(void) ;

SR_32 sr_classifier_init(void)
{
	sr_cls_network_init();

	sr_cls_fs_init();

	sr_cls_rules_init();

//#ifdef UNIT_TEST
	sr_classifier_ut();
//#endif

	return 0;
}

void sr_classifier_uninit(void)
{
	sr_cls_network_uninit();

	sr_cls_fs_uninit();
}

//////////////////////////////// Rules DB section /////////////////////////
struct cls_rule_action_t sr_rules_db[SR_MAX_RULES];

void sr_cls_rules_init(void)
{
	int i;

	if (unlikely(SR_CLS_ACTION_MAX>=(65536))) { // too many actions to fit a 16 bit
		sal_kernel_print_alert("Too many actions defined !\n");
		BUG();
	}
	memset(sr_rules_db, 0, sizeof(sr_rules_db));
	for (i=0; i<SR_MAX_RULES; i++) {
		sr_cls_rl_init(&sr_rules_db[i].rate);
		sr_rules_db[i].actions = SR_CLS_ACTION_ALLOW;
	}
}
void sr_cls_rl_init(struct sr_rl_t *rl)
{
	if (likely(rl)) {
		SR_ATOMIC_SET(&rl->count, 0);
	}
}
void sr_cls_rule_del(SR_U16 rulenum)
{
	sr_cls_rl_init(&sr_rules_db[rulenum].rate);
	sr_rules_db[rulenum].actions = SR_CLS_ACTION_ALLOW;
}
void sr_cls_rule_add(SR_U16 rulenum, SR_U16 actions, SR_U32 rl_max_rate, SR_U16 rl_exceed_action, SR_U16 log_target, SR_U16 email_id, SR_U16 phone_id, SR_U16 skip_rulenum)
{
	if (unlikely(rulenum>=SR_MAX_RULES)){
		sal_kernel_print_alert("sr_cls_rule_add: Invalid rule ID %u\n", rulenum);
		return;
	}
	sr_rules_db[rulenum].actions = actions;
	if (actions & SR_CLS_ACTION_RATE) {
		sr_cls_rl_init(&sr_rules_db[rulenum].rate);
		sr_rules_db[rulenum].rate.max_rate = rl_max_rate;
		sr_rules_db[rulenum].rate.exceed_action = rl_exceed_action;
	}
	if (actions & SR_CLS_ACTION_LOG) {
		sr_rules_db[rulenum].log_target = log_target;
	}
	if (actions & SR_CLS_ACTION_SMS) {
		sr_rules_db[rulenum].phone_id = phone_id;
	}
	if (actions & SR_CLS_ACTION_EMAIL) {
		sr_rules_db[rulenum].email_id = email_id;
	}
	if (actions & SR_CLS_ACTION_SKIP_RULE) {
		sr_rules_db[rulenum].skip_rulenum = skip_rulenum;
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

enum cls_actions sr_cls_rule_match(SR_U16 rulenum)
{
	SR_U16 action;

	if (sr_rules_db[rulenum].actions & SR_CLS_ACTION_RATE) { 
		action = sr_cls_rl_check(&sr_rules_db[rulenum].rate, jiffies);
	} else {
		action = sr_rules_db[rulenum].actions;
	}
	// non-finite actions should be handled here rather than by the caller, so that 
	// there's no need to expose the whole rule structure including emails IDs etc
	// to callers.
	if (sr_rules_db[rulenum].actions & SR_CLS_ACTION_LOG) {
		// TODO
	}
	if (sr_rules_db[rulenum].actions & SR_CLS_ACTION_EMAIL) {
		// TODO
	}
	if (sr_rules_db[rulenum].actions & SR_CLS_ACTION_SMS) {
		// TODO
	}
	return action;
}

///////////////////////////////////////////////////////////////////////////
/////// Actual classifiers entry points
///////////////////////////////////////////////////////////////////////////
// Network events classifier
SR_32 sr_classifier_network(disp_info_t* info)
{
	bit_array *ba_src_ip, *ba_dst_port;
	bit_array ba_res;
	SR_16 rule;
	SR_U16 action;

	sal_kernel_print_alert("sr_classifier_network: Entry for %lx->[%d]\n", (unsigned long)info->tuple_info.saddr.v4addr.s_addr, info->tuple_info.dport);
	// Match 5-tuple
	// Src IP
	ba_src_ip = sr_cls_match_srcip(htonl(info->tuple_info.saddr.v4addr.s_addr));
	//ba_src_ip = sr_cls_match_srcip(htonl(0x0a0a0b00));
	sal_kernel_print_alert("sr_classifier_network: Found src rules\n");
	//return SR_CLS_ACTION_ALLOW;
	// Dst IP - TODO
	// IP Proto - TODO
	// Src Port - TODO
	// Dst Port
	ba_dst_port = sr_cls_match_dport(info->tuple_info.dport);
	sal_kernel_print_alert("sr_classifier_network: Found port rules\n");

	if ((!ba_src_ip) || (!ba_dst_port)) {
		sal_kernel_print_alert("sr_classifier_network: No matching rule! IP: %s, port: %s\n", ba_src_ip?"Match":"None", ba_dst_port?"Match":"None");
		return SR_CLS_ACTION_ALLOW;
	}
	sal_kernel_print_alert("sr_classifier_network: Got some matches\n");
	sal_and_op_arrays(ba_src_ip, ba_dst_port, &ba_res); // Perform arbitration

	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		action = sr_cls_rule_match(rule);
                sal_printf("sr_classifier_network: Matched Rule #%d, action is %d\n", rule, action);
		if (action & SR_CLS_ACTION_DROP) {
			sal_printf("sr_classifier_network: Rule drop\n");
			return SR_CLS_ACTION_DROP;
		}
        }

	
	return SR_CLS_ACTION_ALLOW;
}
SR_32 sr_classifier_file(disp_info_t* info)
{
	bit_array *ba_inode, ba_res;
	SR_16 rule;
	SR_U16 action;

	sal_kernel_print_alert("sr_classifier_file: Entry\n");
	// Match 5-tuple
	// Src IP
	ba_inode = sr_cls_file_find(info->fileinfo.parent_inode);

	if (!ba_inode) {
		sal_kernel_print_alert("sr_classifier_file: No matching rule!\n");
		return SR_CLS_ACTION_ALLOW;
	}
	sal_kernel_print_alert("sr_classifier_file: Got some matches\n");
	memcpy(&ba_res, ba_inode, sizeof(bit_array)); // Perform arbitration

	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		action = sr_cls_rule_match(rule);
                sal_printf("sr_classifier_network: Matched Rule #%d, action is %d\n", rule, action);
		if (action & SR_CLS_ACTION_DROP) {
			sal_printf("sr_classifier_network: Rule drop\n");
			return SR_CLS_ACTION_DROP;
		}
        }

	
	return SR_CLS_ACTION_ALLOW;
}
