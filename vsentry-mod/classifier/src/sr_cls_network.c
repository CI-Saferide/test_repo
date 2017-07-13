#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_cls_file.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"

struct radix_head *sr_cls_src_ipv4;

void sr_classifier_ut(void) ;
int sr_cls_walker_addrule(struct radix_node *node, void *rulenum);
int sr_cls_walker_delrule(struct radix_node *node, void *rulenum);

SR_32 sr_classifier_init(void)
{
	if (!rn_inithead((void **)&sr_cls_src_ipv4, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
		sal_kernel_print_alert("Error Initializing radix tree\n");
	} else {
		sal_kernel_print_alert("Successfully Initialized radix tree\n");
	}
	sr_cls_fs_init();

	sr_cls_rules_init();

//#ifdef UNIT_TEST
	sr_classifier_ut();
//#endif

	return 0;
}

void sr_classifier_uninit(void)
{
	if (sr_cls_src_ipv4) {
		rn_detachhead((void **)&sr_cls_src_ipv4);
		sr_cls_src_ipv4 = NULL;
	}
	sr_cls_fs_uninit();
}

int sr_cls_add_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum)
{
	struct radix_node *node = NULL;
	struct radix_node *treenodes = NULL;
	struct sockaddr_in *ip=NULL, *mask=NULL, *mask2=NULL;

	treenodes = SR_ZALLOC(2*sizeof(struct radix_node));
	ip = SR_ZALLOC(sizeof(struct sockaddr_in));
	mask = SR_ZALLOC(sizeof(struct sockaddr_in));
	mask2 = SR_ZALLOC(sizeof(struct sockaddr_in));

	if (!treenodes || !ip || !mask || !mask2) {
		if (ip)
			SR_FREE(ip);
		if (mask)
			SR_FREE(mask);
		if (mask2)
			SR_FREE(mask2);
		if (treenodes)
			SR_FREE(treenodes);
		return -1;
	}
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = addr;
	//ip.sin_len = 32; // ????
	mask->sin_family = AF_INET;
	mask2->sin_family = AF_INET;
	mask->sin_addr.s_addr = netmask;
	mask2->sin_addr.s_addr = netmask;

	node = rn_addroute((void*)ip, (void*)mask, sr_cls_src_ipv4, treenodes);
	if (!node) { // failed to insert - free memory
		SR_FREE(treenodes);
		SR_FREE(ip);
		SR_FREE(mask);
	} else { // new node, inherit from ancestors
		struct radix_node *ptr = node->rn_parent;
		//sal_kernel_print_alert("Checking ancestry for node %lx\n", (unsigned long)node);
		while (!(ptr->rn_flags & RNF_ROOT)) {
			//sal_kernel_print_alert("ptr %lx, flags %d, left %lx, right %lx\n", (unsigned long)ptr, ptr->rn_flags, ptr->rn_left, ptr->rn_right);
			if (ptr->rn_left && (ptr->rn_left != node) && (ptr->rn_left->rn_bit == -1)) {
				//sal_kernel_print_alert("Node %lx inherited from %lx\n", (unsigned long)node, (unsigned long) ptr->rn_left);
				sal_or_self_op_arrays(&node->sr_private.rules, &ptr->rn_left->sr_private.rules);
			}
			ptr = ptr->rn_parent;
		}
	}

	rn_walktree_from(sr_cls_src_ipv4, ip, mask2, sr_cls_walker_addrule, (void*)(long)rulenum);
	SR_FREE(mask2);
	
	//sal_kernel_print_alert("sr_cls_add_ipv4: added node has address %lx\n", (unsigned long)node);
	return 0;
}

int sr_cls_del_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum)
{
	struct radix_node *node = NULL;
	struct sockaddr_in *ip=NULL, *mask=NULL;

	ip = SR_ZALLOC(sizeof(struct sockaddr_in));
	mask = SR_ZALLOC(sizeof(struct sockaddr_in));

	if (!ip || !mask) {
		if (ip)
			SR_FREE(ip);
		if (mask)
			SR_FREE(mask);
		return -1;
	}

	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = addr;
	//ip.sin_len = 32; // ????
	mask->sin_family = AF_INET;
	mask->sin_addr.s_addr = netmask;

	node = rn_lookup((void*)ip, (void*)mask, sr_cls_src_ipv4);
	if (!node) { // failed to insert - free memory
		sal_kernel_print_alert("sr_cls_del_ipv4: Did not find node!\n");
		SR_FREE(ip);
		SR_FREE(mask);
		return SR_ERROR;
	}

	rn_walktree_from(sr_cls_src_ipv4, ip, mask, sr_cls_walker_delrule, (void*)(long)rulenum); // Clears the rule from tree
	if (!node->sr_private.rules.summary) { // removed last rule
		//sal_kernel_print_alert("Cleared last rule from entry, removing entry\n");
		node = rn_delete((void*)ip, (void*)mask, sr_cls_src_ipv4);
		if (!node) { // failed to insert - free memory
			sal_kernel_print_alert("sr_cls_del_ipv4: Did not find node!\n");
			SR_FREE(ip);
			SR_FREE(mask);
			return SR_ERROR;
		}
		SR_FREE(node); // TODO: do I need to free the original ip and netmasks ?
	}
	//sal_kernel_print_alert("sr_cls_del_ipv4: node to be deleted has address %lx\n", (unsigned long)node);
	SR_FREE(ip);
	SR_FREE(mask);
	return 0;
}

int sr_cls_find_ipv4(SR_U32 addr)
{
	struct radix_node *node = NULL;
	struct sockaddr_in *ip;
	bit_array matched_rules;

	memset(&matched_rules, 0, sizeof(matched_rules));
	ip = SR_ZALLOC(sizeof(struct sockaddr_in));
	if (!ip) {
			return -1;
	}
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = addr;

	node = rn_match((void*)ip, sr_cls_src_ipv4);
#ifdef DEBUG
	if (node) {
		SR_16 rule;
		memcpy(&matched_rules, &node->sr_private.rules, sizeof(matched_rules)); 
		sal_kernel_print_alert("Found match for IP %lx:\n", (unsigned long)addr);
		while ((rule = sal_ffs_and_clear_array (&matched_rules)) != -1) {
			sal_kernel_print_alert("Rule #%d\n", rule);
		}
	}
#endif
	
	SR_FREE(ip);

	return (node?0:-1);
}
bit_array *sr_cls_match_srcip(SR_U32 addr)
{
	struct radix_node *node = NULL;
	struct sockaddr_in ip;

	printk("sr_cls_match_srcip: table is %p\n", sr_cls_src_ipv4);
	//ip = SR_ZALLOC(sizeof(struct sockaddr_in));
	//if (!ip) {
//			return NULL;
//	}
	ip.sin_family = AF_INET;
	ip.sin_addr.s_addr = addr;

	node = rn_match((void*)&ip, sr_cls_src_ipv4);

//	SR_FREE(ip);

	if (node) {
		return(&node->sr_private.rules); 
	} else {
		return NULL;
	}
}

int sr_cls_walker_addrule(struct radix_node *node, void *rulenum)
{
	//sal_kernel_print_alert("Walker adds rule %d to node %lx\n", (int)rulenum, (unsigned long)node);
	sal_set_bit_array((SR_U32)(long)rulenum, &node->sr_private.rules);
	return 0;
}

int sr_cls_walker_delrule(struct radix_node *node, void *rulenum)
{
	//sal_kernel_print_alert("Walker deletes rule %d to node %lx\n", (int)rulenum, (unsigned long)node);
	sal_clear_bit_array((SR_U32)(long)rulenum, &node->sr_private.rules);
	return 0;
}

void sr_classifier_ut(void)
{
	//sr_cls_add_ipv4(htonl(0x23232323), htonl(0xffffffff),10);
	//sr_cls_find_ipv4(htonl(0x23232323));
	sr_cls_add_ipv4(htonl(0x12345600), htonl(0xffffff00),3000);
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_add_ipv4(htonl(0x12345670), htonl(0xfffffff0),999);
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_add_ipv4(htonl(0x12345600), htonl(0xffffff00),30);
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_add_ipv4(htonl(0x12340000), htonl(0xffff0000),20);
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xffffffff),40);
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_del_ipv4(htonl(0x12340000), htonl(0xffff0000), 20); // 20
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_del_ipv4(htonl(0x12345600), htonl(0xffffff00), 30); // 30&3000
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_del_ipv4(htonl(0x12345600), htonl(0xffffff00), 3000); // 30&3000
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_del_ipv4(htonl(0x12345670), htonl(0xfffffff0),999);
	sr_cls_find_ipv4(htonl(0x12345678));
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xffffffff),40);
	sr_cls_find_ipv4(htonl(0x12345678));
	printk("Ran all classifier UTs\n");
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

SR_8 sr_cls_network_msg_dispatch(struct sr_cls_network_msg *msg)
{
	switch (msg->msg_type) {
		case SR_CLS_IPV4_DEL_RULE:
			return sr_cls_del_ipv4(msg->addr, msg->netmask, msg->rulenum);
			sal_debug_network("[del_ipv4] addr=0x%x, netmask=0x%x, rulenum=%d\n",
							msg->addr, msg->netmask, msg->rulenum);	
			break;
		case SR_CLS_IPV4_ADD_RULE:
			return sr_cls_add_ipv4(msg->addr, msg->netmask, msg->rulenum);
			break;
		case SR_CLS_IPV6_DEL_RULE:
			/* not implemented yet */
			break;
		case SR_CLS_IPV6_ADD_RULE:
			/* not implemented yet */
			break;
		default:
			break;
	}
	return SR_SUCCESS;
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
