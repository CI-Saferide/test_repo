#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_cls_file.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_radix.h"

#define MAX_NUM_OF_LOCAL_IPS 10

struct radix_head *sr_cls_src_ipv4;
bit_array sr_cls_network_src_any_rules;
struct radix_head *sr_cls_dst_ipv4;
bit_array sr_cls_network_dst_any_rules;
bit_array sr_cls_network_src_local_rules;
bit_array sr_cls_network_dst_local_rules;

int sr_cls_walker_addrule(struct radix_node *node, void *rulenum);
int sr_cls_walker_delrule(struct radix_node *node, void *rulenum);

static SR_U32 local_ips[MAX_NUM_OF_LOCAL_IPS];

SR_32 local_ips_array_init(void)
{
	SR_32 count;

	if (sal_get_local_ips(local_ips, &count, MAX_NUM_OF_LOCAL_IPS)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "sal_get_local_ips failed");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

SR_BOOL cr_cls_is_ip_address_local(struct in_addr addr)
{
	SR_U32 i;

	for (i = 0; i < MAX_NUM_OF_LOCAL_IPS && local_ips[i]; i++) {
		if (addr.s_addr == local_ips[i])
			return SR_TRUE;
	}

	return SR_FALSE;
}

void sr_cls_network_init(void)
{
	memset(&sr_cls_network_src_any_rules, 0, sizeof(bit_array));
	memset(&sr_cls_network_dst_any_rules, 0, sizeof(bit_array));

	if (!rn_inithead((void **)&sr_cls_src_ipv4, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
		sal_kernel_print_err("Error Initializing src radix tree\n");
	} else {
		if (!rn_inithead((void **)&sr_cls_dst_ipv4, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
			rn_detachhead((void **)&sr_cls_src_ipv4);
			sr_cls_src_ipv4 = NULL;
			sal_kernel_print_err("Error Initializing dst radix tree\n");
		} else {
			sal_kernel_print_info("Successfully Initialized radix tree\n");
		}
	}

	local_ips_array_init();
}

void sr_cls_network_uninit(void)
{
	if (sr_cls_src_ipv4) {
		rn_detachhead((void **)&sr_cls_src_ipv4);
		sr_cls_src_ipv4 = NULL;
	}
	if (sr_cls_dst_ipv4) {
		rn_detachhead((void **)&sr_cls_dst_ipv4);
		sr_cls_dst_ipv4 = NULL;
	}
}

bit_array *src_cls_network_any_src(void) 
{ 
	return &sr_cls_network_src_any_rules; 
}
bit_array *src_cls_network_any_dst(void) 
{ 
	return &sr_cls_network_dst_any_rules; 
}

bit_array *src_cls_network_local_src(void) 
{ 
	return &sr_cls_network_src_local_rules; 
}
bit_array *src_cls_network_local_dst(void) 
{ 
	return &sr_cls_network_dst_local_rules; 
}

int sr_cls_add_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum, SR_8 dir)
{
	struct radix_node *node = NULL;
	struct radix_node *treenodes = NULL;
	struct sockaddr_in *ip=NULL, *mask=NULL, *mask2=NULL;
	struct radix_head *tree_head = NULL;

	if (likely(netmask && addr)) { // Not an "any" rule
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
		if (dir == SR_DIR_SRC) {
			tree_head = sr_cls_src_ipv4;
		} else {
			tree_head = sr_cls_dst_ipv4;
		}


		node = rn_addroute((void*)ip, (void*)mask, tree_head, treenodes);
		if (!node) { // failed to insert - free memory
			SR_FREE(treenodes);
			SR_FREE(ip);
			SR_FREE(mask);
		} else { // new node, inherit from ancestors
			struct radix_node *ptr = node->rn_parent;
			//sal_kernel_print_alert("Checking ancestry for new node %p\n", node);
			while (!(ptr->rn_flags & RNF_ROOT)) {
				//sal_kernel_print_alert("ptr %lx, flags %d, left %lx, right %lx\n", (unsigned long)ptr, ptr->rn_flags, ptr->rn_left, ptr->rn_right);
				if (ptr->rn_left && (ptr->rn_left != node) && (ptr->rn_left->rn_bit != -33)) {
					sal_or_self_op_arrays(&node->sr_private.rules, &ptr->rn_left->sr_private.rules);
				}
				ptr = ptr->rn_parent;
			}
		}

		rn_walktree_from(tree_head, ip, mask2, sr_cls_walker_addrule, (void*)(long)rulenum);
		SR_FREE(mask2);
	} else if (netmask) {
		sal_set_bit_array((SR_U32)(long)rulenum, (dir==SR_DIR_SRC)?&sr_cls_network_src_local_rules:&sr_cls_network_dst_local_rules);
	} else { // "any" = /0
		sal_set_bit_array((SR_U32)(long)rulenum, (dir==SR_DIR_SRC)?&sr_cls_network_src_any_rules:&sr_cls_network_dst_any_rules);
	}

	//sal_kernel_print_alert("sr_cls_add_ipv4: added node has address %lx\n", (unsigned long)node);
	return 0;
}

int sr_cls_del_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum, SR_8 dir)
{
	struct radix_node *node = NULL;
	struct sockaddr_in *ip=NULL, *mask=NULL;
	struct radix_head *tree_head=(dir==SR_DIR_SRC)?sr_cls_src_ipv4:sr_cls_dst_ipv4;

	if (likely(netmask && addr)) { // regular subnet - not "ANY"
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

	node = rn_lookup((void*)ip, (void*)mask, tree_head);
	if (!node) { // failed to insert - free memory
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"failed to del ipv4 for rule %d, node not found!\n", rulenum);
		SR_FREE(ip);
		SR_FREE(mask);
		return SR_ERROR;
	}

	rn_walktree_from(tree_head, ip, mask, sr_cls_walker_delrule, (void*)(long)rulenum); // Clears the rule from tree
	if (!node->sr_private.rules.summary) { // removed last rule
		//sal_kernel_print_alert("Cleared last rule from entry, removing entry\n");
		node = rn_delete((void*)ip, (void*)mask, tree_head);
		if (!node) { // failed to insert - free memory
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"failed to del ipv4 for rule %d, node not found!\n", rulenum);
			SR_FREE(ip);
			SR_FREE(mask);
			return SR_ERROR;
		}
		SR_FREE(node); // TODO: do I need to free the original ip and netmasks ?
	}
	//sal_kernel_print_alert("sr_cls_del_ipv4: node to be deleted has address %lx\n", (unsigned long)node);
	SR_FREE(ip);
	SR_FREE(mask);
	} else if (netmask) {
		sal_set_bit_array((SR_U32)(long)rulenum, (dir==SR_DIR_SRC)?&sr_cls_network_src_local_rules:&sr_cls_network_dst_local_rules);
	} else { // "ANY" rule
		sal_clear_bit_array((SR_U32)(long)rulenum, (dir==SR_DIR_SRC)?&sr_cls_network_src_any_rules:&sr_cls_network_dst_any_rules);
	}
	return 0;
}

int sr_cls_find_ipv4(SR_U32 addr, SR_8 dir)
{
	struct radix_node *node = NULL;
	struct sockaddr_in *ip;
	bit_array matched_rules;
	struct radix_head *tree_head=(dir==SR_DIR_SRC)?sr_cls_src_ipv4:sr_cls_dst_ipv4;

	memset(&matched_rules, 0, sizeof(matched_rules));
	ip = SR_ZALLOC(sizeof(struct sockaddr_in));
	if (!ip) {
			return -1;
	}
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = addr;

	node = rn_match((void*)ip, tree_head);
#ifdef DEBUG
	if (node) {
		SR_16 rule;
		char *cp;
		memcpy(&matched_rules, &node->sr_private.rules, sizeof(matched_rules)); 
		sal_kernel_print_info("Found match for IP %lx:\n", (unsigned long)addr);
		cp = (char *)node->rn_key + 4;
		sal_kernel_print_info("Node key is %x.%x.%x.%x\n", cp[0], cp[1], cp[2], cp[3]);
		while ((rule = sal_ffs_and_clear_array (&matched_rules)) != -1) {
			sal_kernel_print_info("Rule #%d\n", rule);
		}
	}
#endif
	
	SR_FREE(ip);

	return (node?0:-1);
}
bit_array *sr_cls_match_ip(SR_U32 addr, SR_8 dir)
{
	struct radix_node *node = NULL;
	struct sockaddr_in ip;
	struct radix_head *tree_head=(dir==SR_DIR_SRC)?sr_cls_src_ipv4:sr_cls_dst_ipv4;

	ip.sin_family = AF_INET;
	ip.sin_addr.s_addr = addr;

	node = rn_match((void*)&ip, tree_head);

	if (node) {
		return(&node->sr_private.rules); 
	} else {
		return NULL;
	}
}

int sr_cls_walker_addrule(struct radix_node *node, void *rulenum)
{
	sal_set_bit_array((SR_U32)(long)rulenum, &node->sr_private.rules);
	return 0;
}

int sr_cls_walker_delrule(struct radix_node *node, void *rulenum)
{
	sal_clear_bit_array((SR_U32)(long)rulenum, &node->sr_private.rules);
	return 0;
}

SR_8 sr_cls_network_msg_dispatch(struct sr_cls_network_msg *msg)
{
	int st;

	switch (msg->msg_type) {
		case SR_CLS_IPV4_DEL_RULE:
			CEF_log_debug(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
							"[del_ipv4] addr=0x%x, netmask=0x%x, rulenum=%d\n",
							msg->addr, msg->netmask, msg->rulenum);	
			if ((st = sr_cls_del_ipv4(msg->addr, msg->netmask, msg->rulenum, msg->dir)) != SR_SUCCESS)
			    return st;
			if ((st = sr_cls_exec_inode_del_rule(SR_NET_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
				return st;
			return sr_cls_uid_del_rule(SR_NET_RULES, msg->uid, msg->rulenum);
			break;
		case SR_CLS_IPV4_ADD_RULE:
			CEF_log_debug(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
							"[add_ipv4] addr=%x, netmask=%x, rulenum=%d\n",
							msg->addr, msg->netmask, msg->rulenum);
			if ((st = sr_cls_add_ipv4(msg->addr, msg->netmask, msg->rulenum, msg->dir)) != SR_SUCCESS)
			    return st;
			if ((st = sr_cls_exec_inode_add_rule(SR_NET_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
				return st;
			return sr_cls_uid_add_rule(SR_NET_RULES, msg->uid, msg->rulenum);
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

