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

struct addrule_data {
	SR_U8   add_rule; // o/w delete
	SR_U32 	rulenum;
	struct radix_node *node; // added/deleted rule's node, from which there is inheritance down
	struct radix_head *head;
};

int sr_cls_walker_update_rule(struct radix_node *node, void *rulenum);

static SR_U32 local_ips[MAX_NUM_OF_LOCAL_IPS];

static int sr_cls_walker_delete(struct radix_node *node, void *data)
{
	struct radix_node *del_node;

	if (node->rn_bit >= 0 || node->rn_bit == -33)
		return 0;

	del_node = rn_delete((void*)node->rn_key, (void*)node->rn_mask, data);
	if (!del_node) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to del ipv4, node not found!",REASON);
		return SR_ERROR;
	}
	SR_FREE(del_node);

	return 0;
}


SR_32 local_ips_array_init(void)
{
	SR_32 count;

	if (sal_get_local_ips(local_ips, &count, MAX_NUM_OF_LOCAL_IPS)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, 
		"%s=sal_get_local_ips failed",REASON);
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
		rn_walktree(sr_cls_src_ipv4, sr_cls_walker_delete, sr_cls_src_ipv4);
		rn_detachhead((void **)&sr_cls_src_ipv4);
		sr_cls_src_ipv4 = NULL;
	}
	if (sr_cls_dst_ipv4) {
		rn_walktree(sr_cls_dst_ipv4, sr_cls_walker_delete, sr_cls_dst_ipv4);
		rn_detachhead((void **)&sr_cls_dst_ipv4);
		sr_cls_dst_ipv4 = NULL;
	}
}

struct radix_head* get_cls_src_ipv4_table(void)
{
	return sr_cls_src_ipv4;
}

struct radix_head* get_cls_dst_ipv4_table(void)
{
	return sr_cls_dst_ipv4;
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

SR_U32 sr_cls_ipv4_apply_mask(SR_U32 addr, SR_U32 netmask)
{
	return addr & netmask;
}

int sr_cls_add_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum, SR_8 dir)
{
	struct radix_node *node = NULL;
	struct radix_node *treenodes = NULL;
	struct sockaddr_in *ip=NULL, *mask=NULL;
	struct radix_head *tree_head = NULL;
	struct addrule_data addrule_data;
	short free_nodes = 0;

	if (likely(netmask && addr)) { // Not an "any" rule
		treenodes = SR_ZALLOC(2 * sizeof(struct radix_node) + sizeof(struct sockaddr_in));
		mask = SR_ZALLOC(sizeof(struct sockaddr_in));
		if (!treenodes || !mask) {
			if (mask)
				SR_FREE(mask);
			if (treenodes)
				SR_FREE(treenodes);
			return -1;
		}
		ip = (struct sockaddr_in *)(treenodes + 2);

		/* before adding to tree, apply mask on given IP, to avoid user mistakes
		 * such as: IP = 0x12341234 with mask = 0xffff0000
		 * in this case we want: IP = 0x1234000 in tree
		 */
		ip->sin_family = AF_INET;
		ip->sin_addr.s_addr = sr_cls_ipv4_apply_mask(addr, netmask);
		//ip.sin_len = 32; // ????
		mask->sin_family = AF_INET;
		mask->sin_addr.s_addr = netmask;
		if (dir == SR_DIR_SRC) {
			tree_head = sr_cls_src_ipv4;
		} else {
			tree_head = sr_cls_dst_ipv4;
		}

		//sal_kernel_print_info("\nadd rule %d:\n", rulenum);
		node = rn_addroute((void*)ip, (void*)mask, tree_head, treenodes);
		if (node) { // new node, inherit from ancestors and duplicates

			/*  to inherit from ancestors:
			 * 	start at parent
			 * 	if parent's left != current node:
			 * 		go to parent's left
			 * 		if we reached a leaf:
			 * 			check if it is my ancestor and stop
			 * 		else:
			 * 			continue
			 * 	else:
			 * 		go to parent's parent
			 *  if we reached the root - stop anyway
			 *
			 * 	finding a single closest ancestor is enough, since it already inherited
			 * 	from all our previous (more far) ancestors
			 */
			struct radix_node *ptr = node->rn_parent;
			struct radix_node *curr = node;
			SR_U8 found_ancestor = 0;
			SR_U8 *my_kp = (SR_U8 *)(node->rn_key + 4);
			SR_U8 *kp, *mp;
			//sal_kernel_print_alert("Checking ancestry for new node %p\n", node);
			//sal_kernel_print_info("find ancestor c 0x%llx (b %d) -> p 0x%llx (b %d)\n", (SR_U64)node & 0xFFFFFFF, node->rn_bit, (SR_U64)ptr & 0xFFFFFFF, ptr->rn_bit);

			// while we have not found our ancestor or reached tree head
			while (!found_ancestor && !(ptr->rn_flags & RNF_ROOT)) {
				if (ptr->rn_left && (ptr->rn_left != curr)) {
					curr = ptr;
					ptr = ptr->rn_left;
					//sal_kernel_print_info("move left c 0x%llx (b %d) -> p 0x%llx (b %d)\n", (SR_U64)curr & 0xFFFFFFF, curr->rn_bit, (SR_U64)ptr & 0xFFFFFFF, ptr->rn_bit);

					if (ptr->rn_bit < 0) { // leaf
						// if this is a non empty leaf - check if ancestor
						if ((ptr->rn_bit != -33) && (ptr->rn_bit > node->rn_bit)) {
							kp = (SR_U8 *)(ptr->rn_key + 4);
							mp = (SR_U8 *)(ptr->rn_mask + 4);

							if ((kp[0] & mp[0]) == (my_kp[0] & mp[0]) &&
									(kp[1] & mp[1]) == (my_kp[1] & mp[1]) &&
									(kp[2] & mp[2]) == (my_kp[2] & mp[2]) &&
									(kp[3] & mp[3]) == (my_kp[3] & mp[3])) {
								// found closest ancestor
								found_ancestor = 1;

								/*sal_kernel_print_info("update ancestor %d.%d.%d.%d mask %d.%d.%d.%d (0x%llx) -> node 0x%llx\n",
										kp[0], kp[1], kp[2], kp[3],
										mp[0], mp[1], mp[2], mp[3],
										(SR_U64)ptr & 0xFFFFFFF,
										(SR_U64)node & 0xFFFFFFF);*/

								sal_or_self_op_arrays(&node->sr_private.rules, &ptr->sr_private.rules);
							}
						}
						// move to leaf's parent before we continue left/up
						if (!found_ancestor) {
							curr = ptr;
							ptr = ptr->rn_parent;
							//sal_kernel_print_info("move up c 0x%llx (b %d), p 0x%llx  (b %d)\n", (SR_U64)curr & 0xFFFFFFF, curr->rn_bit, (SR_U64)ptr & 0xFFFFFFF, ptr->rn_bit);
						}
					} else if (ptr->rn_bit == 0) {
						// duplicated node - already inherited from original node
						//sal_kernel_print_info("duplicated node - end\n");
						found_ancestor = 1; // end search
					}
				} else {
					curr = ptr;
					ptr = ptr->rn_parent;
					//sal_kernel_print_info("move up c 0x%llx (b %d), p 0x%llx  (b %d)\n", (SR_U64)curr & 0xFFFFFFF, curr->rn_bit, (SR_U64)ptr & 0xFFFFFFF, ptr->rn_bit);
				}
			}

			// if new node has a duplicated node - inherit from it as well
			if (node->rn_dupedkey) {
				//sal_kernel_print_info("inherit from duplicated node 0x%llx (b %d) - > 0x%llx\n", (SR_U64)node->rn_dupedkey & 0xFFFFFFF, node->rn_dupedkey->rn_bit, (SR_U64)node & 0xFFFFFFF);
				sal_or_self_op_arrays(&node->sr_private.rules, &node->rn_dupedkey->sr_private.rules);
			}
		}

		if (!node) { // failed to insert or node already exist
			//sal_kernel_print_info("no node\n");

			/* in case we add key & netmask that already exist - node will be NULL
			 * but we still need to set ba.
			 * check if node already exist - to update addrule_data */
			node = rn_lookup((void*)ip, (void*)mask, tree_head);
			//sal_kernel_print_info("lookup ret 0x%llx\n", (SR_U64)node & 0xFFFFFFF);
			free_nodes = 1;
		}

		if (node) { // check again in case rn_lookup() succeeded
			addrule_data.add_rule = 1;
			addrule_data.rulenum = rulenum;
			addrule_data.node = node;
			addrule_data.head = tree_head;

			rn_walktree_from(tree_head, ip, mask, sr_cls_walker_update_rule, (void*)&addrule_data);
		}
		if (free_nodes) {
			SR_FREE(treenodes);;
		}
		SR_FREE(mask);

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
	struct addrule_data addrule_data;

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

	/* before deleting from tree, apply mask on given IP, to avoid user mistakes
	 * such as: IP = 0x12341234 with mask = 0xffff0000
	 * in this case we want: IP = 0x1234000 in tree
	 */
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = sr_cls_ipv4_apply_mask(addr, netmask);
	//ip.sin_len = 32; // ????
	mask->sin_family = AF_INET;
	mask->sin_addr.s_addr = netmask;

	node = rn_lookup((void*)ip, (void*)mask, tree_head);
	if (!node) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to del ipv4 for rule %d, node not found!",REASON,
			rulenum);
		SR_FREE(ip);
		SR_FREE(mask);
		return SR_ERROR;
	}

	//sal_kernel_print_info("\ndel rule %d:\n", rulenum);
	addrule_data.add_rule = 0; // delete
	addrule_data.rulenum = rulenum;
	addrule_data.node = node;
	addrule_data.head = tree_head;

	// sr_cls_walker_update_rule() will clear the rule from ba and delete nodes if necessary (if ba is empty)
	rn_walktree_from(tree_head, ip, mask, sr_cls_walker_update_rule, (void*)&addrule_data);
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

int sr_cls_walker_update_rule(struct radix_node *node, void *data)
{
	struct addrule_data *ad = (struct addrule_data *)data;
	SR_U8 *kp, *my_kp, *my_mp;
	struct radix_node *del_node;

	if (node == ad->node) {
		if (ad->add_rule) {
			sal_set_bit_array(ad->rulenum, &node->sr_private.rules);
		} else { // delete
			sal_clear_bit_array(ad->rulenum, &node->sr_private.rules);
		}
	} else { // other leaf

		/* when a new leaf is added, its rule number is "passed down" to all leaves
		 * that match new leaf key & netmask.
		 * 2 conditions must be met:
		 *   1) node net mask is longer or equal to new leaf
		 *   2) node key & new leaf mask == new leaf key & new leaf mask
		 *
		 * same should be checked when we delete
		 */
		if (node->rn_bit <= ad->node->rn_bit) {
			kp = (SR_U8 *)(node->rn_key + 4);
			my_kp = (SR_U8 *)(ad->node->rn_key + 4);
			my_mp = (SR_U8 *)(ad->node->rn_mask + 4);

			if ((kp[0] & my_mp[0]) == (my_kp[0] & my_mp[0]) &&
					(kp[1] & my_mp[1]) == (my_kp[1] & my_mp[1]) &&
					(kp[2] & my_mp[2]) == (my_kp[2] & my_mp[2]) &&
					(kp[3] & my_mp[3]) == (my_kp[3] & my_mp[3])) {

				/*sal_kernel_print_info("sr_cls_walker_update_rule: node 0x%llx, rule %d\n",
					(SR_U64)node & 0xFFFFFFF, (SR_U32)(long)ad->rulenum);*/

				if (ad->add_rule) {
					sal_set_bit_array(ad->rulenum, &node->sr_private.rules);
				} else { // delete
					sal_clear_bit_array(ad->rulenum, &node->sr_private.rules);
				}
			}
		}
	}

	// if we removed the last rule (cleared ba) from any leaf - we can now delete it
	if (!node->sr_private.rules.summary) {
		//sal_kernel_print_alert("Cleared last rule from entry, removing entry\n");
		//sal_kernel_print_info("Cleared last rule, removing node 0x%llx\n", (SR_U64)node & 0xFFFFFFF);
		del_node = rn_delete((void*)node->rn_key, (void*)node->rn_mask, ad->head);
		if (!del_node) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to del ipv4, node not found!",REASON);
			return SR_ERROR;
		}
		SR_FREE(del_node);
	}
	return 0;
}

SR_8 sr_cls_network_msg_dispatch(struct sr_cls_network_msg *msg)
{
	int st;

	switch (msg->msg_type) {
		case SR_CLS_IPV4_DEL_RULE:
		
			CEF_log_event(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
				"%s=del_ipv4 addr 0x%x netmask 0x%x %s=%d",MESSAGE,
				msg->addr, 
				msg->netmask, 
				RULE_NUM_KEY,msg->rulenum);	
				
			if ((st = sr_cls_del_ipv4(msg->addr, msg->netmask, msg->rulenum, msg->dir)) != SR_SUCCESS)
			    return st;
			if ((st = sr_cls_exec_inode_del_rule(SR_NET_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
				return st;
			return sr_cls_uid_del_rule(SR_NET_RULES, msg->uid, msg->rulenum);
			
		case SR_CLS_IPV4_ADD_RULE:
		
			CEF_log_event(SR_CEF_CID_NETWORK, "info", SEVERITY_LOW,
				"%s=add_ipv4 addr %x netmask %x %s=%d",MESSAGE,
				msg->addr, 
				msg->netmask, 
				RULE_NUM_KEY,msg->rulenum);
				
			if ((st = sr_cls_add_ipv4(msg->addr, msg->netmask, msg->rulenum, msg->dir)) != SR_SUCCESS)
			    return st;
			if ((st = sr_cls_exec_inode_add_rule(SR_NET_RULES, msg->exec_inode, msg->rulenum)) != SR_SUCCESS)
				return st;
			return sr_cls_uid_add_rule(SR_NET_RULES, msg->uid, msg->rulenum);
			
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

