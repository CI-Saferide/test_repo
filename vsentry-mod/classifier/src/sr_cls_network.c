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
		rn_detachhead((void **)&sr_cls_src_ipv4);
		sr_cls_src_ipv4 = NULL;
	}
	if (sr_cls_dst_ipv4) {
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
	struct sockaddr_in *ip=NULL, *mask=NULL, *mask2=NULL;
	struct radix_head *tree_head = NULL;
	struct addrule_data addrule_data;
	short free_ip = 0;

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

		/* before adding to tree, apply mask on given IP, to avoid user mistakes
		 * such as: IP = 0x12341234 with mask = 0xffff0000
		 * in this case we want: IP = 0x1234000 in tree
		 */
		ip->sin_family = AF_INET;
		ip->sin_addr.s_addr = sr_cls_ipv4_apply_mask(addr, netmask);
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

		//sal_kernel_print_info("add rule %d:\n", rulenum);
		node = rn_addroute((void*)ip, (void*)mask, tree_head, treenodes);
		if (!node) { // failed to insert or node already exist
			// free memory - IP will be freed later
			SR_FREE(treenodes);
			SR_FREE(mask);
		} else { // new node, inherit from ancestors and duplicates

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

		if (!node) {
			//sal_kernel_print_info("no node\n");

			/* in case we add key & netmask that already exist - node will be NULL
			 * but we still need to set ba.
			 * check if node already exist - to update addrule_data */
			node = rn_lookup((void*)ip, (void*)mask, tree_head);
			//sal_kernel_print_info("lookup ret 0x%llx\n", (SR_U64)node & 0xFFFFFFF);
			free_ip = 1;
		}
		if (node) { // check again in case rn_lookup() succeeded
			addrule_data.add_rule = 1;
			addrule_data.rulenum = rulenum;
			addrule_data.node = node;
			addrule_data.head = tree_head;

			rn_walktree_from(tree_head, ip, mask2, sr_cls_walker_update_rule, (void*)&addrule_data);
		}
		if (free_ip) {
			SR_FREE(ip);
		}
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

	//sal_kernel_print_info("del rule %d:\n", rulenum);
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

#ifdef DEBUG
	if (node) {
		SR_16 rule;
		SR_U8 *cp;
		memcpy(&matched_rules, &node->sr_private.rules, sizeof(matched_rules)); 
		sal_kernel_print_info("Found match for IP %u.%u.%u.%u:\n",
				addr & 0xff,
				(addr & 0xff00) >> 8,
				(addr & 0x00ff0000) >> 16,
				(addr & 0xff000000) >> 24);
		cp = (SR_U8 *)node->rn_key + 4;
		sal_kernel_print_info("Node key is %d.%d.%d.%d\n", cp[0], cp[1], cp[2], cp[3]);
		while ((rule = sal_ffs_and_clear_array (&matched_rules)) != -1) {
			sal_kernel_print_info("Rule %d\n", rule);
		}
		sal_kernel_print_info("\n");
	} else {
		sal_kernel_print_info("No match for IP %u.%u.%u.%u:\n",
				addr & 0xff,
				(addr & 0xff00) >> 8,
				(addr & 0x00ff0000) >> 16,
				(addr & 0xff000000) >> 24);
	}
	sal_kernel_print_info("\n");
#endif
	
	SR_FREE(ip);
	return (node?0:-1);
}

#ifdef _RUN_UT_
static int sr_cls_find_ipv4_verify(SR_U32 addr, SR_8 dir, SR_16 *rules, SR_U32 rules_num)
{
	struct radix_node *node = NULL;
	struct sockaddr_in *ip;
	bit_array matched_rules;
	struct radix_head *tree_head=(dir==SR_DIR_SRC)?sr_cls_src_ipv4:sr_cls_dst_ipv4;
	SR_16 rule;
	SR_U32 rule_index = 0;

	memset(&matched_rules, 0, sizeof(matched_rules));
	ip = SR_ZALLOC(sizeof(struct sockaddr_in));
	if (!ip) {
			return -1;
	}
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = addr;

	node = rn_match((void*)ip, tree_head);

	if (node) {
		memcpy(&matched_rules, &node->sr_private.rules, sizeof(matched_rules));
		rule = sal_ffs_and_clear_array (&matched_rules);
		while ((rule_index < rules_num) && (rule != -1)) {
			if (rule != rules[rule_index])  {
				sal_kernel_print_info("sr_cls_find_ipv4_verify: ERR expected rule %d, but match %d instead\n",
						rules[rule_index], rule);
				SR_FREE(ip);
				return -1;
			}
			rule_index++;
			rule = sal_ffs_and_clear_array (&matched_rules);
		}
		if ((rule_index != rules_num) || (rule != -1)) {
			sal_kernel_print_info("sr_cls_find_ipv4_verify: ERR num of matched rules != expected\n");
			SR_FREE(ip);
			return -1; // err
		}
	} else { // no match
		if (rules_num != 0) {
			sal_kernel_print_info("sr_cls_find_ipv4_verify: ERR expected %d rules, but no match\n", rules_num);
			SR_FREE(ip);
			return -1;
		}
	}

	SR_FREE(ip);
	return 0;
}
#endif // _RUN_UT_

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
					((SR_U64)node & 0xFFFFFFF), (SR_U32)(long)ad->rulenum);*/

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
		SR_FREE(del_node); // TODO: do I need to free the original ip and netmasks ?
	}
	return 0;
}

#ifdef _RUN_UT_
int sr_cls_network_ut(void)
{
	int ret = 0;
	SR_16 rules[5];

	sr_cls_add_ipv4(htonl(0x23232323), htonl(0xffffffff),10, SR_DIR_SRC);

	rules[0] = 10;
	ret |= sr_cls_find_ipv4_verify(htonl(0x23232323), SR_DIR_SRC, rules, 1);

	sr_cls_add_ipv4(htonl(0x12345600), htonl(0xffffff00),3000, SR_DIR_SRC);

	rules[0] = 3000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 1);

	sr_cls_add_ipv4(htonl(0x12345670), htonl(0xfffffff0),999, SR_DIR_SRC);

	rules[0] = 999;
	rules[1] = 3000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 2);

	sr_cls_add_ipv4(htonl(0x12345600), htonl(0xffffff00),30, SR_DIR_SRC);

	rules[0] = 30;
	rules[1] = 999;
	rules[2] = 3000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 3);

	sr_cls_add_ipv4(htonl(0x12340000), htonl(0xffff0000),20, SR_DIR_SRC);

	rules[0] = 20;
	rules[1] = 30;
	rules[2] = 999;
	rules[3] = 3000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 4);

	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xffffffff),40, SR_DIR_SRC);

	rules[2] = 40;
	rules[3] = 999;
	rules[4] = 3000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 5);

	sr_cls_del_ipv4(htonl(0x12340000), htonl(0xffff0000), 20, SR_DIR_SRC); // 20

	rules[0] = 30;
	rules[1] = 40;
	rules[2] = 999;
	rules[3] = 3000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 4);

	sr_cls_del_ipv4(htonl(0x12345600), htonl(0xffffff00), 30, SR_DIR_SRC); // 30&3000

	rules[0] = 40;
	rules[1] = 999;
	rules[2] = 3000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 3);

	sr_cls_del_ipv4(htonl(0x12345600), htonl(0xffffff00), 3000, SR_DIR_SRC); // 30&3000

	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 2);

	sr_cls_del_ipv4(htonl(0x12345670), htonl(0xfffffff0),999, SR_DIR_SRC);

	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 1);

	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xffffffff),40, SR_DIR_SRC);

	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_SRC, rules, 0);

	if (ret) {
		sal_kernel_print_info("sr_cls_network_ut: FAIL\n");
	} else {
		sal_kernel_print_info("sr_cls_network_ut: PASS\n");
	}
	return ret;
}

int sr_cls_network_ut2(void)
{
	int ret = 0;
	SR_16 rules[6];

	// this case verifies we deal with duplicated nodes correctly
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),10, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xfffffff0),40, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xff000000),30, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffffC0),20, SR_DIR_DST); // creates dup
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffff00),50, SR_DIR_DST); // creates dup

	rules[0] = 10;
	rules[1] = 20;
	rules[2] = 30;
	rules[3] = 40;
	rules[4] = 50;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 5);
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 5);

	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffffff),60, SR_DIR_DST); // should inherit from both dups

	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 5);
	rules[5] = 60;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 6);

	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),10, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xfffffff0),40, SR_DIR_DST);

	rules[0] = 20;
	rules[1] = 30;
	rules[2] = 50;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 3);
	rules[3] = 60;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 4);

	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xff000000),30, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffff00),20, SR_DIR_DST);

	rules[0] = 50;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 1);
	rules[1] = 60;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 2);

	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffff00),50, SR_DIR_DST);

	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 0);
	rules[0] = 60;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 1);

	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffffff),60, SR_DIR_DST);

	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 0);
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 0);

	if (ret) {
		sal_kernel_print_info("sr_cls_network_ut2: FAIL\n");
	} else {
		sal_kernel_print_info("sr_cls_network_ut2: PASS\n");
	}
	return ret;
}

int sr_cls_network_ut3(void)
{
	int ret = 0;
	SR_16 rules[10];

	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),10, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffff00),20, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xff000000),30, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffffc0),40, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xfffffff0),50, SR_DIR_DST);

	rules[0] = 10;
	rules[1] = 20;
	rules[2] = 30;
	rules[3] = 40;
	rules[4] = 50;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 5);
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 5);

	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xf0000000),60, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffffff),70, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xfff00000),80, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xfffff000),90, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),1000, SR_DIR_DST); // same

	rules[5] = 60;
	rules[6] = 80;
	rules[7] = 90;
	rules[8] = 1000;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 9);
	rules[6] = 70;
	rules[7] = 80;
	rules[8] = 90;
	rules[9] = 1000;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 10);

	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),1000, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xfffff000),90, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xfff00000),80, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffffff),70, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xf0000000),60, SR_DIR_DST);

	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 5);
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 5);

	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xfffffff0),50, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffffc0),40, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xff000000),30, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffff00),20, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),10, SR_DIR_DST);

	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 0);
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 0);

	if (ret) {
		sal_kernel_print_info("sr_cls_network_ut3: FAIL\n");
	} else {
		sal_kernel_print_info("sr_cls_network_ut3: PASS\n");
	}
	return ret;
}

int sr_cls_network_ut4(void)
{
	int ret = 0;
	SR_16 rules[10];

	// same side of tree
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),10, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffff00),20, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xff000000),30, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xfffffff0),40, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffffC0),50, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xf0000000),60, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffffffff),70, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xfff00000),80, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xfffff000),90, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),1000, SR_DIR_DST); // same

	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xfffffff0),100, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xff000000),200, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xffffffc0),300, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xf0000000),400, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xfff00000),500, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xffffff00),600, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xfffff000),700, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xff000000),800, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xffffffff),900, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xfffff000),2000, SR_DIR_DST); // same

	rules[0] = 10;
	rules[1] = 20;
	rules[2] = 30;
	rules[3] = 40;
	rules[4] = 50;
	rules[5] = 60;
	rules[6] = 80;
	rules[7] = 90;
	rules[8] = 1000;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 9);
	rules[0] = 10;
	rules[1] = 20;
	rules[2] = 30;
	rules[3] = 40;
	rules[4] = 50;
	rules[5] = 60;
	rules[6] = 70;
	rules[7] = 80;
	rules[8] = 90;
	rules[9] = 1000;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 10);
	rules[1] = 30;
	rules[2] = 60;
	rules[3] = 80;
	rules[4] = 1000;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCD0000), SR_DIR_DST, rules, 5);
	rules[0] = 100;
	rules[1] = 200;
	rules[2] = 300;
	rules[3] = 400;
	rules[4] = 500;
	rules[5] = 600;
	rules[6] = 700;
	rules[7] = 800;
	rules[8] = 900;
	rules[9] = 2000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x87654321), SR_DIR_DST, rules, 10);
	rules[8] = 2000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x87654320), SR_DIR_DST, rules, 9);

	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),1000, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xfffff000),90, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xfff00000),80, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffffff),70, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xf0000000),60, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffffC0),50, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xfffffff0),40, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xff000000),30, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffffff00),20, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xffff0000),10, SR_DIR_DST);

	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xfffffff0),100, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xff000000),200, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xffffffc0),300, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xf0000000),400, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xfff00000),500, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xffffff00),600, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xfffff000),700, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xff000000),800, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xffffffff),900, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xfffff000),2000, SR_DIR_DST);

	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF09), SR_DIR_DST, rules, 0);
	ret |= sr_cls_find_ipv4_verify(htonl(0x87654321), SR_DIR_DST, rules, 0);

	if (ret) {
		sal_kernel_print_info("sr_cls_network_ut4: FAIL\n");
	} else {
		sal_kernel_print_info("sr_cls_network_ut4: PASS\n");
	}
	return ret;
}

int sr_cls_network_ut5(void)
{
	int ret = 0;
	SR_16 rules[10];

	// different sides of tree
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xffff0000),10, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xffffff00),20, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xff000000),30, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xfffffff0),40, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xffffffC0),50, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xf0000000),60, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xffffffff),70, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xfff00000),80, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xfffff000),90, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x12345678), htonl(0xffff0000),1000, SR_DIR_DST); // same

	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xfffffff0),100, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xff000000),200, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xffffffc0),300, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xf0000000),400, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xfff00000),500, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xffffff00),600, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xfffff000),700, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xff000000),800, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xffffffff),900, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x87654321), htonl(0xfffff000),2000, SR_DIR_DST); // same

	rules[0] = 10;
	rules[1] = 20;
	rules[2] = 30;
	rules[3] = 40;
	rules[4] = 50;
	rules[5] = 60;
	rules[6] = 70;
	rules[7] = 80;
	rules[8] = 90;
	rules[9] = 1000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_DST, rules, 10);
	rules[6] = 80;
	rules[7] = 90;
	rules[8] = 1000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345670), SR_DIR_DST, rules, 9);
	rules[1] = 30;
	rules[2] = 60;
	rules[3] = 80;
	rules[4] = 90;
	rules[5] = 1000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x12345000), SR_DIR_DST, rules, 6);
	rules[0] = 100;
	rules[1] = 200;
	rules[2] = 300;
	rules[3] = 400;
	rules[4] = 500;
	rules[5] = 600;
	rules[6] = 700;
	rules[7] = 800;
	rules[8] = 900;
	rules[9] = 2000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x87654321), SR_DIR_DST, rules, 10);
	rules[0] = 200;
	rules[1] = 300;
	rules[2] = 400;
	rules[3] = 500;
	rules[4] = 600;
	rules[5] = 700;
	rules[6] = 800;
	rules[7] = 2000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x87654300), SR_DIR_DST, rules, 8);

	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xfffffff0),100, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xff000000),200, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xffffffc0),300, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xf0000000),400, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xfff00000),500, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xffffff00),600, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xfffff000),700, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xff000000),800, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xffffffff),900, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x87654321), htonl(0xfffff000),2000, SR_DIR_DST);

	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xffff0000),10, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xffffff00),20, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xff000000),30, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xfffffff0),40, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xffffffC0),50, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xf0000000),60, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xffffffff),70, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xfff00000),80, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xfffff000),90, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x12345678), htonl(0xffff0000),1000, SR_DIR_DST);

	ret |= sr_cls_find_ipv4_verify(htonl(0x12345678), SR_DIR_DST, rules, 0);
	ret |= sr_cls_find_ipv4_verify(htonl(0x87654321), SR_DIR_DST, rules, 0);

	if (ret) {
		sal_kernel_print_info("sr_cls_network_ut5: FAIL\n");
	} else {
		sal_kernel_print_info("sr_cls_network_ut5: PASS\n");
	}
	return ret;
}

int sr_cls_network_ut6_build(void)
{
	int ret = 0;
	SR_16 rules[5];

	sr_cls_add_ipv4(htonl(0x239d247b), htonl(0xffffffff),1111, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2411), htonl(0xffffffff),156, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2a00), htonl(0xffffff00),56, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x23440000), htonl(0xffff0000),4000, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x91440000), htonl(0xffff0000),2222, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d243f), htonl(0xffffffff),343, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2400), htonl(0xffffff00),666, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x23440f00), htonl(0xffffff00),40, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2437), htonl(0xffffffff),500, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x23440f21), htonl(0xffffffff),30, SR_DIR_DST);

	rules[0] = 666;
	rules[1] = 1111;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d247b), SR_DIR_DST, rules, 2);
	rules[0] = 156;
	rules[1] = 666;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d2411), SR_DIR_DST, rules, 2);
	rules[0] = 343;
	rules[1] = 666;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d243f), SR_DIR_DST, rules, 2);
	rules[0] = 500;
	rules[1] = 666;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d2437), SR_DIR_DST, rules, 2);
	rules[0] = 30;
	rules[1] = 40;
	rules[2] = 4000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x23440f21), SR_DIR_DST, rules, 3);

	sr_cls_del_ipv4(htonl(0x239d247b), htonl(0xffffffff),1111, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2411), htonl(0xffffffff),156, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2a00), htonl(0xffffff00),56, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x23440000), htonl(0xffff0000),4000, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x91440000), htonl(0xffff0000),2222, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d243f), htonl(0xffffffff),343, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2400), htonl(0xffffff00),666, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x23440f00), htonl(0xffffff00),40, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2437), htonl(0xffffffff),500, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x23440f21), htonl(0xffffffff),30, SR_DIR_DST);

	ret |= sr_cls_find_ipv4_verify(htonl(0x23440f21), SR_DIR_DST, rules, 0);

	if (ret) {
		sal_kernel_print_info("sr_cls_network_ut6_build: FAIL\n");
	} else {
		sal_kernel_print_info("sr_cls_network_ut6_build: PASS\n");
	}
	return ret;
}

int sr_cls_network_ut7_build_down(void)
{
	int ret = 0;
	SR_16 rules[5];

	sr_cls_add_ipv4(htonl(0x239d0000), htonl(0xffff0000),2, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d8c00), htonl(0xffffff00),303, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2400), htonl(0xffffff00),80, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2400), htonl(0xffffff00),777, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2430), htonl(0xfffffff0),4000, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d247b), htonl(0xffffffff),1111, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2432), htonl(0xffffffff),600, SR_DIR_DST);
	sr_cls_add_ipv4(htonl(0x239d2411), htonl(0xffffffff),156, SR_DIR_DST);

	rules[0] = 2;
	rules[1] = 303;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d8c00), SR_DIR_DST, rules, 2);
	rules[0] = 2;
	rules[1] = 80;
	rules[2] = 777;
	rules[3] = 4000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d2430), SR_DIR_DST, rules, 4);
	rules[0] = 2;
	rules[1] = 80;
	rules[2] = 777;
	rules[3] = 1111;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d247b), SR_DIR_DST, rules, 4);
	rules[0] = 2;
	rules[1] = 80;
	rules[2] = 600;
	rules[3] = 777;
	rules[4] = 4000;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d2432), SR_DIR_DST, rules, 5);
	rules[0] = 2;
	rules[1] = 80;
	rules[2] = 156;
	rules[3] = 777;
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d2411), SR_DIR_DST, rules, 4);

	sr_cls_del_ipv4(htonl(0x239d0000), htonl(0xffff0000),2, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d8c00), htonl(0xffffff00),303, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2400), htonl(0xffffff00),80, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2400), htonl(0xffffff00),777, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2430), htonl(0xfffffff0),4000, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d247b), htonl(0xffffffff),1111, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2432), htonl(0xffffffff),600, SR_DIR_DST);
	sr_cls_del_ipv4(htonl(0x239d2411), htonl(0xffffffff),156, SR_DIR_DST);

	ret |= sr_cls_find_ipv4_verify(htonl(0x239d2430), SR_DIR_DST, rules, 0);
	ret |= sr_cls_find_ipv4_verify(htonl(0x239d2411), SR_DIR_DST, rules, 0);

	if (ret) {
		sal_kernel_print_info("sr_cls_network_ut7_build_down: FAIL\n");
	} else {
		sal_kernel_print_info("sr_cls_network_ut7_build_down: PASS\n");
	}
	return ret;
}
#endif // _RUN_UT_

SR_8 sr_cls_network_msg_dispatch(struct sr_cls_network_msg *msg)
{
	int st;

#ifdef _RUN_UT_
			st = 0;
			st |= sr_cls_network_ut();
			st |= sr_cls_network_ut2();
			st |= sr_cls_network_ut3();
			st |= sr_cls_network_ut4();
			st |= sr_cls_network_ut5();
			st |= sr_cls_network_ut6_build();
			st |= sr_cls_network_ut7_build_down();
			if (st) {
				sal_kernel_print_info("ERROR: unit tests failed\n");
			}
#else

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
#endif
	return SR_SUCCESS;
}

