#include "multiplexer.h"
#include "sal_linux.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_cls_file.h"

struct radix_head *sr_cls_src_ipv4;

void sr_classifier_ut(void) ;
int sr_cls_walker_addrule(struct radix_node *node, void *rulenum);
int sr_cls_walker_delrule(struct radix_node *node, void *rulenum);

int sr_classifier_init(void)
{
	if (!rn_inithead((void **)&sr_cls_src_ipv4, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
		sal_kernel_print_alert("Error Initializing radix tree\n");
	} else {
		sal_kernel_print_alert("Successfully Initialized radix tree\n");
	}
	sr_cls_init();

	sr_classifier_ut();

	return 0;
}

void sr_classifier_uninit(void)
{
	if (sr_cls_src_ipv4) {
		rn_detachhead((void **)&sr_cls_src_ipv4);
		sr_cls_src_ipv4 = NULL;
	}
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
	SR_16 rule;

	memset(&matched_rules, 0, sizeof(matched_rules));

        ip = SR_ZALLOC(sizeof(struct sockaddr_in));


        if (!ip) {
                return -1;
        }
        ip->sin_family = AF_INET;
        ip->sin_addr.s_addr = addr;

        node = rn_match((void*)ip, sr_cls_src_ipv4, &matched_rules);
	if (node) {
		memcpy(&matched_rules, &node->sr_private.rules, sizeof(matched_rules)); 
		//sal_kernel_print_alert("Found match for IP %lx:\n", addr);
		while ((rule = sal_ffs_and_clear_array (&matched_rules)) != -1) {
			//sal_kernel_print_alert("Rule #%d\n", rule);
		}
	}
	

	SR_FREE(ip);

        return (node?0:-1);
}

int sr_cls_walker_addrule(struct radix_node *node, void *rulenum)
{
	//sal_kernel_print_alert("Walker adds rule %d to node %lx\n", (int)rulenum, (unsigned long)node);
	sal_set_bit_array((SR_U32)rulenum, &node->sr_private.rules);
	return 0;
}

int sr_cls_walker_delrule(struct radix_node *node, void *rulenum)
{
	//sal_kernel_print_alert("Walker deletes rule %d to node %lx\n", (int)rulenum, (unsigned long)node);
	sal_clear_bit_array((SR_U32)rulenum, &node->sr_private.rules);
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
}

