#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_cls_file.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_cls_test.h"
#include "sr_radix.h"

#ifdef UNIT_TEST

static SR_32 sr_cls_find_ipv4_verify(SR_U32 addr, SR_8 dir, SR_16 *rules, SR_U32 rules_num)
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

#ifdef DEBUG
	if (node) {
		SR_U8 *cp;
		sal_print_info("Found match for IP %u.%u.%u.%u:\n",
				addr & 0xff,
				(addr & 0xff00) >> 8,
				(addr & 0x00ff0000) >> 16,
				(addr & 0xff000000) >> 24);
		cp = (SR_U8 *)node->rn_key + 4;
		sal_print_info("Node key is %d.%d.%d.%d\n", cp[0], cp[1], cp[2], cp[3]);
		memcpy(&matched_rules, &node->sr_private.rules, sizeof(matched_rules));
		while ((rule = sal_ffs_and_clear_array (&matched_rules)) != -1) {
			sal_print_info("Rule %d\n", rule);
		}
		sal_print_info("\n");
	} else {
		sal_print_info("No match for IP %u.%u.%u.%u:\n",
				addr & 0xff,
				(addr & 0xff00) >> 8,
				(addr & 0x00ff0000) >> 16,
				(addr & 0xff000000) >> 24);
	}
#endif

	if (node) {
		memcpy(&matched_rules, &node->sr_private.rules, sizeof(matched_rules));
		rule = sal_ffs_and_clear_array (&matched_rules);
		while ((rule_index < rules_num) && (rule != -1)) {
			if (rule != rules[rule_index])  {
				sal_print_info("sr_cls_find_ipv4_verify: ERR expected rule %d, but match %d instead\n",
						rules[rule_index], rule);
				SR_FREE(ip);
				return -1;
			}
			rule_index++;
			rule = sal_ffs_and_clear_array (&matched_rules);
		}
		if ((rule_index != rules_num) || (rule != -1)) {
			sal_print_info("sr_cls_find_ipv4_verify: ERR num of matched rules != expected\n");
			SR_FREE(ip);
			return -1; // err
		}
	} else { // no match
		if (rules_num != 0) {
			sal_print_info("sr_cls_find_ipv4_verify: ERR expected %d rules, but no match\n", rules_num);
			SR_FREE(ip);
			return -1;
		}
	}

	SR_FREE(ip);
	return 0;
}

SR_32 sr_cls_network_ut1(void)
{
	SR_32 ret = 0;
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

	sr_cls_del_ipv4(htonl(0x23232323), htonl(0xffffffff),10, SR_DIR_SRC);

	if (ret)
		sal_print_info("sr_cls_network_ut1: failed\n");
	return ret;
}

SR_32 sr_cls_network_ut2(void)
{
	SR_32 ret = 0;
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
	sr_cls_del_ipv4(htonl(0xABCDEF09), htonl(0xfffffff0),40, SR_DIR_DST); // del orig of 2 dups

	rules[0] = 20;
	rules[1] = 30;
	rules[2] = 50;
	ret |= sr_cls_find_ipv4_verify(htonl(0xABCDEF00), SR_DIR_DST, rules, 3); // still has dups rules
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

	if (ret)
		sal_print_info("sr_cls_network_ut2: failed\n");
	return ret;
}

SR_32 sr_cls_network_ut3(void)
{
	SR_32 ret = 0;
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

	if (ret)
		sal_print_info("sr_cls_network_ut3: failed\n");
	return ret;
}

SR_32 sr_cls_network_ut4(void)
{
	SR_32 ret = 0;
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

	if (ret)
		sal_print_info("sr_cls_network_ut4: failed\n");
	return ret;
}

SR_32 sr_cls_network_ut5(void)
{
	SR_32 ret = 0;
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

	if (ret)
		sal_print_info("sr_cls_network_ut5: failed\n");
	return ret;
}

SR_32 sr_cls_network_ut6(void)
{
	SR_32 ret = 0;
	SR_16 rules[5];

	// build tree - check inheritance from ancestors
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

	if (ret)
		sal_print_info("sr_cls_network_ut6: failed\n");
	return ret;
}

SR_32 sr_cls_network_ut7(void)
{
	SR_32 ret = 0;
	SR_16 rules[5];

	// build tree down - check inheritance from new node
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

	if (ret)
		sal_print_info("sr_cls_network_ut7: failed\n");
	return ret;
}

SR_32 sr_cls_network_ut8(SR_16 max_rules)
{
	SR_16 i;
	SR_32 ip = 0x0, ip_inc, mask = 0xffffffff;

	// create large tree (> 64k) - each IP match many rules
	ip_inc = 0xffffffff / max_rules;
	for (i = 0; i < max_rules; i++) {
		if (sr_cls_add_ipv4(htonl(ip), htonl(mask << (i % 32)),i, SR_DIR_DST)) {
			sal_print_info("sr_cls_network_ut8: failed\n");
			return -1;
		}
		ip += ip_inc;
	}
	return 0;
}

SR_32 sr_cls_network_ut9(SR_16 max_rules)
{
	SR_16 i;
	SR_32 ip = 0x87654321, mask = 0xffffffff;

	// create large tree (> 64k) - each IP is more specific
	for (i = 0; i < max_rules; i++) {
		if (sr_cls_add_ipv4(htonl(ip), htonl(mask),4095-i, SR_DIR_DST)) {
			sal_print_info("sr_cls_network_ut9: failed\n");
			return -1;
		}
		ip += 0x1;
	}
	return 0;
}

SR_32 sr_cls_can_ut1(SR_16 max_rules)
{
	SR_16 i;
	SR_8 dir;

	for (i = 0; i < max_rules; i++) {
		dir = i % 3;
		if (dir == 2) { // both
			if (sr_cls_canid_add_rule(i, i, SR_CAN_IN)) {
				sal_print_info("sr_cls_can_ut1: failed\n");
				return -1;
			}
			if (sr_cls_canid_add_rule(i, i, SR_CAN_OUT)) {
				sal_print_info("sr_cls_can_ut1: failed\n");
				return -1;
			}
		} else {
			if (sr_cls_canid_add_rule(i, i, dir)) {
				sal_print_info("sr_cls_can_ut1: failed\n");
				return -1;
			}
		}
	}
	return 0;
}

SR_32 sr_cls_file_ut1(SR_16 max_rules)
{
	SR_16 i;
	SR_U32 inode1, exec_inode = 0;
	SR_32 uid = -1;

	inode1 = 4460000;
	for (i = 0; i < max_rules; i++) {
		inode1++;
		if (sr_cls_inode_add_rule(inode1, i)) {
			sal_print_info("sr_cls_file_ut1: failed\n");
			return -1;
		}
		if (sr_cls_exec_inode_add_rule(SR_FILE_RULES, exec_inode, i)) {
			sal_print_info("sr_cls_file_ut1: failed\n");
			return -1;
		}
		if (sr_cls_uid_add_rule(SR_FILE_RULES, uid, i)) {
			sal_print_info("sr_cls_file_ut1: failed\n");
			return -1;
		}
	}
	return 0;
}

void sr_cls_test_runall(void) {
	SR_32 rt = 0;

	rt |= sr_cls_network_ut1();
	rt |= sr_cls_network_ut2();
	rt |= sr_cls_network_ut3();
	rt |= sr_cls_network_ut4();
	rt |= sr_cls_network_ut5();
	rt |= sr_cls_network_ut6();
	rt |= sr_cls_network_ut7();
	/* used to tests debugfs:
	rt |= sr_cls_network_ut8(4096/2);
	rt |= sr_cls_network_ut9(4096/2);
	rt |= sr_cls_can_ut1(4096);
	rt |= sr_cls_file_ut1(4096);*/
	if (!rt)
		sal_print_info("sr_cls_test_runall: All unit tests passed\n");
}

#endif // UNIT_TEST
