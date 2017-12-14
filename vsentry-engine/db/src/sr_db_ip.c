#include "sr_db.h"
#include "string.h"
#include "sal_linux.h"
#include "list.h"

static list_t ip_rules_list;

static bool ip_rule_search_cb(void *candidate, void *data)
{
	ip_rule_t *search_ptr = (ip_rule_t *)data;
	ip_rule_t *candidate_ptr = (ip_rule_t *)candidate;

	if ((search_ptr->rulenum == candidate_ptr->rulenum) &&
		(search_ptr->tuple.id == candidate_ptr->tuple.id))
		return SR_TRUE;

	return SR_FALSE;
}

static int ip_rule_compare_cb(void *a, void *b)
{
	ip_rule_t *ip_rule_a = (ip_rule_t *)a;
	ip_rule_t *ip_rule_b = (ip_rule_t *)b;

	if (ip_rule_a->rulenum > ip_rule_b->rulenum)
		return NODE_CMP_BIGGER;
	if (ip_rule_a->rulenum < ip_rule_b->rulenum)
		return NODE_CMP_SMALLER;
	if (ip_rule_a->tuple.id > ip_rule_b->tuple.id)
		return NODE_CMP_BIGGER;
	if (ip_rule_a->tuple.id < ip_rule_b->tuple.id)
		return NODE_CMP_SMALLER;
	
        return NODE_CMP_EQUAL;
}

static void ip_rule_print_cb(void *data)
{
	ip_rule_t *ip_rule = (ip_rule_t *)data;

	sal_printf("ip_rule#%d tuple:%d prot:%d saddr:%x sport:%d daddr:%x dport:%d \n",
		ip_rule->rulenum, ip_rule->tuple.id, ip_rule->tuple.proto, ip_rule->tuple.srcaddr.s_addr, ip_rule->tuple.srcport,
		ip_rule->tuple.dstaddr.s_addr, ip_rule->tuple.dstport);
}

SR_32 sr_db_ip_rule_init(void)
{
	list_init(&ip_rules_list, ip_rule_search_cb, ip_rule_print_cb, ip_rule_compare_cb);

	return SR_SUCCESS;
}

SR_32 sr_db_ip_rule_add(ip_rule_t *ip_rule)
{
	if (!list_append(&ip_rules_list, ip_rule)) {
		sal_printf("%s list_append failed !!!\n", __FUNCTION__);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

ip_rule_t *sr_db_ip_rule_get(ip_rule_t *ip_rule)
{
	node_t*  node;

	if (!(node = list_search_node(&ip_rules_list, ip_rule)))
		return NULL;
	return node ? (ip_rule_t *)node->data : NULL;
}

SR_32 sr_db_ip_rule_delete(ip_rule_t *ip_rule)
{
	node_t *node;

	if (!(node = list_search_node(&ip_rules_list, ip_rule)))
		return SR_NOT_FOUND;
	if (!list_remove_node(&ip_rules_list, node))
		return SR_ERROR;
	return SR_SUCCESS;
}

void sr_db_ip_rule_print(void)
{
	list_print(&ip_rules_list);
}

SR_32 sr_db_ip_rule_deinit(void)
{
	node_t *ptr = ip_rules_list.head;

	while (ptr) {
        	if (ptr->data)
            		free(ptr->data);
        	list_remove_node(&ip_rules_list, ptr);
		ptr = ip_rules_list.head;
	}

	return SR_SUCCESS;
}

