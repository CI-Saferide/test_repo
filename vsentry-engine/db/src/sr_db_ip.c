#include "sr_db.h"
#include "string.h"
#include "sal_linux.h"
#include "sal_mem.h"
#include "list.h"
#include "sr_cls_wl_common.h"
#include "sr_engine_cli.h"

static list_t ip_rules_list;

static void dump_ip_rule(void *data, void *param)
{
        int fd = (int)(long)param, n, len;
        char buf[MAX_BUF_SIZE], src_addr[IPV4_STR_MAX_LEN], dst_addr[IPV4_STR_MAX_LEN];
        char src_netmask[IPV4_STR_MAX_LEN], dst_netmask[IPV4_STR_MAX_LEN];
	SR_BOOL is_wl;

      	ip_rule_t *ip_rule = (ip_rule_t *)data;

	is_wl = (ip_rule->rulenum >= SR_IP_WL_START_RULE_NO);
	strncpy(src_addr, sal_get_str_ip_address(htonl(ip_rule->tuple.srcaddr.s_addr)), IPV4_STR_MAX_LEN);
	strncpy(src_netmask, sal_get_str_ip_address(htonl(ip_rule->tuple.srcnetmask.s_addr)), IPV4_STR_MAX_LEN);
	strncpy(dst_addr, sal_get_str_ip_address(htonl(ip_rule->tuple.dstaddr.s_addr)), IPV4_STR_MAX_LEN);
	strncpy(dst_netmask, sal_get_str_ip_address(htonl(ip_rule->tuple.dstnetmask.s_addr)), IPV4_STR_MAX_LEN);
        sprintf(buf, "ip%s,%d,%d,%s,%s,%s,%s,%s,%d,%d,%d,%s,%s%c",
                is_wl ? "_wl" : "", ip_rule->rulenum, ip_rule->tuple.id, ip_rule->action_name,
		src_addr, src_netmask, dst_addr, dst_netmask, ip_rule->tuple.proto,
		ip_rule->tuple.srcport, ip_rule->tuple.dstport, ip_rule->tuple.user, ip_rule->tuple.program, SR_CLI_END_OF_ENTITY);
        len = strlen(buf);
        if ((n = write(fd, buf, len)) < len) {
		perror("write");
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=write to cli for file failed.",REASON);
        }
}

SR_32 ip_rule_dump_rules(int fd)
{   
        list_exec_for_each(&ip_rules_list, dump_ip_rule, (void *)(long)fd);

        return SR_SUCCESS;
}

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
					
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=%d %s=%d %s=%d %s=%x %s=%d %s=%x %s=%d",
		RULE_NUM_KEY,ip_rule->rulenum, 
		"TupleID",ip_rule->tuple.id, 
		TRANSPORT_PROTOCOL,ip_rule->tuple.proto, 
		DEVICE_SRC_IP,ip_rule->tuple.srcaddr.s_addr, 
		DEVICE_SRC_PORT,ip_rule->tuple.srcport,
		DEVICE_DEST_IP,ip_rule->tuple.dstaddr.s_addr, 
		DEVICE_DEST_PORT,ip_rule->tuple.dstport);
}

SR_32 sr_db_ip_rule_init(void)
{
	list_init(&ip_rules_list, ip_rule_search_cb, ip_rule_print_cb, ip_rule_compare_cb);

	return SR_SUCCESS;
}

SR_32 sr_db_ip_rule_add(ip_rule_t *ip_rule)
{
	ip_rule_t *new_item;
    
	SR_Zalloc(new_item, ip_rule_t *, sizeof(ip_rule_t));
	if (!new_item)
		return SR_ERROR;
    	*new_item = *ip_rule;

	if (!list_append(&ip_rules_list, new_item)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
		"%s=ip rule add list_append failed",REASON);
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

