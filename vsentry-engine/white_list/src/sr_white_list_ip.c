#include "sr_sal_common.h"
#include "sr_event_receiver.h"
#include "sr_radix.h"
#include "sr_sal_common.h"
#include "sr_white_list.h"
#include "sysrepo_mng.h"
#include "sr_actions_common.h"
#include "sr_cls_network_control.h"
#include "sr_cls_port_control.h"
#include "sr_cls_rules_control.h"
#include "sr_config_parse.h"
#include <netinet/in.h>
#include "sr_gen_hash.h"
#include "engine_sal.h"
#include "sysrepo_mng.h"
#include "sr_cls_wl_common.h"

#define HASH_SIZE 500

#define WL_IP_RULE_ID 4095

static SR_BOOL is_wl_ip_init;

typedef struct wl_ip_item { 
	SR_U32 ip;
	struct wl_ip_item *next;
} wl_ip_item_t;

typedef struct wl_exec_item { 
	char exec[SR_MAX_PATH_SIZE];
	struct wl_exec_item *next;
} wl_exec_item_t;

struct radix_head *sr_wl_conngraph_table;
static struct sr_gen_hash *wl_ip_binary_hash;
static wl_ip_item_t *ip_item_list;
static wl_exec_item_t *exec_item_list;

typedef struct wl_ip_binary_item  {
        char exec[SR_MAX_PATH_SIZE];
} sr_wl_ip_binary_t;

void (*print_cb)(char *buf);

void white_list_ip_print_cb_register(void (*i_print_cb)(char *buf))
{
        print_cb = i_print_cb;
}

static SR_32 wl_ip_binary_comp(void *data_in_hash, void *comp_val)
{
	sr_wl_ip_binary_t *wl_ip_binary_item = (sr_wl_ip_binary_t *)data_in_hash;
	char *comp_exe = (char *)comp_val;

	if (!data_in_hash)
		return -1;

	return strncmp(wl_ip_binary_item->exec, comp_exe, SR_MAX_PATH_SIZE);
}

static void wl_ip_binary_print(void *data_in_hash)
{
	sr_wl_ip_binary_t *wl_ip_binary_item = (sr_wl_ip_binary_t *)data_in_hash;
	char print_buf[512];

	sprintf(print_buf, "exec:%s: \n", wl_ip_binary_item->exec);
	printf("%s", print_buf);
	if (print_cb)
		print_cb(print_buf);
}

static SR_U32 wl_ip_binary_create_key(void *data)
{
	sr_wl_ip_binary_t *wl_ip_binary_item = (sr_wl_ip_binary_t *)data;
	SR_U32 num = 0, len, i;

        // TODO : Ctreate a better hash key creation function.
	len = strlen(wl_ip_binary_item->exec);
	for (i = 0; i < len; i++)
		num += wl_ip_binary_item->exec[i];

	return num;
}

static void wl_ip_binary_free(void *data_in_hash)
{
	sr_wl_ip_binary_t *wl_ip_binary_item = (sr_wl_ip_binary_t *)data_in_hash;

	if (!wl_ip_binary_item)
		return;

	SR_Free(wl_ip_binary_item);
}

SR_32 sr_white_list_ip_init(void)
{
	hash_ops_t hash_ops = {};

	hash_ops.create_key = wl_ip_binary_create_key;
	hash_ops.comp = wl_ip_binary_comp;
	hash_ops.print = wl_ip_binary_print;
	hash_ops.free = wl_ip_binary_free;
	if (!(wl_ip_binary_hash = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to init white list ip hash table",REASON);
		return SR_ERROR;
	}

	if (!rn_inithead((void **)&sr_wl_conngraph_table, (8 * offsetof(struct sockaddr_in, sin_addr)))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=error initializing connection graph table",REASON);
		return (SR_ERROR);
	}

	is_wl_ip_init = SR_TRUE;

	return SR_SUCCESS;
}

void sr_white_list_ip_uninit(void)
{
	if (!is_wl_ip_init)
		return;

	sr_gen_hash_destroy(wl_ip_binary_hash);
	is_wl_ip_init = SR_FALSE;
}

void sr_wl_ip_binary_print(void)
{
        sr_gen_hash_print(wl_ip_binary_hash);
}

SR_32 sr_wl_ip_binary_insert(char *exec)
{
	sr_wl_ip_binary_t *sr_wl_ip_binary_item;

	if (sr_gen_hash_get(wl_ip_binary_hash, exec, 0)) {
		return SR_ENTRY_EXISTS;
	}

	SR_Zalloc(sr_wl_ip_binary_item, sr_wl_ip_binary_t *, sizeof(sr_wl_ip_binary_t));
	if (!sr_wl_ip_binary_item) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to allocate memory for white list ip", REASON);
		return SR_ERROR;
	}

	strncpy(sr_wl_ip_binary_item->exec, exec, SR_MAX_PATH_SIZE);
        if (sr_gen_hash_insert(wl_ip_binary_hash, (void *)exec, sr_wl_ip_binary_item, 0) != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                               "%s=failed to insert new item to white list ip table",REASON);
                return SR_ERROR;
        }

	return SR_SUCCESS;
}

static SR_32 white_list_ip_clear_graph(void)
{
	if (!rn_detachhead((void **)&sr_wl_conngraph_table)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to clear connection graph",REASON);
	}

	return sr_white_list_ip_init();
}

SR_32 sr_white_list_ip_delete_all(void)
{
	SR_32 rc, rc1;

	rc = white_list_ip_clear_graph();
        rc1 = sr_gen_hash_delete_all(wl_ip_binary_hash, 0);

	if (rc != SR_SUCCESS || rc1 != SR_SUCCESS) 
		return SR_ERROR;
	return SR_SUCCESS;
}

SR_32 sr_wl_ip_exec_for_all(SR_32 (*cb)(void *hash_data, void *data))
{
        return sr_gen_hash_exec_for_each(wl_ip_binary_hash, cb, NULL, 0);
}

SR_32 exec_add_to_list_cb(void *hash_data, void *data)
{
	sr_wl_ip_binary_t *ip_binary = (sr_wl_ip_binary_t *)hash_data;
	wl_exec_item_t *new_item;

	SR_Zalloc(new_item, wl_exec_item_t *, sizeof(wl_exec_item_t));
        if (!new_item) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                "%s=failed to allocate memory for white list ip exec",REASON);
                return SR_ERROR;
        }
	new_item->next = exec_item_list;
	strcpy(new_item->exec, ip_binary->exec);
	exec_item_list = new_item;

	return SR_SUCCESS;
}

static int ip_add_to_list_cb(struct radix_node *node, void *unused)
{
	struct sockaddr_in *ip;
	wl_ip_item_t *new_item;

	ip=(struct sockaddr_in *)(node->rn_u.rn_leaf.rn_Key);

	SR_Zalloc(new_item, wl_ip_item_t *, sizeof(wl_ip_item_t));
        if (!new_item) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                "%s=failed to allocate memory for white list ip addr",REASON);
                return SR_ERROR;
        }
	new_item->next = ip_item_list;
	new_item->ip = ip->sin_addr.s_addr;
	ip_item_list = new_item;

	return 0;
}

SR_32 sr_white_list_ip_apply(SR_32 is_apply)
{
	wl_exec_item_t *exec_iter, *exec_help;
	wl_ip_item_t *ip_iter, *ip_help;
	static sysrepo_mng_handler_t sysrepo_handler;
	SR_U32 tuple_id = 0;

	// Create one rule, 
        if (sysrepo_mng_session_start(&sysrepo_handler)) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                        "%s=failed to start persistent storage session",REASON);
                return SR_ERROR;
        }

	// load all ips to list
	rn_walktree(sr_wl_conngraph_table, ip_add_to_list_cb, NULL);
	// load all execs to list
	sr_wl_ip_exec_for_all(exec_add_to_list_cb);

	if (!exec_item_list || !ip_item_list)
		return SR_SUCCESS;

	for (exec_iter = exec_item_list, ip_iter = ip_item_list; exec_iter && ip_iter;
			exec_iter = exec_iter->next, ip_iter = ip_iter->next) {
		if (sys_repo_mng_create_net_rule(&sysrepo_handler, WL_IP_RULE_ID, tuple_id, "0.0.0.0", "0.0.0.0", sal_get_str_ip_address(ip_iter->ip), "255.255.255.255",
			0, 0, 0, exec_iter->exec, "*", WHITE_LIST_ACTION) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to create ip rule (id %d ip and exec)",
					REASON, WL_IP_RULE_ID);
		}
		tuple_id++;
	}
	// In case exec iter was left (out of ips, but list on exec still available)
	for (; exec_iter; exec_iter = exec_iter->next) {
		if (sys_repo_mng_create_net_rule(&sysrepo_handler, WL_IP_RULE_ID, tuple_id, "0.0.0.0", "0.0.0.0", sal_get_str_ip_address(ip_item_list->ip), "255.255.255.255",
			0, 0, 0, exec_iter->exec, "*", WHITE_LIST_ACTION) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to create ip rule (id %d exec only)",
					REASON, WL_IP_RULE_ID);
		}
		tuple_id++;
	}
	// In case ip iter was left (out of execs, but list of ips still available)
	for (; ip_iter; ip_iter = ip_iter->next) {
		if (sys_repo_mng_create_net_rule(&sysrepo_handler, WL_IP_RULE_ID, tuple_id, "0.0.0.0", "0.0.0.0", sal_get_str_ip_address(ip_iter->ip), "255.255.255.255",
			0, 0, 0, exec_item_list->exec, "*", WHITE_LIST_ACTION) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to create ip rule (id %d ip only)",
					REASON, WL_IP_RULE_ID);
		}
		tuple_id++;
	}
	
	// Delete the lists
	for (exec_iter = exec_item_list; exec_iter;) {
		exec_help = exec_iter;
		exec_iter = exec_iter->next;
		SR_Free(exec_help);
	}
	exec_item_list = NULL;
	for (ip_iter = ip_item_list; ip_iter;) {
		ip_help = ip_iter;
		ip_iter = ip_iter->next;
		SR_Free(ip_help);
	}
	ip_item_list = NULL;

        if (sys_repo_mng_commit(&sysrepo_handler) != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                "%s=ip wl: failed to commit changes to persistent storage", REASON);
        }
        sysrepo_mng_session_end(&sysrepo_handler);

	return SR_SUCCESS;
}

static SR_32 white_list_ip_update_pid(char *exec, struct sockaddr_in *ip)
{
	if (sr_wl_ip_binary_insert(exec) == SR_ERROR) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=ip wl: ip binary insert failed",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

SR_32 sr_white_list_ip_new_connection(struct sr_ec_new_connection_wl_t *pNewConnection)
{
	struct radix_node *treenodes = NULL;
	struct sockaddr_in *ip=NULL;
	struct radix_node *node;

	if (sr_white_list_get_mode() == SR_WL_MODE_OFF)
		return SR_SUCCESS;

	ip = calloc(1, sizeof(struct sockaddr_in));
	if (!ip) {
		return SR_ERROR;
	}
	ip->sin_family = AF_INET;
	ip->sin_addr.s_addr = pNewConnection->con.remote_addr.v4addr;

	if (!*pNewConnection->exec) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=no exec learned for ip: %x",
				MESSAGE, ip->sin_addr.s_addr);
		return SR_ERROR;
	}

	node = rn_lookup((void*)ip, NULL, sr_wl_conngraph_table);
	
	switch (sr_white_list_get_mode()) {
		case SR_WL_MODE_LEARN:
			if (node) {
				white_list_ip_update_pid(pNewConnection->exec, ip);
				free(ip);
				return SR_SUCCESS;
			}
			treenodes = calloc(1, 2*sizeof(struct radix_node));
			if (!treenodes) {
				free(ip);
				return SR_ERROR;
			}
			node = rn_addroute((void*)ip, NULL, sr_wl_conngraph_table, treenodes);
			white_list_ip_update_pid(pNewConnection->exec, ip);
			break;
		case SR_WL_MODE_APPLY:
			free(ip);
			break;
		default:
			free(ip);
			break;
	}

	return SR_SUCCESS;
}

static int sr_wl_node_printer(struct radix_node *node, void *unused)
{ 
	struct sockaddr_in *ip;
	char print_buf[512];

	ip = (struct sockaddr_in *)(node->rn_u.rn_leaf.rn_Key);
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=address learned: %s", MESSAGE, sal_get_str_ip_address(ip->sin_addr.s_addr));
	sprintf(print_buf, "Address learned: %s\n", sal_get_str_ip_address(ip->sin_addr.s_addr));
	printf("%s", print_buf);

	if (print_cb)
		print_cb(print_buf);
					

	return 0;
}

void sr_wl_conngraph_print_tree(void)
{
	rn_walktree(sr_wl_conngraph_table, sr_wl_node_printer, NULL);
}

void sr_white_list_ip_print(void)
{
	char print_buf[512];

	if (!is_wl_ip_init)
		return;

	printf("radix tree:\n");
	sprintf(print_buf, "ip addresses learned:\n");
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
					"%s=%s",MESSAGE, print_buf);
	if (print_cb)
		print_cb(print_buf);

	sr_wl_conngraph_print_tree();
	printf("\nbinary hash:\n");
	sr_wl_ip_binary_print();
}

