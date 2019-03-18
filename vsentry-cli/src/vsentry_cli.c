#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include "sr_types.h"
#include "sentry.h"
#include "action.h"
#include "ip_rule.h"
#include "can_rule.h"
#include "file_rule.h"
#include "sal_linux.h"
#include "sr_engine_cli.h"
#include "sr_canbus_common.h"
#include "db_tools.h"
#include "redis_mng.h"
#include <termios.h>
#include <sys/stat.h>
#include <pwd.h>
#include "cli.h"

#define NUM_OF_RULES 4096
#define MAX_BUF_SIZE 10000
#define NUM_OF_CMD_ENTRIES 100
#define MAX_LIST_NAME 64

#define CLI_PROMPT "vsentry cli> "
#define RULE "rule"
//#define TUPLE "tuple"
#define FILENAME "files"
#define PERM "perm"
#define PROGRAM "programs"
#define USER "users"
#define ACTION "action"
#define SRC_IP "src_ip"
#define SRC_NETMASK "src_netmask"
#define DST_IP "dst_ip"
#define DST_NETMASK "dst_netmask"
#define IP_PROTO "proto"
#define SRC_PORT "src_port"
#define SDT_PORT "dst_port"
#define CAN_MSG "can_mid"
#define DIRECTION "direction"
#define INTERFACE "interface"
#define ACTION_OBJ "action_obj"
#define ACTION "action"
#define LOG "log"

#define GET_NEXT_TOKEN(ptr, del) \
	ptr = strtok(NULL, del); \
	if (!ptr) \
		return SR_ERROR;

SR_BOOL is_run = SR_TRUE;
static redisContext *c;

#if 0
typedef struct rule_info {
	SR_U32 tuple_id;
	rule_type_t rule_type;
	union {
		can_rule_t can_rule;
		file_rule_t file_rule;
		ip_rule_t ip_rule;
	};
	struct rule_info *next;
} rule_info_t;

typedef struct rule_container {
	char action_name[ACTION_STR_SIZE];
	rule_info_t *rule_info;
} rule_container_t;

rule_container_t file_rules[NUM_OF_RULES] = {};
rule_container_t ip_rules[NUM_OF_RULES] = {};
rule_container_t can_rules[NUM_OF_RULES] = {};
rule_container_t file_wl[NUM_OF_RULES] = {};
rule_container_t ip_wl[NUM_OF_RULES] = {};
rule_container_t can_wl[NUM_OF_RULES] = {};
action_t actions[DB_MAX_NUM_OF_ACTIONS] = {};
#endif

//static action_t *get_action(char *action_name);
static SR_32 cli_handle_reply(SR_32 fd, SR_32 (*handle_data_cb)(char *buf));
//static void cleanup_rule_table(rule_container_t table[]);
//static void cleanup_rule(rule_container_t table[], SR_32 rule_id);
//static void db_cleanup(void);

SR_BOOL engine_state;

//static SR_U8 num_of_actions;

static SR_BOOL is_dirty = SR_FALSE;

#if 0
static void notify_updated_can_rule(SR_U32 rule_id, rule_info_t *update_rule, char *action_name)
{
	char msg[256];

	snprintf(msg, sizeof(msg), "can rule update:\n   rule:%d tuple:%d\n   mid :%x interface :%s direction :%s user:%s program:%s action:%s \n",
		rule_id, update_rule->tuple_id, 
		update_rule->can_rule.tuple.msg_id,
		update_rule->can_rule.tuple.interface,
		get_dir_desc(update_rule->can_rule.tuple.direction),
		update_rule->can_rule.tuple.user, update_rule->can_rule.tuple.program,
		action_name);
	cli_notify_info(msg);
}

static void notify_updated_ip_rule(SR_U32 rule_id, rule_info_t *update_rule, char *action_name)
{
	char src_addr[IPV4_STR_MAX_LEN], src_netmask[IPV4_STR_MAX_LEN], dst_addr[IPV4_STR_MAX_LEN], dst_netmask[IPV4_STR_MAX_LEN];
	char msg[512];

	inet_ntop(AF_INET, &update_rule->ip_rule.tuple.srcaddr, src_addr, IPV4_STR_MAX_LEN);
	inet_ntop(AF_INET, &update_rule->ip_rule.tuple.srcnetmask, src_netmask, IPV4_STR_MAX_LEN);
	inet_ntop(AF_INET, &update_rule->ip_rule.tuple.dstaddr, dst_addr, IPV4_STR_MAX_LEN);
	inet_ntop(AF_INET, &update_rule->ip_rule.tuple.dstnetmask, dst_netmask, IPV4_STR_MAX_LEN);
	snprintf(msg, sizeof(msg), "ip rule updated: \n  rule:%d tuple:%d \n  src_addr:%s/%s dst_addr:%s/%s proto:%d src_port:%d dst_port:%d user:%s program:%s action:%s\n",
		rule_id, update_rule->tuple_id,
		src_addr, src_netmask, dst_addr, dst_netmask, update_rule->ip_rule.tuple.proto,
		update_rule->ip_rule.tuple.srcport, update_rule->ip_rule.tuple.dstport,
		update_rule->ip_rule.tuple.user, update_rule->ip_rule.tuple.program, action_name);
	cli_notify_info(msg);
}

static void notify_updated_file_rule(SR_U32 rule_id, rule_info_t *update_rule, char *action_name)
{
	char msg[256];

	snprintf(msg, sizeof(msg), "file rule updated: \n  rule:%d tuple:%d \n  file:%s perm:%s user:%s program:%s action:%s\n",
			rule_id, update_rule->tuple_id,
			update_rule->file_rule.tuple.filename, prem_db_to_cli(update_rule->file_rule.tuple.permission),
			update_rule->file_rule.tuple.user, update_rule->file_rule.tuple.program, action_name);

	cli_notify_info(msg);
}
#endif

static int engine_connect(void)
{
	int fd;
	struct sockaddr_un addr = {};

	if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) {
		perror("socket error");
		return -1;
	}

        addr.sun_family = AF_UNIX;
        strcpy(addr.sun_path, SR_CLI_INTERFACE_FILE);

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("connect error");
		return -1;
	}

	return fd;
}

// for load (from eng)
#if 0
static SR_32 handle_file_data(rule_info_t *new_rule, SR_U32 rule_num, char *action_name, SR_U32 tuple_id)
{
	char *ptr;

	new_rule->rule_type = RULE_TYPE_FILE;
	new_rule->file_rule.rulenum= rule_num;
	new_rule->file_rule.tuple.id = tuple_id;
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(action_name, ptr, ACTION_STR_SIZE);

	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.tuple.filename, ptr, FILE_NAME_SIZE);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.tuple.permission, ptr, 4);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.tuple.user, ptr, USER_NAME_SIZE);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.tuple.program, ptr, PROG_NAME_SIZE);
#if DEBUG
	printf("file:  tuple:%d action:%s: file:%s perm:%s user:%s prog:%s \n", new_rule->file_rule.tuple.id, action_name,
		new_rule->file_rule.tuple.filename, new_rule->file_rule.tuple.permission, new_rule->file_rule.tuple.user, new_rule->file_rule.tuple.program);
#endif

	return SR_SUCCESS;
}

static SR_32 handle_can_data(rule_info_t *new_rule, SR_U32 rule_num, char *action_name, SR_U32 tuple_id)
{
	char *ptr;

	new_rule->rule_type = RULE_TYPE_CAN;
	new_rule->can_rule.rulenum= rule_num;
	new_rule->can_rule.tuple.id = tuple_id;
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(action_name, ptr, ACTION_STR_SIZE);

	GET_NEXT_TOKEN(ptr, ",");
	new_rule->can_rule.tuple.msg_id = atoi(ptr);
	GET_NEXT_TOKEN(ptr, ",");
	new_rule->can_rule.tuple.direction = atoi(ptr);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->can_rule.tuple.interface, ptr, INTERFACE_SIZE);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->can_rule.tuple.user, ptr, USER_NAME_SIZE);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->can_rule.tuple.program, ptr, PROG_NAME_SIZE);

	return SR_SUCCESS;
}

static SR_32 handle_ip_data(rule_info_t *new_rule, SR_U32 rule_num, char *action_name, SR_U32 tuple_id)
{
	char *ptr;

	new_rule->rule_type = RULE_TYPE_IP;
	new_rule->ip_rule.rulenum= rule_num;
	new_rule->ip_rule.tuple.id = tuple_id;
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(action_name, ptr, ACTION_STR_SIZE);
	GET_NEXT_TOKEN(ptr, ",");
	inet_aton(ptr, &(new_rule->ip_rule.tuple.srcaddr));
	GET_NEXT_TOKEN(ptr, ",");
	inet_aton(ptr, &(new_rule->ip_rule.tuple.srcnetmask));
	GET_NEXT_TOKEN(ptr, ",");
	inet_aton(ptr, &(new_rule->ip_rule.tuple.dstaddr));
	GET_NEXT_TOKEN(ptr, ",");
	inet_aton(ptr, &(new_rule->ip_rule.tuple.dstnetmask));
	GET_NEXT_TOKEN(ptr, ",");
	new_rule->ip_rule.tuple.proto = atoi(ptr);
	GET_NEXT_TOKEN(ptr, ",");
	new_rule->ip_rule.tuple.srcport = atoi(ptr);
	GET_NEXT_TOKEN(ptr, ",");
	new_rule->ip_rule.tuple.dstport = atoi(ptr);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->ip_rule.tuple.user, ptr, USER_NAME_SIZE);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->ip_rule.tuple.program, ptr, PROG_NAME_SIZE);

	return SR_SUCCESS;
}
#endif

// insert a rule to cli db (sorted by tuple id)
#if 0
static void insert_rule_sorted(rule_info_t **table, rule_info_t *new_rule, SR_U32 tuple_id)
{
	rule_info_t **iter;
	
	for (iter = table; *iter && (*iter)->tuple_id < tuple_id; iter = &((*iter)->next));
	new_rule->next = *iter;
	*iter = new_rule;
}

static void update_rule(rule_container_t *table, char *action, rule_info_t *new_rule, SR_U32 tuple_id)
{
	strncpy(table->action_name, action, ACTION_STR_SIZE);
	insert_rule_sorted(&(table->rule_info), new_rule, tuple_id);
}

static rule_info_t *get_rule_sorted(rule_info_t *table, SR_U32 tuple_id)
{
	rule_info_t *iter;

	for (iter = table; iter && iter->tuple_id < tuple_id; iter = iter->next);

	return (iter && iter->tuple_id == tuple_id) ? iter : NULL;
}

static SR_32 delete_rule(rule_info_t **table, SR_U32 tuple_id)
{
	rule_info_t **iter, *help;

	for (iter = table; *iter && (*iter)->tuple_id < tuple_id; iter = &((*iter)->next));
	if (!*iter || (*iter)->tuple_id > tuple_id) {
		printf("\nrule for deletion was not found.\n");	
		return SR_NOT_FOUND;
	}
	help = *iter;
	*iter = (*iter)->next;
	free(help);
	
	return SR_SUCCESS;
}

static SR_32 handle_engine_load(char *buf)
{
	char *ptr, *help_str = NULL;
	SR_32 rc = SR_SUCCESS;

	help_str = strdup(buf);
	ptr = strtok(help_str, ",");
	if (!(ptr = strtok(NULL, ","))) {
		printf("invalid engine message:%s: \n", buf);
		rc =  SR_ERROR;
		goto out;
	}

	engine_state = strcmp(ptr, "on") == 0 ? SR_TRUE : SR_FALSE;

out:
	if (help_str)
		free(help_str);
	return rc;
}

static SR_32 handle_action_load(char *buf)
{
	char *ptr, *help_str = NULL;
	SR_32 rc = SR_SUCCESS;

	if (num_of_actions == DB_MAX_NUM_OF_ACTIONS) {
		printf("max number of actions reached (%d)\n", num_of_actions);
		return SR_ERROR;
	}
	help_str = strdup(buf);
	ptr = strtok(help_str, ",");
	if (!(ptr = strtok(NULL, ","))) {
		printf("invalid action message:%s: \n", buf);
		rc = SR_ERROR;
		goto out;
	}
	strncpy(actions[num_of_actions].action_name, ptr, ACTION_STR_SIZE);
	if (!(ptr = strtok(NULL, ","))) {
		printf("invalid action message:%s: \n", buf);
		rc = SR_ERROR;
		goto out;
	}
	actions[num_of_actions].action = get_action_code(ptr);
	if (!(ptr = strtok(NULL, ","))) {
		printf("invalid action message:%s: \n", buf);
		rc = SR_ERROR;
		goto out;
	}
	actions[num_of_actions].log_facility = get_action_log_facility_code(ptr);
	num_of_actions++;
out:
	if (help_str)
		free(help_str);
	return rc;
}

static SR_32 handle_load_data(char *buf)
{
	char *ptr, *help_str = NULL;
	SR_U32 rule_id, tuple_id;
	rule_info_t *new_rule;
	SR_32 rc = SR_SUCCESS;
	SR_BOOL is_wl;
	char action_name[ACTION_STR_SIZE];

	if (!memcmp(buf, "action", strlen("action")))
		return handle_action_load(buf);

	if (!memcmp(buf, "engine", strlen("engine")))
		return handle_engine_load(buf);

	help_str = strdup(buf);
	ptr = strtok(help_str, ",");
	ptr = strtok(NULL, ",");
	rule_id = atoi(ptr);
	ptr = strtok(NULL, ",");
	tuple_id = atoi(ptr);

	if (!(new_rule = malloc(sizeof(rule_info_t)))) {
		rc =  SR_ERROR;
		goto out;
	}
	new_rule->tuple_id = tuple_id;

	if (!memcmp(buf, "file", strlen("file"))) {
		is_wl = !memcmp(buf, "file_wl", strlen("file_wl"));
		if ((rc = handle_file_data(new_rule, rule_id, action_name, tuple_id)) != SR_SUCCESS) {
			printf("\nerror parsing file rule id:%d tuple:%d \n", rule_id, tuple_id);
			free(new_rule);
			goto out;
		}
		update_rule(is_wl ? &file_wl[rule_id] : &file_rules[rule_id], action_name, new_rule, tuple_id);
		goto out;
	} 
	if (!memcmp(buf, "ip", strlen("ip"))) {
		is_wl = !memcmp(buf, "ip_wl", strlen("ip_wl"));
		if ((rc = handle_ip_data(new_rule, rule_id, action_name, tuple_id)) != SR_SUCCESS) {
			printf("\nerror parsing ip rule id:%d tuple:%d \n", rule_id, tuple_id);
			free(new_rule);
			goto out;
		}
		update_rule(is_wl ? &ip_wl[rule_id] : &ip_rules[rule_id], action_name, new_rule, tuple_id);
		goto out;
	}
	if (!memcmp(buf, "can", strlen("can"))) {
		is_wl = !memcmp(buf, "can_wl", strlen("can_wl"));
		if ((rc = handle_can_data(new_rule, rule_id, action_name, tuple_id)) != SR_SUCCESS) {
			printf("\nerror parsing can rule id:%d tuple:%d \n", rule_id, tuple_id);
			free(new_rule);
			goto out;
		}
		update_rule(is_wl ? &can_wl[rule_id] : &can_rules[rule_id], action_name, new_rule, tuple_id);
		goto out;
	}

out:
	if (help_str)
		free(help_str);

	return rc;
}
#endif

static SR_32 cli_handle_reply(SR_32 fd, SR_32 (*handle_data_cb)(char *buf))
{
	SR_32 ind, len;
	char buf[2000], cval;

	if (!handle_data_cb) {
		printf("Handle reply failed, no handle data cb\n");
		return SR_ERROR;
	}

	buf[0] = 0;
	ind = 0;
	for (;;) { 
		len = read(fd, &cval, 1);
		if (!len) {
			printf("failed to read from socket");
			return SR_ERROR;
		}
		switch (cval) {
			case SR_CLI_END_OF_TRANSACTION: /* Finish reply */
				goto out;
			case SR_CLI_END_OF_ENTITY: /* Finish entity */
				buf[ind] = 0;
				if (handle_data_cb(buf) != SR_SUCCESS) {
					printf(" Handle buf:%s: failed \n", buf);
				}
				buf[0] = 0;
				ind = 0;
				break;
			default:
				buf[ind++] = cval;
				break;
		}
	}
out:
	return SR_SUCCESS;
}

#if 0
static SR_32 handle_load(void)
{
	SR_32 fd, rc, st = SR_SUCCESS;
	char cmd[100];

	if ((fd = engine_connect()) < 0) {
		printf("connection to engine failed\n");
		return SR_ERROR;
	}
	
	strcpy(cmd, "cli_load");
        rc = write(fd, cmd , strlen(cmd));
        if (rc < 0) {
                perror("write error");
                return SR_ERROR;
        }
        if (rc < strlen(cmd)) {
                fprintf(stderr,"partial write");
                return SR_ERROR;
	}
	if (cli_handle_reply(fd, handle_load_data) != SR_SUCCESS) {
                fprintf(stderr,"cli handle reply failed");
                return SR_ERROR;
	}

	sleep(1);
        close(fd);

	return st;
}
#endif

static void print_show_usage(void) 
{
	printf("\n\r");
	printf("\rload 	- load information from database \n");
	printf("\rshow 	- show current information \n");
	printf("\rupdate 	- update current information \n");
	printf("\rdelete  - delete current information \n");
	printf("\rcommit 	- commit current information to database and running configuration \n");
	printf("\rcontrol	- control vsentry \n");
	printf("\rengine	- control engine state\n");
	printf ("\n");
	printf("\rshow    [action | rule | wl] [can | ip | file] [rule=x] [tuple=y] \n");
	printf("\rupdate  [action | rule | wl] [action_obj | can | ip | file] [rule=x] [tuple=y] \n");
	printf("\rdelete  [action | rule | wl] [action_obj | can | ip | file] [rule=x] [tuple=y] \n");
	printf("\r	[action | rule | wl] - action table, user defied table or white list table \n");
	printf("\r	[can | ip | file] - specifies the desired table\n");
	printf("\r	[rule=x] - if exists, shows all tuples on the specific rule\n");
	printf("\r	[tuple=y] - if exists, shows specific tuple\n");
	printf ("\n");
	printf("\rcontrol [wl | sp | sr_ver]  [learn | apply | print | reset] \n");
	printf("\r	[wl | sp] - specifies specific module (white-list or system-policer)\n");
	printf("\r	[sr_ver] - show running vsentry engine version \n");
	printf("\r	[learn | apply | print | reset] - specifies specific action to preform\n");
	printf ("\n");
	printf("\rengine  [state | update] [on | off] \n");
	printf("\r	[state | update] - state to show, update to change \n");
	printf("\r	[on | off] - applicable when using update \n");
	printf("\r\n");
	printf("\r\n");
}

static void print_usage(void)
{
	print_show_usage();
}

static void print_usage_cb(char *buf)
{
	print_usage();
}

static void print_actions(redisContext *c)
{
	//SR_U32 i;
	printf("\nactions \n");
	printf("%-10s %-6s %-6s\n", ACTION_OBJ, ACTION, LOG);
	printf("----------------------------------------\n");
	redis_mng_print_db(c, -1, -1);
	/*for (i = 0 ;i < num_of_actions; i++) {
		printf("%-10s %-6s %-6s \n", actions[i].action_name, get_action_string(actions[i].action), 
				strcmp(get_action_log_facility_string(actions[i].log_facility), "none") != 0 ? "1" : "0");
	}*/
}

static void print_file_rules(redisContext *c, SR_BOOL is_wl, SR_32 rule_id)
{
	//SR_U32 i;
	//rule_info_t *iter;

	printf("\n%sfile rules:\n", is_wl ? "wl " : "");
	printf("%-6s %-88s %-4s %-24s %-10s %s\n",
		RULE, FILENAME, PERM, PROGRAM, USER, ACTION);
	printf("----------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	redis_mng_print_db(c, RULE_TYPE_FILE, rule_id);
#if 0
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i].rule_info; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->file_rule.tuple.id)) {
				printf("%-6d %-88.88s %-4s %-24.24s %-10.10s %-10.10s\n",
					i, iter->file_rule.tuple.filename, prem_db_to_cli(iter->file_rule.tuple.permission),
					iter->file_rule.tuple.program, iter->file_rule.tuple.user, table[i].action_name); 
			}
		}
	}
#endif
}

static void print_ip_rules(redisContext *c, SR_BOOL is_wl, SR_32 rule_id)
{
	//SR_U32 i;
	//rule_info_t *iter;
	//char src_addr[IPV4_STR_MAX_LEN], dst_addr[IPV4_STR_MAX_LEN];
      //  char src_netmask[IPV4_STR_MAX_LEN], dst_netmask[IPV4_STR_MAX_LEN];

	printf("\n%sip rules:\n", is_wl ? "wl " : "");
	printf("%-6s %-16s %-16s %-16s %-16s %-5s %-8s %-8s %-24.24s %-10.10s %-10.10s\n",
		RULE, SRC_IP, SRC_NETMASK, DST_IP, DST_NETMASK, IP_PROTO, SRC_PORT, SDT_PORT, PROGRAM, USER, ACTION);
	printf("---------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	redis_mng_print_db(c, RULE_TYPE_IP, rule_id);
#if 0
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i].rule_info; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->ip_rule.tuple.id)) {
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.srcaddr.s_addr), src_addr, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.srcnetmask.s_addr), src_netmask, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.dstaddr.s_addr), dst_addr, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.dstnetmask.s_addr), dst_netmask, IPV4_STR_MAX_LEN);
				printf("%-6d %-6d %-16s %-16s %-16s %-16s %-5d %-8d %-8d %-24.24s %-10.10s %-10.10s\n",
					i, iter->ip_rule.tuple.id, src_addr, src_netmask, dst_addr, dst_netmask,
					iter->ip_rule.tuple.proto, iter->ip_rule.tuple.srcport, iter->ip_rule.tuple.dstport,
					iter->ip_rule.tuple.program, iter->ip_rule.tuple.user, table[i].action_name);
			}
		}
	}
#endif
}

static void print_can_rules(redisContext *c, SR_BOOL is_wl, SR_32 rule_id)
{
	//SR_U32 i;
	//rule_info_t *iter;
	//char msg_id[32];

	printf("\r\n%scan rules:\n", is_wl ? "wl " : "");
	printf("\r%-6s %-8s %-10s %-10s %-24.24s %-10.10s %-10.10s\n",
		RULE, CAN_MSG, DIRECTION, INTERFACE, PROGRAM, USER, ACTION);
	printf("\r--------------------------------------------------------------------------------------------------------------------------------\n");
	redis_mng_print_db(c, RULE_TYPE_CAN, rule_id);
#if 0
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i].rule_info; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->can_rule.tuple.id)) {
				if (iter->can_rule.tuple.msg_id == MSGID_ANY)
					strcpy(msg_id, "any");
				else
					sprintf(msg_id, "%x", iter->can_rule.tuple.msg_id);
				printf("\r%-6d %-6d %-8s %-10.10s %-10.10s %-24.24s %-10.10s %-10.10s\n", 
					i, iter->can_rule.tuple.id, msg_id, get_dir_desc(iter->can_rule.tuple.direction),
					iter->can_rule.tuple.interface, iter->can_rule.tuple.program, iter->can_rule.tuple.user, table[i].action_name);
			}
		}
	}
#endif
	printf("\r");
}

static int is_valid_msg_ig(char *str)
{
	if (!strcmp(str, "any"))
		return 1;
	for (; *str; str++) {
		if (!isxdigit(*str))
			return 0;
	}
	return 1;
}

static int is_valid_action(char *action_name)
{
	return 1;
}

#if 0
static SR_BOOL is_special_interface(char *interface)
{
	struct stat buf;
	char dev_name[128];

	if (strstr(interface, PCAN_DEV_NAME)) {
		sprintf(dev_name, "/dev/%s", interface);
		if (stat(dev_name, &buf) == 0)
			return SR_TRUE;
	}
	return SR_FALSE;
}

static int is_valid_interface(char *interface)
{
	if (if_nametoindex(interface))
		return 1;
	if (is_special_interface(interface))
		return 1;
	return 0;
}

static int is_valid_dir(char *dir)
{
	return get_dir_id(dir) != -1;
}

static int is_valid_ip_proto(char *ip_proto)
{
	return (!strcmp(ip_proto, "tcp") || !strcmp(ip_proto, "udp") || !strcmp(ip_proto, "any"));
}

static int _is_valid_ip(char *ip_addr)
{
	return (int)is_valid_ip(ip_addr);
}

static int is_valid_port(char *port)
{
	for (; *port; port++) {
		if (!isdigit(*port))
			return 0;
	}

	return 1;
}
#endif

static int is_perm_valid(char *perm)
{
	if (strlen(perm) > 3)
		return 0;

	for(; *perm; perm++) {
		if (*perm != 'r' && *perm != 'w' && *perm != 'x') {
			return 0;
		}
	}

	return 1;
}

static void msg_id_help(void)
{
	printf("hex digits, for any mid - \"any\", default: \"any\" \n");
}

#if 0

static void ip_proto_help(void)
{
	printf("tcp, udp, any\n");
}

static void can_interface_help(void)
{
	struct ifaddrs *addrs,*tmp;
	char buf[1000] = {};

	getifaddrs(&addrs);
	for (tmp = addrs; tmp; tmp = tmp->ifa_next) {
		if (tmp->ifa_name && strstr(tmp->ifa_name, "can"))
			sprintf(buf + strlen(buf), "%s ", tmp->ifa_name);
	}
	
	if (strlen(buf))
		printf("can interfaces: %s\n", buf);
	else
		printf("no can interfaces available!!\n");

	freeifaddrs(addrs);
}

#endif 

static int is_valid_program(char *program)
{
	struct stat buf;

	if (*program == '*')
		return 1;

	if (stat(program, &buf)) {
		printf("program does not exist\n");
		return 0;
	}

        if (!(buf.st_mode & S_IXUSR)) {
		printf("program does reflect an executable\n");
		return 0;
	}

	return 1;

}

static int is_valid_user(char *user)
{
	if (*user == '*')
		return 1;

	if (getpwnam(user))
		return 1;

	return 0;
}

static int is_valid_file(char *file)
{
	struct stat buf;

	if (stat(file, &buf)) {
		printf("file does not exist\n");
		return 0;
	}

	return 1;
}

static void file_perm_help(void)
{
	printf("r - read, w - write, x - executable\n");
}

/* fixme get (and verify) each mid
 * add to list */
#if 0
static char *handle_update_can(void)
{
	char msg_id_def[32];

	strcpy(msg_id_def, "any"); // default

	return cli_get_string_user_input(0, msg_id_def, "mid", is_valid_msg_ig, msg_id_help);
}
#endif

static SR_32 handle_update_can(redisContext *c, SR_BOOL is_wl, SR_U32 rule_id)
{
	//rule_info_t *rule_info, update_rule, *new_rule;
	char /**ptr,*/ *msg_id_input, msg_id_def[32]/*, *dir_input*/, dir_def[16];
	char /**action_name = NULL,*/ new_action_name[ACTION_STR_SIZE];
	SR_32 ret;
	SR_8 update;

	// todo need to know if this is a new rule or modifed, because if new and not all fields are given, need to use default vals

	// Check if the rule exists
	if ((ret = redis_mng_has_can_rule(c, rule_id)) == SR_ERROR)
		return SR_ERROR;

	if (ret) {
		printf("\r\n> updating an existing rule...\n\r");
		update = 1;
/*		if (rule_info->can_rule.tuple.msg_id == MSGID_ANY)
			strcpy(msg_id_def, "any");
		else
			sprintf(msg_id_def, "%x", rule_info->can_rule.tuple.msg_id);
		strcpy(dir_def, get_dir_desc(rule_info->can_rule.tuple.direction));
		action_name = is_wl ? can_wl[rule_id].action_name : can_rules[rule_id].action_name;*/
	} else {
		printf("\r\n> adding a new rule...\n\r");
		update = 0;
		// defaults if no mid list or dir given
		strcpy(msg_id_def, "any");
		strcpy(dir_def, "both");
	}

	// mid - should string or list name, if string verify valid val, else verify nothing (or that list exist ? list type ?)
	msg_id_input = cli_get_string_user_input(update,
			msg_id_def,
			"mid",
			is_valid_msg_ig,
			msg_id_help);
	// fixme
#if 0
	if (!strcmp(msg_id_input, "any"))
		update_rule.can_rule.tuple.msg_id = MSGID_ANY;
	else
		update_rule.can_rule.tuple.msg_id = strtoul(msg_id_input, &ptr, 16);

	strncpy(update_rule.can_rule.tuple.interface, 
		cli_get_string_user_input(update,
				rule_info ? rule_info->can_rule.tuple.interface : NULL,
				"interface",
				is_valid_interface,
				can_interface_help), INTERFACE_SIZE);

	dir_input = cli_get_string_user_input(update,
			dir_def,
			"direction (in, out, both)",
			is_valid_dir,
			NULL);
	update_rule.can_rule.tuple.direction = get_dir_id(dir_input);

	strncpy(update_rule.can_rule.tuple.program,
			cli_get_string_user_input(update,
					rule_info ? rule_info->can_rule.tuple.program : "*",
					"program",
					is_valid_program,
					NULL), PROG_NAME_SIZE);
	strncpy(update_rule.can_rule.tuple.user,
			cli_get_string_user_input(update,
					rule_info ? rule_info->can_rule.tuple.user : "*",
					"user",
					is_valid_user,
					NULL), USER_NAME_SIZE);

	strncpy(new_action_name,
			cli_get_string_user_input(update,
					action_name,
					"action",
					is_valid_action,
					NULL), ACTION_STR_SIZE);

	update_rule.tuple_id = update_rule.can_rule.tuple.id = tuple_id;
	update_rule.can_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_CAN;
#endif

#ifdef CLI_DEBUG
	printf("tuple id :%d \n", update_rule.tuple_id);
	printf("mid :%x \n", update_rule.can_rule.tuple.msg_id);
	printf("interface :%s \n", update_rule.can_rule.tuple.interface);
	printf("direction :%s \n", get_dir_desc(update_rule.can_rule.tuple.direction));
	printf("program :%s \n", update_rule.can_rule.tuple.program);
	printf("user :%s \n", update_rule.can_rule.tuple.user);
	printf("action :%s \n", new_action_name);
#endif
	
#if 0
	//notify_updated_can_rule(rule_id, &update_rule, new_action_name);
	snprintf(msg, sizeof(msg), "can rule update:\n   rule:%d tuple:%d\n   mid :%x interface :%s direction :%s user:%s program:%s action:%s \n",
			rule_id, update_rule->tuple_id,
			update_rule->can_rule.tuple.msg_id,
			update_rule->can_rule.tuple.interface,
			get_dir_desc(update_rule->can_rule.tuple.direction),
			update_rule->can_rule.tuple.user, update_rule->can_rule.tuple.program,
			action_name);
	cli_notify_info(msg);
#endif

	// fixme
	if (update)
		ret = redis_mng_mod_can_rule(c, rule_id, msg_id_input, NULL/*interface*/, NULL/*exec*/, NULL/*user*/,
				new_action_name, dir_def);
	else
		ret = redis_mng_add_can_rule(c, rule_id, msg_id_input, "NULL"/*interface*/, "NULL"/*exec*/, "NULL"/*user*/,
				new_action_name, dir_def);

#if 0
	strncpy(is_wl ? can_wl[rule_id].action_name : can_rules[rule_id].action_name, new_action_name, ACTION_STR_SIZE);
	if (!rule_info) { 
		if (!(new_rule = malloc(sizeof(rule_info_t)))) {
			return SR_ERROR;
		}
		*new_rule = update_rule;
		insert_rule_sorted(is_wl ? &can_wl[rule_id].rule_info : &can_rules[rule_id].rule_info, new_rule, tuple_id);
	} else {
		*rule_info = update_rule;
	}
#endif

	return ret;
}

static SR_32 handle_update_ip(redisContext *c, SR_BOOL is_wl, SR_U32 rule_id)
{
	char /**param,*/ src_ip_address_def[IPV4_STR_MAX_LEN];
	char dst_ip_address_def[IPV4_STR_MAX_LEN], ip_proto_def[8], src_port_def[8], dst_port_def[8];
	char  /**action_name = NULL,*/ new_action_name[ACTION_STR_SIZE];
	SR_32 ret;
	SR_8 update;

	// Check if the rule exists
	if ((ret = redis_mng_has_net_rule(c, rule_id)) == SR_ERROR)
		return SR_ERROR;

#if 0
	rule_info = get_rule_sorted(is_wl ? ip_wl[rule_id].rule_info : ip_rules[rule_id].rule_info, tuple_id);
	action_name = is_wl ? ip_wl[rule_id].action_name : ip_rules[rule_id].action_name;
	if (!*action_name)
		action_name = NULL;
#endif
//	if (rule_info) {
	if (ret) {
//		update_rule = *rule_info;
		update = 1;
		printf("> updating an existing rule...\n");
#if 0
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.srcaddr.s_addr), src_ip_address_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.dstaddr.s_addr), dst_ip_address_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.srcnetmask.s_addr), src_netmask_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.dstnetmask.s_addr), dst_netmask_def, IPV4_STR_MAX_LEN);
		strcpy(ip_proto_def, get_ip_proto_name(rule_info->ip_rule.tuple.proto)); 
		sprintf(src_port_def, "%d", rule_info->ip_rule.tuple.srcport);
		sprintf(dst_port_def, "%d", rule_info->ip_rule.tuple.dstport);
#endif
	} else {
		update = 0;
		printf("\n> adding a new rule...\n");
		strcpy(src_ip_address_def, "0.0.0.0/32");
		strcpy(dst_ip_address_def, "0.0.0.0/32");
//		strcpy(dst_netmask_def, "255.255.255.255");
//		strcpy(src_netmask_def, "255.255.255.255");
		strcpy(ip_proto_def, "tcp");
		strcpy(src_port_def, "0");
		strcpy(dst_port_def, "0");
	}

	// fixme
#if 0
	param = cli_get_string_user_input(rule_info != NULL, src_ip_address_def , "src addr", _is_valid_ip, NULL);
	inet_aton(param, &update_rule.ip_rule.tuple.srcaddr);
	param = cli_get_string_user_input(rule_info != NULL, src_netmask_def , "src netmask", _is_valid_ip, NULL);
	inet_aton(param, &update_rule.ip_rule.tuple.srcnetmask);
	param = cli_get_string_user_input(rule_info != NULL, dst_ip_address_def , "dst addr", _is_valid_ip, NULL);
	inet_aton(param, &update_rule.ip_rule.tuple.dstaddr);
	param = cli_get_string_user_input(rule_info != NULL, dst_netmask_def , "dst netmask", _is_valid_ip, NULL);
	inet_aton(param, &update_rule.ip_rule.tuple.dstnetmask);
	param = cli_get_string_user_input(rule_info != NULL, ip_proto_def , "ip proto", is_valid_ip_proto, ip_proto_help);
	update_rule.ip_rule.tuple.proto = get_ip_proto_code(param);
	param = cli_get_string_user_input(rule_info != NULL, src_port_def , "src port", is_valid_port, NULL);
	update_rule.ip_rule.tuple.srcport = atoi(param);
	param = cli_get_string_user_input(rule_info != NULL, dst_port_def , "dst port", is_valid_port, NULL);
	update_rule.ip_rule.tuple.dstport = atoi(param);

	strncpy(update_rule.ip_rule.tuple.program, cli_get_string_user_input(rule_info != NULL, rule_info ? rule_info->ip_rule.tuple.program : "*" , "program", is_valid_program, NULL),
		 PROG_NAME_SIZE);
	strncpy(update_rule.ip_rule.tuple.user, cli_get_string_user_input(rule_info != NULL, rule_info ? rule_info->ip_rule.tuple.user : "*" , "user", is_valid_user, NULL),
		USER_NAME_SIZE);
	strncpy(new_action_name, cli_get_string_user_input(rule_info != NULL, action_name , "action", is_valid_action, NULL), ACTION_STR_SIZE);
	update_rule.tuple_id = update_rule.ip_rule.tuple.id = tuple_id;
	update_rule.ip_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_IP;
#endif

	//notify_updated_ip_rule(rule_id, &update_rule, new_action_name);
#if 0
	strncpy(is_wl ? ip_wl[rule_id].action_name : ip_rules[rule_id].action_name, new_action_name, ACTION_STR_SIZE);
	if (!rule_info) { 
		if (!(new_rule = malloc(sizeof(rule_info_t)))) {
			return SR_ERROR;
		}
		*new_rule = update_rule;
		insert_rule_sorted(is_wl ? &ip_wl[rule_id].rule_info : &ip_rules[rule_id].rule_info, new_rule, tuple_id);
	} else {
		*rule_info = update_rule;
	}
#endif
	if (update)
		ret = redis_mng_mod_net_rule(c, rule_id, src_ip_address_def, dst_ip_address_def, ip_proto_def,
				src_port_def, dst_port_def, NULL/*exec*/, NULL/*user*/, new_action_name);
	else
		ret = redis_mng_add_net_rule(c, rule_id, src_ip_address_def, dst_ip_address_def, ip_proto_def,
				src_port_def, dst_port_def, "NULL"/*exec*/, "NULL"/*user*/, new_action_name);
	return ret;
}

static SR_32 handle_update_file(redisContext *c, SR_BOOL is_wl, SR_U32 rule_id)
{
	char  *action_name = NULL, new_action_name[ACTION_STR_SIZE];
	SR_32 ret;
	SR_8 is_update;
	char filename[FILE_NAME_SIZE];
	char permission[4];
 	char user[USER_NAME_SIZE];
	char program[PROG_NAME_SIZE];
//	SR_U8 file_op = 0;

	// Check if the rule exists
	ret = redis_mng_has_file_rule(c, rule_id);
	if ((ret = redis_mng_has_file_rule(c, rule_id)) == SR_ERROR)
		return SR_ERROR;

	if (ret) {
		is_update = 1;
		printf("\n> updating an existing rule...\n");
	} else {
		is_update = 0;
		printf("\n> adding a new rule...\n");
	}

	strncpy(filename,
		cli_get_string_user_input(is_update, is_update ? filename : NULL , "file", is_valid_file, NULL), FILE_NAME_SIZE);
	strncpy(permission, cli_get_string_user_input(is_update, is_update ? permission : NULL , "perm", is_perm_valid, file_perm_help), sizeof(permission));
	strncpy(program, cli_get_string_user_input(is_update, is_update ? program : "*" , "program", is_valid_program, NULL), PROG_NAME_SIZE);
	strncpy(user, cli_get_string_user_input(is_update, is_update ? user : "*" , "user", is_valid_user, NULL), USER_NAME_SIZE);
	strncpy(new_action_name, cli_get_string_user_input(is_update, action_name, "action", is_valid_action, NULL), ACTION_STR_SIZE);

#if 0
	strncpy(is_wl ? file_wl[rule_id].action_name : file_rules[rule_id].action_name, new_action_name, ACTION_STR_SIZE);
	if (!rule_info) { 
		if (!(new_rule = malloc(sizeof(rule_info_t)))) {
			return SR_ERROR;
		}
		*new_rule = update_rule;
		insert_rule_sorted(is_wl ? &file_wl[rule_id].rule_info : &file_rules[rule_id].rule_info, new_rule, tuple_id);
	} else {
		*rule_info = update_rule;
	}
#endif
	if (is_update)
		ret = redis_mng_mod_file_rule(c, rule_id, NULL/*file_name*/, NULL/*exec*/, NULL/*user*/, new_action_name, permission/*file_op*/);
	else {
		ret = redis_mng_add_file_rule(c, rule_id, filename, program, user, new_action_name, permission);
	}
/*
	  if ((rc = redis_mng_add_file_rule(c, i, strs.file, "NULL", "NULL", "drop",
                                j ? (j == 1 ? SR_FILEOPS_READ : SR_FILEOPS_WRITE) : SR_FILEOPS_EXEC))) {
                        printf("ERROR: redis_mng_add_file_rule %d failed, ret %d\n", i, rc);
                        redis_mng_session_end(c);
                        return -1;
                }

*/

	//notify_updated_file_rule(rule_id, &update_rule, new_action_name);
	return ret;
}

static SR_32 handle_delete(redisContext *c, rule_type_t rule_type, SR_U32 rule_id)
{
	char rule_type_str[MAX_RULE_TYPE], msg[256], rules_msg[256];
	SR_32 ret;

	strcpy(rule_type_str, get_rule_string(rule_type));
#if 0
	if (rule_id == -1) {
		cleanup_rule_table(rule_container);
		strcpy(rules_msg, "rules were deleted");
		goto out;
	}
#endif
	sprintf(rules_msg, "rule id:%d was deleted", rule_id);

	switch (rule_type) {
	case RULE_TYPE_CAN:
		ret = redis_mng_del_can_rule(c, rule_id);
		break;
	case RULE_TYPE_IP:
		ret = redis_mng_del_net_rule(c, rule_id);
		break;
	case RULE_TYPE_FILE:
		ret = redis_mng_del_file_rule(c, rule_id);
		break;
	default:
		ret = SR_ERROR;
	}
	if (ret) {
		sprintf(msg, "%s delete failed", rule_type_str);
		cli_error(msg, SR_TRUE);
	}

#if 0
	if (delete_rule(rule_type, rule_id) != SR_SUCCESS) {
		sprintf(msg, "%s delete failed", rule_type_str);
		cli_error(msg, SR_TRUE);
		return SR_ERROR;
	}
#endif

//out:
	sprintf(msg, "%s %s", rule_type_str, rules_msg);
	cli_notify_info(msg);
	return ret;
}

// todo there was a different container for wl and user rules, how to define now? by rule num ?
static SR_32 handle_delete_can(redisContext *c, SR_BOOL is_wl, SR_U32 rule_id)
{
	return handle_delete(c, RULE_TYPE_CAN, rule_id);
}

static SR_32 handle_delete_ip(redisContext *c, SR_BOOL is_wl, SR_U32 rule_id)
{
	return handle_delete(c, RULE_TYPE_IP, rule_id);
}

static SR_32 handle_delete_file(redisContext *c, SR_BOOL is_wl, SR_U32 rule_id)
{
	return handle_delete(c, RULE_TYPE_FILE, rule_id);
}

#if 0
static action_t *get_action(char *action_name)
{
	SR_U32 i;

	for (i = 0; i < DB_MAX_NUM_OF_ACTIONS && strcmp(action_name, actions[i].action_name); i++);
	if (i == DB_MAX_NUM_OF_ACTIONS) {
		// Not found.
		return NULL;
	}
	return &actions[i];
}
#endif

// fixme will be updated and will print the msg
#if 0
static SR_BOOL is_action_exist_in_rule(rule_container_t table[], char *action_name)
{
	SR_U32 i;

	for (i = 0; i < NUM_OF_RULES; i++) {
		if (!strcmp(table[i].action_name, action_name))
			return SR_TRUE;
	}

	return SR_FALSE;
}
#endif

/*static*/ SR_32 delete_action(redisContext *c, char *action_name)
{
//	SR_U32 i;
//	char msg[128];

#if 0
	for (i = 0; i < num_of_actions && strcmp(action_name, actions[i].action_name) != 0; i++);
	if (i == num_of_actions) {
		snprintf(msg, sizeof(msg), "action %s does not exist\n", action_name);
		cli_error(msg, SR_TRUE);
		return SR_NOT_FOUND;
	}
#endif

	// fixme I will add an API for this
#if 0
	/* check if the action exists in any of the rules */
	if (is_action_exist_in_rule(file_rules, action_name)) {
		sprintf(msg, "action %s exists in file rules", action_name);
		cli_error(msg, SR_TRUE);
		return SR_ERROR;
	}
	if (is_action_exist_in_rule(can_rules, action_name)) {
		sprintf(msg, "action %s exists in can rules", action_name);
		cli_error(msg, SR_TRUE);
		return SR_ERROR;
	}
	if (is_action_exist_in_rule(ip_rules, action_name)) {
		sprintf(msg, "action %s exists in ip rules", action_name);
		cli_error(msg, SR_TRUE);
		return SR_ERROR;
	}
#endif

#if 0
	for (; i < num_of_actions - 1; i++) 
		actions[i] = actions[i + 1];
	num_of_actions--;
#endif
	return redis_mng_del_action(c, action_name);
}

#if 0
static void engine_commit(SR_32 fd)
{
	char buf[MAX_BUF_SIZE];
	SR_U32 len;

	sprintf(buf, "engine,%s%c", engine_state ? "on" :  "off", SR_CLI_END_OF_ENTITY);
	len = strlen(buf);
	if (write(fd, buf, len) < len) {
		printf("Write to engine failed !!\n");
		return;
	}
}

static void actions_commit(SR_32 fd)
{
	SR_U32 i, len;
	char buf[MAX_BUF_SIZE];

	for (i = 0; i < num_of_actions; i++) {
		sprintf(buf, "action,%s,%s,%s%c", actions[i].action_name, get_action_string(actions[i].action),
                        get_action_log_facility_string(actions[i].log_facility), SR_CLI_END_OF_ENTITY);
                len = strlen(buf);
                if (write(fd, buf, len) < len) {
                        printf("write to engine failed !!\n");
			return;
                }
        }
}

static char *get_str_ip_address(SR_U32 ip)
{
        static char str_address[INET_ADDRSTRLEN];

        // Assuming network order 
        inet_ntop(AF_INET, &ip, str_address, INET_ADDRSTRLEN);

        return str_address;
}

static void commit_file_buf_cb(rule_info_t *iter, SR_BOOL is_wl, char *action, char *buf)
{
	sprintf(buf, "file%s,%d,%d,%s,%s,%s,%s,%s%c",
		is_wl ? "_wl" : "", iter->file_rule.rulenum, iter->file_rule.tuple.id,
		action, iter->file_rule.tuple.filename,
		iter->file_rule.tuple.permission, iter->file_rule.tuple.user,
		iter->file_rule.tuple.program, SR_CLI_END_OF_ENTITY);
}

static void commit_ip_buf_cb(rule_info_t *iter, SR_BOOL is_wl, char *action, char *buf)
{
	char src_addr[IPV4_STR_MAX_LEN], dst_addr[IPV4_STR_MAX_LEN];
	char src_netmask[IPV4_STR_MAX_LEN], dst_netmask[IPV4_STR_MAX_LEN];

	strncpy(src_addr, get_str_ip_address(iter->ip_rule.tuple.srcaddr.s_addr), IPV4_STR_MAX_LEN);
	strncpy(src_netmask, get_str_ip_address(iter->ip_rule.tuple.srcnetmask.s_addr), IPV4_STR_MAX_LEN);
	strncpy(dst_addr, get_str_ip_address(iter->ip_rule.tuple.dstaddr.s_addr), IPV4_STR_MAX_LEN);
	strncpy(dst_netmask, get_str_ip_address(iter->ip_rule.tuple.dstnetmask.s_addr), IPV4_STR_MAX_LEN);
	sprintf(buf, "ip%s,%d,%d,%s,%s,%s,%s,%s,%d,%d,%d,%s,%s%c",
						is_wl ? "_wl" : "", iter->ip_rule.rulenum, iter->ip_rule.tuple.id, action,
						src_addr, src_netmask, dst_addr, dst_netmask, iter->ip_rule.tuple.proto,
						iter->ip_rule.tuple.srcport, iter->ip_rule.tuple.dstport, iter->ip_rule.tuple.user, iter->ip_rule.tuple.program,
						SR_CLI_END_OF_ENTITY);
}

static void commit_can_buf_cb(rule_info_t *iter, SR_BOOL is_wl, char *action, char *buf)
{
	sprintf(buf, "can%s,%d,%d,%s,%d,%d,%s,%s,%s%c",
		is_wl ? "_wl" : "", iter->can_rule.rulenum, iter->can_rule.tuple.id, action,
		iter->can_rule.tuple.msg_id, iter->can_rule.tuple.direction, iter->can_rule.tuple.interface,
		iter->can_rule.tuple.user, iter->can_rule.tuple.program, SR_CLI_END_OF_ENTITY);
}

static void rule_type_commit(SR_BOOL is_wl, rule_container_t table[], SR_32 fd, void (*buf_cb)(rule_info_t *iter, SR_BOOL is_wl, char *action, char *buf))
{
	rule_info_t *iter;
	SR_U32 i, len;
	char buf[MAX_BUF_SIZE];
	char *action_name;

	if (!buf_cb) {
		printf("cannot create buffer !!!\n");
		return;
	}

	for (i = 0; i < NUM_OF_RULES; i++) {
		action_name = table[i].action_name;
		for (iter = table[i].rule_info; iter; iter = iter->next) {
			buf_cb(iter, is_wl, action_name, buf);
			len = strlen(buf);
			if (write(fd, buf, len) < len) {
				printf("write to engine failed !!\n");
				return;
			}
		}
	}
}

static void rules_commit(SR_32 fd)
{
	rule_type_commit(SR_TRUE, file_wl, fd, commit_file_buf_cb);
	rule_type_commit(SR_TRUE, can_wl, fd, commit_can_buf_cb);
	rule_type_commit(SR_TRUE, ip_wl, fd, commit_ip_buf_cb);
	rule_type_commit(SR_FALSE, file_rules, fd, commit_file_buf_cb);
	rule_type_commit(SR_FALSE, can_rules, fd, commit_can_buf_cb);
	rule_type_commit(SR_FALSE, ip_rules, fd, commit_ip_buf_cb);
}

static SR_32 __handle_commit(void)
{
	SR_32 fd, rc, len, st = SR_SUCCESS;
	char cmd[100], cval, buf[2] = {};
	
	if ((fd = engine_connect()) < 0) {
		printf("failed engine connect\n");
		return SR_ERROR;
	}

        strcpy(cmd, "cli_commit");
        rc = write(fd, cmd , strlen(cmd));
        if (rc < 0) {
                perror("write error");
                return SR_ERROR;
        }
        if (rc < strlen(cmd)) {
                fprintf(stderr,"partial write");
                return SR_ERROR;
        }
        len = read(fd, &cval, 1);
        if (!len) {
            printf("failed reading from socket");
            st = SR_ERROR;
            goto out;
        }

	engine_commit(fd);
	actions_commit(fd);
	rules_commit(fd);
	buf[0] = SR_CLI_END_OF_TRANSACTION;
	if (write(fd, buf, 1) < 1)
		printf("write of SR_CLI_END_OF_TRANSACTION failed!\n");
	sleep(1);
	len = read(fd, &cval, 1);
	if (!len) {
		printf("failed reading from socket");
		st = SR_ERROR;
		goto out;
	}

out:
        close(fd);

	if (st == SR_SUCCESS)
		is_dirty = SR_FALSE;

	return st;
}

static void cleanup_rule(rule_container_t table[], SR_32 rule_id)
{
	rule_info_t **iter, *help;

	for (iter = &table[rule_id].rule_info; *iter;) {
		help = *iter;
		*iter = (*iter)->next;
		free(help);
	}
}

static void cleanup_rule_table(rule_container_t table[])
{
	SR_U32 i;

	for (i = 0; i < NUM_OF_RULES; i++) {
		cleanup_rule(table, i);
	}
}

static void db_cleanup(void)
{
	cleanup_rule_table(file_rules);
	cleanup_rule_table(can_rules);
	cleanup_rule_table(ip_rules);
	cleanup_rule_table(file_wl);
	cleanup_rule_table(can_wl);
	cleanup_rule_table(ip_wl);
	num_of_actions = 0;
}
#endif

static SR_32 handle_print_cb(char *buf)
{
	printf("%s", buf);
	return SR_SUCCESS;
}

static void handle_cmd_gen(char *cmd, char *msg, SR_BOOL is_print)
{
	SR_32 fd;
	int rc;

	if ((fd = engine_connect()) < 0) {
		cli_error("failed engine connect", SR_TRUE);
		return;
	}
	rc = write(fd, cmd, strlen(cmd));
	if (rc < 0) {
		cli_error("write error", SR_TRUE);
		return;
	}
	if (rc < strlen(cmd)) {
		cli_error("partial write", SR_TRUE);
		return;
	}

	if (is_print) {
		if (cli_handle_reply(fd, handle_print_cb) != SR_SUCCESS)
			printf("print Failed\n");
	}

	close(fd);

	if (msg)
		cli_notify_info(msg);
}

static void handle_learn(char *buf)
{
	return  handle_cmd_gen("wl_learn", "learning...", SR_FALSE);
}

static void handle_reset(char *buf)
{
	return  handle_cmd_gen("wl_reset", "reseting...", SR_FALSE);
}

static void handle_wl_print(char *buf)
{
	return  handle_cmd_gen("wl_print", NULL, SR_TRUE);
}

static void handle_apply(char *buf)
{
	SR_32 fd;
	int ret = 0, rc, counter = 0;
	char line[4] = {'|', '/', '-', '\\'}, cval;
	fd_set fds;
	struct timeval tv;

	if ((fd = engine_connect()) < 0) {
		cli_error("failed engine connect", SR_TRUE);
		return;
	}
	rc = write(fd, "wl_apply", strlen("wl_apply"));
	if (rc < 0) {
		cli_error("write error", SR_TRUE);
		return;
	}
	if (rc < strlen("wl_apply")) {
		cli_error("partial write", SR_TRUE);
		return;
	}

	printf("\napplying  ");

	while (1) {
		tv.tv_sec = 0;
		tv.tv_usec = 250000;

		FD_ZERO(&fds);
		FD_SET(fd, &fds);

		printf("\033[1D");
		printf("%c", line[counter%4]);
		fflush(stdout);

		counter++;

		ret =  select((fd+1), &fds, NULL, NULL, &tv);
		if (!ret || ret <0)
			continue;
		break;
	}

	if (read(fd, &cval, 1) < 1)
		printf("failed reading from socket");

	cli_notify_info("apply finished.");
	close(fd);
	printf("\nloading....\n");
/*	db_cleanup();
	if (handle_load() != SR_SUCCESS) {
		printf("error handling load\n");
	}*/
	cli_notify_info("load finished.");

}

static void handle_sr_ver(char *buf)
{
	int fd, rc;
	char buf2[256];

	if ((fd = engine_connect()) < 0) {
		cli_error("failed engine connect", SR_TRUE);
		return;
	}
	rc = write(fd, "sr_ver", strlen("sr_ver"));
	if (rc < 0) {
		cli_error("write error", SR_TRUE);
		return;
	}
	if (rc < strlen("sr_ver")) {
		cli_error("partial write", SR_TRUE);
		return;
	}

	usleep(30000);
	rc = read(fd, buf2, 256);
	if (rc < 0) {
		perror("read error");
		return;
	}
	printf("\n%s\n", buf2);

	close(fd);
}

static void rule_help(void)
{
        printf("[rule=X]");
}

static void update_list(void)
{
        printf("listname");
}

static void action_help(void)
{
	printf("action_name action_type (none | allow | drop) [log=syslog | file | none]\n");
}

static void delete_action_help(void)
{
	printf("action_name\n");
}

static void engine_update_help(void)
{
        printf("on | off\b");
}

static void show_rule(char *buf)
{
	print_file_rules(c, SR_FALSE, -1);
	print_can_rules(c, SR_FALSE, -1);
	print_ip_rules(c, SR_FALSE, -1);
}

static void show_wl(char *buf)
{
	print_file_rules(c, SR_TRUE, -1);
	print_can_rules(c, SR_TRUE, -1);
	print_ip_rules(c, SR_TRUE, -1);
}

static void show_action(char *buf)
{
	print_actions(c);
}

static void show(char *buf)
{
	print_actions(c);
	show_rule(buf);
	show_wl(buf);
}

static void get_rule_id(char *buf, int *rule_id)
{
	char *tmp = NULL, *ptr;

	tmp = strdup(buf);

	*rule_id = -1;

	for (ptr = strtok(tmp, " "); ptr && memcmp(ptr, "rule=", strlen("rule=")); ptr = strtok(NULL, " "));
	if (ptr)
		*rule_id = atoi(ptr+strlen("rule="));

	if (tmp)
		free(tmp);
}

static void show_rule_can(char *buf)
{
//	int rule_id, tuple_id;

//	get_rule_ids(buf, &rule_id, &tuple_id);
	print_can_rules(c, SR_FALSE, -1/*rule_id*/);
}

static void show_wl_can(char *buf)
{
//	int rule_id, tuple_id;

//	get_rule_ids(buf, &rule_id, &tuple_id);
	// fixme define high rule numbers only ?
	print_can_rules(c, SR_TRUE, -1/*rule_id*/);
}

static void show_rule_file(char *buf)
{
//	int rule_id, tuple_id;

//	get_rule_ids(buf, &rule_id, &tuple_id);
	print_file_rules(c, SR_FALSE, -1/*rule_id*/);
}

static void show_wl_file(char *buf)
{
//	int rule_id, tuple_id;

//	get_rule_ids(buf, &rule_id, &tuple_id);
	// fixme define high rule numbers only ?
	print_file_rules(c, SR_TRUE, -1/*rule_id*/);
}

static void show_rule_ip(char *buf)
{
//	int rule_id, tuple_id;

//	get_rule_ids(buf, &rule_id, &tuple_id);
	print_ip_rules(c, SR_FALSE, -1/*rule_id*/);
}

static void show_wl_ip(char *buf)
{
//	int rule_id, tuple_id;

//	get_rule_ids(buf, &rule_id, &tuple_id);
	// fixme define high rule numbers only ?
	print_ip_rules(c, SR_TRUE, -1/*rule_id*/);
}

#if 0
static void update_rule_can(redisContext *c)
{
/*	get_rule_ids(buf, &rule_id, &tuple_id);
	if (rule_id == -1 || tuple_id == -1) {
		cli_error("\rRule id or Tuple is missing", SR_FALSE);
		return;
	}*/
	handle_update_can(c, SR_FALSE, rule_id);
	is_dirty = SR_TRUE;
}

static void __update_action(char *buf, SR_BOOL is_delete)
{
	char *tmp = NULL, *ptr, *action_name, *action_type, *log, *log_facility;
	action_t *action;
	action_e action_code;
	char msg[256];
	log_facility_e log_facility_code = LOG_NONE;

	if (!(tmp = strdup(buf)))
		return;
	if (!(ptr = strtok(tmp, " ")))
		return;
	if (!strcmp(ptr, is_delete ? "delete" : "update")) {
		if (!(ptr = strtok(NULL, " ")))
			return;
		if (!strcmp(ptr, "action")) {
			if (!(ptr = strtok(NULL, " ")))
				return;
		}
		
	}
	action_name = ptr;

	if (strlen(action_name) >= ACTION_STR_SIZE) {
		snprintf(msg, sizeof(msg), "Action name exeeds max len %d/%d ", (int)strlen(action_name), ACTION_STR_SIZE - 1);
		cli_error(msg ,SR_TRUE);
		return;
	}
	if (is_delete) {
		if (delete_action(action_name) == SR_SUCCESS) {
			sprintf(msg, "action %s was deleted", action_name);
			cli_notify_info(msg);
		}
		return;
	}
	// todo get from redis
	//action = get_action(action_name);
	if (!action) {
		// Check if a new action can be created
		if (num_of_actions == DB_MAX_NUM_OF_ACTIONS) {
                	printf("max number of action reached (%d)\n", num_of_actions);
                	return;
		}
		action = &actions[num_of_actions++];
		memset(action, 0, sizeof(action_t));
		strncpy(action->action_name, action_name, ACTION_STR_SIZE);
	}

	action_type = strtok(NULL, " ");
	if (!action_type || (action_code = get_action_code(action_type)) == ACTION_INVALID) {
		cli_error("invalid action type" ,SR_TRUE);
		printf("usage: update action action_name action_type (none | allow | drop) log\n");
		return;
	}

	log = strtok(NULL, " ");
	if (log) {
		if (memcmp(log, "log=", strlen("log="))) {
			cli_error("invalid action log", SR_TRUE);
			printf("usage: update action action_name action_type (none | allow | drop) [log=syslog | file | none]\n");
			return;
		}
		log_facility = log + strlen("log=");
		if ((log_facility_code = get_action_log_facility_code(log_facility)) == LOG_INVALID) {
			cli_error("invalid log facility", SR_TRUE);
			printf("usage: update action action_name action_type (none | allow | drop) [log=syslog | file | none]\n");
			return;
		}
	}

#ifdef CLI_DEBUG
	printf("update action:%s: action type:%s: action code:%d  log:%s log facility code:%d \n",
		action_name, action_type, action_code, log_facility, log_facility_code);
#endif
	sprintf(msg, "action %s was updated", action_name);
	cli_notify_info(msg);
	action->action = action_code;
	action->log_facility = log_facility_code;

	if (tmp)
		free(tmp);
}

static void update_action_cb(char *buf)
{
	is_dirty = SR_TRUE;
	return __update_action(buf, SR_FALSE);
}

static void delete_action_cb(char *buf)
{
	is_dirty = SR_TRUE;
	return __update_action(buf, SR_TRUE);
}
#endif

static void update_wl_can(char *buf)
{
/*	int rule_id, tuple_id;

	get_rule_ids(buf, &rule_id, &tuple_id);
	if (rule_id == -1 || tuple_id == -1) {
		cli_error("\rRule id or Tuple is missing", SR_FALSE);
		return;
	}*/
	handle_update_can(c, SR_TRUE, -1/*rule_id*/);
	is_dirty = SR_TRUE;
}

static void update_rule_file(char *buf)
{
	int rule_id;

	get_rule_id(buf, &rule_id);
	if (rule_id < 0) {
		cli_error("\rRule id or Tuple is missing", SR_FALSE);
		return;
	}

	handle_update_file(c, SR_FALSE, rule_id);
	is_dirty = SR_TRUE;
}

static void update_wl_file(char *buf)
{
/*	int rule_id, tuple_id;

	get_rule_ids(buf, &rule_id, &tuple_id);
	
	if (rule_id == -1 || tuple_id == -1) {
		cli_error("\rRule id or Tuple is missing", SR_FALSE);
		return;
	}*/
	handle_update_file(c, SR_TRUE, -1/*rule_id*/);
	is_dirty = SR_TRUE;
}

static void update_rule_ip(char *buf)
{
/*	int rule_id, tuple_id;

	get_rule_ids(buf, &rule_id, &tuple_id);
	
	if (rule_id == -1 || tuple_id == -1) {
		cli_error("\rRule id or Tuple is missing", SR_FALSE);
		return;
	}*/
	handle_update_ip(c, SR_FALSE, -1/*rule_id*/);
	is_dirty = SR_TRUE;
}

static void update_wl_ip(char *buf)
{
/*	int rule_id, tuple_id;

	get_rule_ids(buf, &rule_id, &tuple_id);
	
	if (rule_id == -1 || tuple_id == -1) {
		cli_error("\rRule id or Tuple is missing", SR_FALSE);
		return;
	}*/
	handle_update_ip(c, SR_TRUE, -1/*rule_id*/);
	is_dirty = SR_TRUE;
}

static void delete_rule_file(char *buf)
{
/*	int rule_id, tuple_id;

	get_rule_ids(buf, &rule_id, &tuple_id);*/

	handle_delete_file(c, SR_FALSE, -1);
	is_dirty = SR_TRUE;
}

static void delete_rule_can(char *buf)
{
/*	int rule_id, tuple_id;

	get_rule_ids(buf, &rule_id, &tuple_id);*/

	handle_delete_can(c, SR_FALSE, -1);
	is_dirty = SR_TRUE;
}

static void delete_rule_ip(char *buf)
{
	/*int rule_id, tuple_id;

	get_rule_ids(buf, &rule_id, &tuple_id);*/

	handle_delete_ip(c, SR_FALSE, -1);
	is_dirty = SR_TRUE;
}

static void handle_exit(char *buf)
{
/*
	char *ptr;
	char help[128];

	if (is_dirty) {
		printf("\n>there are uncommited changes. are you sure? [Y|n]\n");
		ptr = fgets(help, 128, stdin);
		if (ptr && *help == 'n')
			return;
	}
*/
	cli_set_run(0);
}

#if 0
static void handle_commit(char *buf)
{
	printf("\ncommitting...\n");
	if (__handle_commit() != SR_SUCCESS) {
		printf("commit failed !!!\n");
	}
}


static void handle_load_cb(char *buf)
{
	db_cleanup();
	if (handle_load() != SR_SUCCESS) {
		cli_error("error handling load\n", SR_TRUE);
	}
	cli_notify_info("load finished.");
}

static void engine_state_cb(char *buf)
{
	printf("\n%s\n", engine_state ? "ON" : "OFF");
}

static void engine_update_cb(char *buf)
{
	char *ptr, *tmp = NULL;

	if (!(tmp = strdup(buf)))
		return;
	ptr = strtok(tmp, " ");
	if (!strcmp(ptr, "engine")) {
		ptr = strtok(NULL, " ");
	}
	if (!ptr || strcmp(ptr, "update")) 
		return; // Somtething wrong
	
	ptr = strtok(NULL, " ");
	if (!ptr)
		return;
	
	if (!strcmp(ptr, "on")) {
		engine_state = SR_TRUE;
		cli_notify_info("engine set to on");
	} else if (!strcmp(ptr, "off")) {
		engine_state = SR_FALSE;
		cli_notify_info("engine set to off");
	} else {
		cli_error("Invalid state, Posible states: on, off", SR_TRUE);
	}

	if (tmp)
		free(tmp);
}
#endif

static void handle_sp_learn(char *buf)
{
	return  handle_cmd_gen("sp_learn", "system policer learning...", SR_FALSE);
}

static void handle_sp_apply(char *buf)
{
	return  handle_cmd_gen("sp_apply", "system policer applying...", SR_FALSE);
}

static void handle_sp_off(char *buf)
{
	return  handle_cmd_gen("sp_off", "system policer off...", SR_FALSE);
}

void get_listname(char *buf, char *name)
{
	char *tmp = NULL, *p;

	if (!(tmp = strdup(buf)))
		return;
	if (!(p = strtok(tmp, " ")))
		goto out;
	if (!(p = strtok(NULL, " ")))
		goto out;
	if (!(p = strtok(NULL, " ")))
		goto out;
	if (!(p = strtok(NULL, " ")))
		goto out;
	strncpy(name, p, MAX_LIST_NAME);
out:
	if (tmp)
		free(tmp);
}

static void handle_list_filename(char *buf)
{
	char name[MAX_LIST_NAME];

	get_listname(buf, name);
	printf("\r\nbuf:%s: \n", name);
#if 0
	rule_info_t *rule_info, update_rule, *new_rule;
	char  *action_name = NULL, new_action_name[ACTION_STR_SIZE];

	// Check if the rule exists
	rule_info = get_rule_sorted(is_wl ? file_wl[rule_id].rule_info : file_rules[rule_id].rule_info, tuple_id);
	action_name = is_wl ? file_wl[rule_id].action_name : file_rules[rule_id].action_name;
	if (rule_info) {
		update_rule = *rule_info;
		printf("> updating an existing rule...\n");
	} else {
		printf("\n> adding a new rule...\n");
		action_name = NULL;
	}

	strncpy(update_rule.file_rule.tuple.filename,
		cli_get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.filename : NULL , "file", is_valid_file, NULL), FILE_NAME_SIZE);
	strncpy(update_rule.file_rule.tuple.permission,
		perm_cli_to_db(cli_get_string_user_input(rule_info != NULL, rule_info ? prem_db_to_cli(rule_info->file_rule.tuple.permission) : NULL , "perm", is_perm_valid,
			 file_perm_help)), 4);
	strncpy(update_rule.file_rule.tuple.program, cli_get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.program : "*" , "program", is_valid_program, NULL), PROG_NAME_SIZE);
	strncpy(update_rule.file_rule.tuple.user, cli_get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.user : "*" , "user", is_valid_user, NULL), USER_NAME_SIZE);
	strncpy(new_action_name, cli_get_string_user_input(rule_info != NULL, action_name, "action", is_valid_action, NULL), ACTION_STR_SIZE);

	update_rule.tuple_id = update_rule.file_rule.tuple.id = tuple_id;
	update_rule.file_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_FILE;

	notify_updated_file_rule(rule_id, &update_rule, new_action_name);

	strncpy(is_wl ? file_wl[rule_id].action_name : file_rules[rule_id].action_name, new_action_name, ACTION_STR_SIZE);
	if (!rule_info) { 
		if (!(new_rule = malloc(sizeof(rule_info_t)))) {
			return SR_ERROR;
		}
		*new_rule = update_rule;
		insert_rule_sorted(is_wl ? &file_wl[rule_id].rule_info : &file_rules[rule_id].rule_info, new_rule, tuple_id);
	} else {
		*rule_info = update_rule;
	}
#endif
}

SR_32 main(int argc, char **argv)
{
	node_operations_t show_operations;
	node_operations_t show_rule_operations;
	node_operations_t show_wl_operations;
	node_operations_t show_action_operations;
	node_operations_t show_rule_can_operations;
	node_operations_t show_rule_file_operations;
	node_operations_t show_rule_ip_operations;
	node_operations_t show_wl_can_operations;
	node_operations_t show_wl_file_operations;
	node_operations_t show_wl_ip_operations;
	node_operations_t update_action_operations;
	node_operations_t update_rule_can_operations;
	node_operations_t update_rule_file_operations;
	node_operations_t update_rule_ip_operations;
	node_operations_t update_wl_can_operations;
	node_operations_t update_wl_file_operations;
	node_operations_t update_wl_ip_operations;
	node_operations_t delete_action_operations;
	node_operations_t delete_rule_file_operations;
	node_operations_t delete_rule_can_operations;
	node_operations_t delete_rule_ip_operations;
	node_operations_t help_operations;
	node_operations_t commit_operations;
	node_operations_t exit_operations;
	node_operations_t load_operations;
	node_operations_t control_wl_learn_operations;
	node_operations_t control_wl_apply_operations;
	node_operations_t control_wl_print_operations;
	node_operations_t control_wl_reset_operations;
	node_operations_t control_sr_ver_operations;
	node_operations_t control_sp_learn_operations;
	node_operations_t control_sp_apply_operations;
	node_operations_t control_sp_off_operations;
	node_operations_t engine_state_operations;
	node_operations_t engine_update_operations;
	node_operations_t update_list_filename_operations;

	// fixme
/*	if (!(argc > 1 && !strcmp(argv[1], "nl"))) {
		if (handle_load() != 0) {
			printf("error handling load\n");
			return SR_ERROR;
		}
	}*/

	if (!(c = redis_mng_session_start(1))) {
                printf("ERROR: redis_mng_session_start failed\n");
                redis_mng_session_end(c);
                return -1;
        }

	cli_init("(vsentry-cli"
		  "(help)"
		  "(show (rule (can)(ip)(file)) (wl (can)(ip)(file))(action))"
		  "(update "
		    "(rule (can)(ip)(file))"
		    "(wl (can)(ip)(file))"
		    "(action)"
		    "(list "
		       "(filename)"
		       "(user)"
		       "(program)"
		     ")"
		   ")" 
		  "(delete (rule (can)(ip)(file)) (wl (can)(ip)(file))(action))"
		  "(commit)"
		  "(control (wl (learn)(apply)(print)(reset))(sr_ver)(sp (learn)(apply)(off)))"
		  "(load)"
		  "(engine (state)(update))"
		  "(exit))"); 

        help_operations.help_cb = NULL;
        help_operations.run_cb = print_usage_cb;
        cli_register_operatios("help", &help_operations);

        show_operations.help_cb = NULL;
        show_operations.run_cb = show;
        cli_register_operatios("show", &show_operations);

        show_rule_operations.help_cb = NULL;
        show_rule_operations.run_cb = show_rule;
        cli_register_operatios("show/rule", &show_rule_operations);

        show_wl_operations.help_cb = NULL;
        show_wl_operations.run_cb = show_wl;
        cli_register_operatios("show/wl", &show_wl_operations);

        show_action_operations.help_cb = NULL;
        show_action_operations.run_cb = show_action;
        cli_register_operatios("show/action", &show_action_operations);

        show_rule_can_operations.help_cb = rule_help;
        show_rule_can_operations.run_cb = show_rule_can;
        cli_register_operatios("show/rule/can", &show_rule_can_operations);

        show_rule_file_operations.help_cb = rule_help;
        show_rule_file_operations.run_cb = show_rule_file;
        cli_register_operatios("show/rule/file", &show_rule_file_operations);

        show_rule_ip_operations.help_cb = rule_help;
        show_rule_ip_operations.run_cb = show_rule_ip;
        cli_register_operatios("show/rule/ip", &show_rule_ip_operations);

        show_wl_can_operations.help_cb = rule_help;
        show_wl_can_operations.run_cb = show_wl_can;
        cli_register_operatios("show/wl/can", &show_wl_can_operations);

        show_wl_file_operations.help_cb = rule_help;
        show_wl_file_operations.run_cb = show_wl_file;
        cli_register_operatios("show/wl/file", &show_wl_file_operations);

        show_wl_ip_operations.help_cb = rule_help;
        show_wl_ip_operations.run_cb = show_wl_ip;
        cli_register_operatios("show/wl/ip", &show_wl_ip_operations);

        update_action_operations.help_cb = action_help;
        update_action_operations.run_cb = NULL/*update_action_cb*/;
        cli_register_operatios("update/action", &update_action_operations);

        delete_action_operations.help_cb = delete_action_help;
        delete_action_operations.run_cb = NULL/*delete_action_cb*/;
        cli_register_operatios("delete/action", &delete_action_operations);

        update_rule_can_operations.help_cb = rule_help;
        update_rule_can_operations.run_cb = NULL/*update_rule_can*/;
        cli_register_operatios("update/rule/can", &update_rule_can_operations);

        update_rule_file_operations.help_cb = rule_help;
        update_rule_file_operations.run_cb = update_rule_file;
        cli_register_operatios("update/rule/file", &update_rule_file_operations);

        update_rule_ip_operations.help_cb = rule_help;
        update_rule_ip_operations.run_cb = update_rule_ip;
        cli_register_operatios("update/rule/ip", &update_rule_ip_operations);

        update_wl_can_operations.help_cb = rule_help;
        update_wl_can_operations.run_cb = update_wl_can;
        cli_register_operatios("update/wl/can", &update_wl_can_operations);

        update_wl_file_operations.help_cb = rule_help;
        update_wl_file_operations.run_cb = update_wl_file;
        cli_register_operatios("update/wl/file", &update_wl_file_operations);

        update_wl_ip_operations.help_cb = rule_help;
        update_wl_ip_operations.run_cb = update_wl_ip;
        cli_register_operatios("update/wl/ip", &update_wl_ip_operations);

        update_list_filename_operations.help_cb = update_list;
        update_list_filename_operations.run_cb = handle_list_filename;
        cli_register_operatios("update/list/filename", &update_list_filename_operations);

        commit_operations.help_cb = NULL;
        commit_operations.run_cb = NULL/*handle_commit*/;
        cli_register_operatios("commit", &commit_operations);

        exit_operations.help_cb = NULL;
        exit_operations.run_cb = handle_exit;
        cli_register_operatios("exit", &exit_operations);

        load_operations.help_cb = NULL;
        load_operations.run_cb = NULL/*handle_load_cb*/;
        cli_register_operatios("load", &load_operations);

        control_wl_learn_operations.help_cb = NULL;
        control_wl_learn_operations.run_cb = handle_learn;
        cli_register_operatios("control/wl/learn", &control_wl_learn_operations);

        control_wl_apply_operations.help_cb = NULL;
        control_wl_apply_operations.run_cb = handle_apply;
        cli_register_operatios("control/wl/apply", &control_wl_apply_operations);

        control_wl_reset_operations.help_cb = NULL;
        control_wl_reset_operations.run_cb = handle_reset;
        cli_register_operatios("control/wl/reset", &control_wl_reset_operations);

        control_wl_print_operations.help_cb = NULL;
        control_wl_print_operations.run_cb = handle_wl_print;
        cli_register_operatios("control/wl/print", &control_wl_print_operations);

        control_sr_ver_operations.help_cb = NULL;
        control_sr_ver_operations.run_cb = handle_sr_ver;
        cli_register_operatios("control/sr_ver", &control_sr_ver_operations);

        delete_rule_file_operations.help_cb = rule_help;
        delete_rule_file_operations.run_cb = delete_rule_file;
        cli_register_operatios("delete/rule/file", &delete_rule_file_operations);

        delete_rule_can_operations.help_cb = rule_help;
        delete_rule_can_operations.run_cb = delete_rule_can;
        cli_register_operatios("delete/rule/can", &delete_rule_can_operations);

        delete_rule_ip_operations.help_cb = rule_help;
        delete_rule_ip_operations.run_cb = delete_rule_ip;
        cli_register_operatios("delete/rule/ip", &delete_rule_ip_operations);

        engine_state_operations.help_cb = NULL;
        engine_state_operations.run_cb = NULL/*engine_state_cb*/;
        cli_register_operatios("engine/state", &engine_state_operations);

        engine_update_operations.help_cb = engine_update_help,
        engine_update_operations.run_cb = NULL/*engine_update_cb*/;
        cli_register_operatios("engine/update", &engine_update_operations);

        control_sp_learn_operations.help_cb = NULL;
        control_sp_learn_operations.run_cb = handle_sp_learn;
        cli_register_operatios("control/sp/learn", &control_sp_learn_operations);

        control_sp_apply_operations.help_cb = NULL;
        control_sp_apply_operations.run_cb = handle_sp_apply;
        cli_register_operatios("control/sp/apply", &control_sp_apply_operations);

        control_sp_off_operations.help_cb = NULL;
        control_sp_off_operations.run_cb = handle_sp_off;
        cli_register_operatios("control/sp/off", &control_sp_off_operations);

        cli_run();

	return SR_SUCCESS;
}

