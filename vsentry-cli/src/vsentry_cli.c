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
#include <termios.h>
#include <sys/stat.h>
#include <pwd.h>

#define NUM_OF_RULES 4096
#define MAX_BUF_SIZE 10000
#define NUM_OF_CMD_ENTRIES 100

#define COLOR_RED "\033[31m"
#define COLOR_GREEN "\033[32m"
#define CLEAR_RIGHT "\033[K"
#define COLOR_RESET "\033[0m"

#define CLI_PROMPT "vsentry cli> "
#define RULE "rule"
#define TUPLE "tuple"
#define FILENAME "file"
#define PERM "perm"
#define PROGRAM "program"
#define USER "user"
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

static action_t *get_action(char *action_name);
static void term_reset(int count);

SR_BOOL is_run = SR_TRUE;

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

rule_info_t *file_rules[NUM_OF_RULES] = {};
rule_info_t *ip_rules[NUM_OF_RULES] = {};
rule_info_t *can_rules[NUM_OF_RULES] = {};
rule_info_t *file_wl[NUM_OF_RULES] = {};
rule_info_t *ip_wl[NUM_OF_RULES] = {};
rule_info_t *can_wl[NUM_OF_RULES] = {};
action_t actions[DB_MAX_NUM_OF_ACTIONS] = {};
SR_BOOL engine_state;

static char *cmds[NUM_OF_CMD_ENTRIES] = {};

static SR_U8 num_of_actions;

static SR_U32 cmd_curr;

static SR_BOOL is_dirty = SR_FALSE;

static void error(char *msg, SR_BOOL is_nl)
{
	if (is_nl)
		printf("\n");
	printf(COLOR_RED);
	printf("%s\n", msg);
	printf(COLOR_RESET);
}
		
static void notify_info(char *msg)
{
	printf(COLOR_GREEN);
	printf("\n%s\n", msg);
	printf(COLOR_RESET);
}
		
static void notify_updated_can_rule(SR_U32 rule_id, rule_info_t *update_rule)
{
	printf(COLOR_GREEN);
	printf("can rule update:\n");
	printf("  rule:%d tuple:%d\n", rule_id, update_rule->tuple_id);
	printf("  mid :%x interface :%s direction :%s user:%s program:%s action:%s \n",
		update_rule->can_rule.tuple.msg_id,
		update_rule->can_rule.tuple.interface,
		get_dir_desc(update_rule->can_rule.tuple.direction),
		update_rule->can_rule.tuple.program, update_rule->can_rule.tuple.user,
		update_rule->can_rule.action_name);
	printf(COLOR_RESET);
}

static void notify_updated_ip_rule(SR_U32 rule_id, rule_info_t *update_rule)
{
	char src_addr[IPV4_STR_MAX_LEN], src_netmask[IPV4_STR_MAX_LEN], dst_addr[IPV4_STR_MAX_LEN], dst_netmask[IPV4_STR_MAX_LEN];

	printf(COLOR_GREEN);
	inet_ntop(AF_INET, &update_rule->ip_rule.tuple.srcaddr, src_addr, IPV4_STR_MAX_LEN);
	inet_ntop(AF_INET, &update_rule->ip_rule.tuple.srcnetmask, src_netmask, IPV4_STR_MAX_LEN);
	inet_ntop(AF_INET, &update_rule->ip_rule.tuple.dstaddr, dst_addr, IPV4_STR_MAX_LEN);
	inet_ntop(AF_INET, &update_rule->ip_rule.tuple.dstnetmask, dst_netmask, IPV4_STR_MAX_LEN);
	printf("ip rule updated: \n");
	printf("  rule:%d tuple:%d \n", rule_id, update_rule->tuple_id);
        printf("  src_addr:%s/%s dst_addr:%s/%s proto:%d src_port:%d dst_port:%d user:%s program:%s action:%s\n", 
		src_addr, src_netmask, dst_addr, dst_netmask, update_rule->ip_rule.tuple.proto,
		update_rule->ip_rule.tuple.srcport, update_rule->ip_rule.tuple.dstport,
		update_rule->ip_rule.tuple.user, update_rule->ip_rule.tuple.program, update_rule->ip_rule.action_name);
	printf(COLOR_RESET);
}
		
static void notify_updated_file_rule(SR_U32 rule_id, rule_info_t *update_rule)
{
	printf(COLOR_GREEN);
	printf("file rule updated: \n");
	printf("  rule:%d tuple:%d \n", rule_id, update_rule->tuple_id);
	printf("  file:%s perm:%s user:%s program:%s action:%s \n",
		update_rule->file_rule.tuple.filename, prem_db_to_cli(update_rule->file_rule.tuple.permission),
		update_rule->file_rule.tuple.user, update_rule->file_rule.tuple.program, update_rule->file_rule.action_name);
	printf(COLOR_RESET);
}

static SR_32 get_control_cmd(char *ptr, char *cmd)
{
	if (!strcmp(ptr, "wl")) {
		ptr = strtok(NULL, " ");
		if (!ptr)
			return SR_ERROR;
		if (!strcmp(ptr, "learn")) {
			strcpy(cmd, "wl_learn");
			return SR_SUCCESS;
		}
		if (!strcmp(ptr, "apply")) {
			strcpy(cmd, "wl_apply");
			return SR_SUCCESS;
		}
		if (!strcmp(ptr, "apply")) {
			strcpy(cmd, "wl_apply");
			return SR_SUCCESS;
		}
		if (!strcmp(ptr, "print")) {
			strcpy(cmd, "wl_print");
			return SR_SUCCESS;
		}
		if (!strcmp(ptr, "reset")) {
			strcpy(cmd, "wl_reset");
			return SR_SUCCESS;
		}
	}
	if (!strcmp(ptr, "sp")) {
		ptr = strtok(NULL, " ");
		if (!ptr)
			return SR_ERROR;
		if (!strcmp(ptr, "learn")) {
			strcpy(cmd, "sp_learn");
			return SR_SUCCESS;
		}
		if (!strcmp(ptr, "apply")) {
			strcpy(cmd, "sp_apply");
			return SR_SUCCESS;
		}
		if (!strcmp(ptr, "off")) {
			strcpy(cmd, "sp_off");
			return SR_SUCCESS;
		}
	}

	if (!strcmp(ptr, "sr_ver")) {
		strcpy(cmd, "sr_ver");
		return SR_SUCCESS;
	}

        return SR_ERROR;
}

static void cmd_insert(char *arr[], char *str)
{
	SR_U32 i;

	/// Always insert at first
	if (arr[NUM_OF_CMD_ENTRIES - 1])
		free(arr[NUM_OF_CMD_ENTRIES - 1]);
	for (i = NUM_OF_CMD_ENTRIES - 1; i > 0; i--) {
		arr[i] = arr[i - 1];
	}
	arr[0] = strdup(str);
}

static char *cmd_get_first(char *arr[])
{
	cmd_curr = 0;
	return arr[0];
}

static char *cmd_get_next(char *arr[])
{
	if (cmd_curr == NUM_OF_CMD_ENTRIES || !arr[cmd_curr + 1])
		return NULL;
	cmd_curr++;
	return arr[cmd_curr];
}

static char *cmd_get_prev(char *arr[])
{
	if (cmd_curr == 0 || !arr[cmd_curr - 1])
		return NULL;
	cmd_curr--;
	return arr[cmd_curr];
}

static void chop_nl(char *str)
{
	SR_32 len = strlen(str);

	if (len > 0 && str[len - 1] == '\n')
		str[len - 1] = '\0';
}

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

static SR_32 handle_file_data(rule_info_t *new_rule, SR_U32 rule_num, SR_U32 tuple_id)
{
	char *ptr;

	new_rule->rule_type = RULE_TYPE_FILE;
	new_rule->file_rule.rulenum= rule_num;
	new_rule->file_rule.tuple.id = tuple_id;
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.action_name, ptr, ACTION_STR_SIZE);

	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.tuple.filename, ptr, FILE_NAME_SIZE);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.tuple.permission, ptr, 4);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.tuple.user, ptr, USER_NAME_SIZE);
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->file_rule.tuple.program, ptr, PROG_NAME_SIZE);
#if DEBUG
	printf("file:  tuple:%d action:%s: file:%s perm:%s user:%s prog:%s \n", new_rule->file_rule.tuple.id, new_rule->file_rule.action_name,
		new_rule->file_rule.tuple.filename, new_rule->file_rule.tuple.permission, new_rule->file_rule.tuple.user, new_rule->file_rule.tuple.program);
#endif

	return SR_SUCCESS;
}

static SR_32 handle_can_data(rule_info_t *new_rule, SR_U32 rule_num, SR_U32 tuple_id)
{
	char *ptr;

	new_rule->rule_type = RULE_TYPE_CAN;
	new_rule->can_rule.rulenum= rule_num;
	new_rule->can_rule.tuple.id = tuple_id;
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->can_rule.action_name, ptr, ACTION_STR_SIZE);

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

static SR_32 handle_ip_data(rule_info_t *new_rule, SR_U32 rule_num, SR_U32 tuple_id)
{
	char *ptr;

	new_rule->rule_type = RULE_TYPE_IP;
	new_rule->ip_rule.rulenum= rule_num;
	new_rule->ip_rule.tuple.id = tuple_id;
	GET_NEXT_TOKEN(ptr, ",");
	strncpy(new_rule->ip_rule.action_name, ptr, ACTION_STR_SIZE);
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

static void insert_rule_sorted(rule_info_t **table, rule_info_t *new_rule, SR_U32 tuple_id)
{
	rule_info_t **iter;

	for (iter = table; *iter && (*iter)->tuple_id < tuple_id; iter = &((*iter)->next));
	new_rule->next = *iter;
	*iter = new_rule;
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
		printf("rule for deletion was not found.\n");	
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
		if ((rc = handle_file_data(new_rule, rule_id, tuple_id)) != SR_SUCCESS) {
			printf("\nerror parsing file rule id:%d tuple:%d \n", rule_id, tuple_id);
			free(new_rule);
			goto out;
		}
		insert_rule_sorted(is_wl ? &file_wl[rule_id] : &file_rules[rule_id], new_rule, tuple_id);
		goto out;
	} 
	if (!memcmp(buf, "ip", strlen("ip"))) {
		is_wl = !memcmp(buf, "ip_wl", strlen("ip_wl"));
		if ((rc = handle_ip_data(new_rule, rule_id, tuple_id)) != SR_SUCCESS) {
			printf("\nerror parsing ip rule id:%d tuple:%d \n", rule_id, tuple_id);
			free(new_rule);
			goto out;
		}
		insert_rule_sorted(is_wl ? &ip_wl[rule_id] : &ip_rules[rule_id], new_rule, tuple_id);
		goto out;
	}
	if (!memcmp(buf, "can", strlen("can"))) {
		is_wl = !memcmp(buf, "can_wl", strlen("can_wl"));
		if ((rc = handle_can_data(new_rule, rule_id, tuple_id)) != SR_SUCCESS) {
			printf("\nerror parsing can rule id:%d tuple:%d \n", rule_id, tuple_id);
			free(new_rule);
			goto out;
		}
		insert_rule_sorted(is_wl ? &can_wl[rule_id] : &can_rules[rule_id], new_rule, tuple_id);
		goto out;
	}

out:
	if (help_str)
		free(help_str);

	return rc;
}

static SR_32 handle_load(void)
{
	SR_32 fd, rc, ind, len, st = SR_SUCCESS;
	char cmd[100], buf[2000], cval;

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
	buf[0] = 0;
	ind = 0;
	for (;;) { 
		len = read(fd, &cval, 1);
		if (!len) {
			printf("failed to read from socket");
			st = SR_ERROR;
			goto out;
		}
		switch (cval) {
			case SR_CLI_END_OF_TRANSACTION: /* Finish load */
				goto out;
			case SR_CLI_END_OF_ENTITY: /* Finish entity */
				buf[ind] = 0;
				handle_load_data(buf);
				buf[0] = 0;
				ind = 0;
				break;
			default:
				buf[ind++] = cval;
				break;
		}
	}

out:
	sleep(1);
        close(fd);

	return st;
}

static void print_engine_usage(void) {
	printf("\nengine [state|update [on|off]]\n");
}

static void print_show_usage(void) 
{
	printf("load 	- load information from database \n");
	printf("show 	- show current information \n");
	printf("update 	- update current information \n");
	printf("del 	- delete current information \n");
	printf("commit 	- commit current information to database and running configuration \n");
	printf("control	- control vsentry \n");
	printf("engine	- control engine state\n");
	printf ("\n");
	printf("show [action | rule | wl] [can | ipv4 | file] [rule=x] [tuple=y] \n");
	printf("update [action | rule | wl] [action_obj | can | ipv4 | file] [rule=x] [tuple=y] \n");
	printf("del [action | rule | wl] [action_obj | can | ipv4 | file] [rule=x] [tuple=y] \n");
	printf("	[action | rule | wl] - action table, user defied table or white list table \n");
	printf("	[can | ipv4 | file] - specifies the desired table\n");
	printf("	[rule=x] - if exists, shows all tuples on the specific rule\n");
	printf("	[tuple=y] - if exists, shows specific tuple\n");
	printf ("\n");
	printf("control [whitelist | system-policer | sr_ver]  [learn | apply | print | reset] \n");
	printf("	[whitelist | system-policer] - specifies specific module \n");
	printf("	[learn | apply | print | reset] - specifies specific action to preform\n");
	printf ("\n");
	printf("engine [state | update] [on | off] \n");
	printf("	[state | update] - state to show, update to change \n");
	printf("	[on | off] - applicable when using state \n");
	printf("\n");
	printf("show version - show running version \n");
	printf("\n");
}

static void print_update_rule_usage(SR_BOOL is_type)
{
	if (is_type)
		printf("[can | ipv4 | file] - specifies the desired table\n");
	printf("rule=x, tuple=y\n");
}

static void print_update_usage(void)
{
	printf("update | delete action | rule | wl action_obj | can | ip | file rule=x tuple=y\n");
	printf("  update tables\n");
	printf("action | rule | wl - action table, user defined table or white list table \n");
	print_update_rule_usage(SR_TRUE);
}

static void print_usage(void)
{
	print_show_usage();
	print_update_usage();
	print_engine_usage();
}

static void print_actions(void)
{
	SR_U32 i;

	printf("\nactions \n");
	printf("%-10s %-6s %-6s\n", ACTION_OBJ, ACTION, LOG);
	printf("----------------------------------------\n");
	for (i = 0 ;i < num_of_actions; i++) { 
		printf("%-10s %-6s %-6s \n", actions[i].action_name, get_action_string(actions[i].action), 
				strcmp(get_action_log_facility_string(actions[i].log_facility), "none") != 0 ? "1" : "0");
	}
}

static void print_file_rules(SR_BOOL is_wl, rule_info_t *table[], SR_32 rule_id, SR_32 tuple_id)
{
	SR_U32 i;
	rule_info_t *iter;

	printf("\n%sfile rules:\n", is_wl ? "wl " : "");
	printf("%-6s %-6s %-88s %-4s %-24s %-10s %s\n",
		RULE, TUPLE, FILENAME, PERM, PROGRAM, USER, ACTION); 
	printf("----------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->file_rule.tuple.id)) {
				printf("%-6d %-6d %-88.88s %-4s %-24.24s %-10.10s %-10.10s\n", 
					i, iter->file_rule.tuple.id,  iter->file_rule.tuple.filename, prem_db_to_cli(iter->file_rule.tuple.permission),
					iter->file_rule.tuple.program, iter->file_rule.tuple.user, iter->file_rule.action_name); 
			}
		}
	}
}

static void print_ip_rules(SR_BOOL is_wl, rule_info_t *table[], SR_32 rule_id, SR_32 tuple_id)
{
	SR_U32 i;
	rule_info_t *iter;
	char src_addr[IPV4_STR_MAX_LEN], dst_addr[IPV4_STR_MAX_LEN];
        char src_netmask[IPV4_STR_MAX_LEN], dst_netmask[IPV4_STR_MAX_LEN];

	printf("\n%sip rules:\n", is_wl ? "wl " : "");
	printf("%-6s %-6s %-16s %-16s %-16s %-16s %-5s %-8s %-8s %-24.24s %-10.10s %-10.10s\n",
		RULE, TUPLE, SRC_IP, SRC_NETMASK, DST_IP, DST_NETMASK, IP_PROTO, SRC_PORT, SDT_PORT, PROGRAM, USER, ACTION); 
	printf("---------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->ip_rule.tuple.id)) {
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.srcaddr.s_addr), src_addr, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.srcnetmask.s_addr), src_netmask, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.dstaddr.s_addr), dst_addr, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.dstnetmask.s_addr), dst_netmask, IPV4_STR_MAX_LEN);
				printf("%-6d %-6d %-16s %-16s %-16s %-16s %-5d %-8d %-8d %-24.24s %-10.10s %-10.10s\n",
					i, iter->ip_rule.tuple.id, src_addr, src_netmask, dst_addr, dst_netmask,
					iter->ip_rule.tuple.proto, iter->ip_rule.tuple.srcport, iter->ip_rule.tuple.dstport,
					iter->ip_rule.tuple.program, iter->ip_rule.tuple.user, iter->ip_rule.action_name); 
			}
		}
	}
}

static void print_can_rules(SR_BOOL is_wl, rule_info_t *table[], SR_32 rule_id, SR_32 tuple_id)
{
	SR_U32 i;
	rule_info_t *iter;
	char msg_id[32];

	printf("\n%scan rules:\n", is_wl ? "wl " : "");
	printf("%-6s %-6s %-8s %-10s %-10s %-24.24s %-10.10s %-10.10s\n",
		RULE, TUPLE, CAN_MSG, DIRECTION, INTERFACE, PROGRAM, USER, ACTION); 
	printf("--------------------------------------------------------------------------------------------------------------------------------\n");
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->can_rule.tuple.id)) {
				if (iter->can_rule.tuple.msg_id == MSGID_ANY)
					strcpy(msg_id, "any");
				else
					sprintf(msg_id, "%x", iter->can_rule.tuple.msg_id);
				printf("%-6d %-6d %-8s %-10.10s %-10.10s %-24.24s %-10.10s %-10.10s\n", 
					i, iter->can_rule.tuple.id, msg_id, get_dir_desc(iter->can_rule.tuple.direction),
					iter->can_rule.tuple.interface, iter->can_rule.tuple.program, iter->can_rule.tuple.user, iter->can_rule.action_name); 
			}
		}
	}
}

static void get_num_param(SR_32 *rule_id, SR_32 *tuple_id)
{
	char *ptr, *iter;

	ptr = strtok(NULL, " "); 
	if (!ptr)
		return;

	for (iter = ptr; *iter && *iter != '='; iter++);
	if (!iter) 
		return;
	iter++;
	
	if (!memcmp(ptr, "rule", strlen("rule")))
		*rule_id = atoi(iter);
	else if (!memcmp(ptr, "tuple", strlen("tuple")))
		*tuple_id = atoi(iter);
}

static SR_32 get_rule_type(SR_BOOL *is_can, SR_BOOL *is_file, SR_BOOL *is_ip, SR_BOOL *is_help, SR_BOOL def_val)
{
	char *ptr; 

	ptr = strtok(NULL, " "); 
	if (!ptr) {
		*is_can = *is_file = *is_ip = def_val;
		return SR_SUCCESS;
	}
	if (!strcmp(ptr, "file"))
		*is_file = SR_TRUE;
	else if (!strcmp(ptr, "can"))
		*is_can = SR_TRUE;
	else if (!strcmp(ptr, "ip"))
		*is_ip = SR_TRUE;
	else if (*ptr == '?') 
		*is_help = SR_TRUE;
	else {
		return SR_ERROR;
	}

	return SR_SUCCESS;
} 

static void handle_show(void)
{
	SR_BOOL is_wl = SR_FALSE, is_rule = SR_FALSE, is_action = SR_FALSE, is_can = SR_FALSE, is_file = SR_FALSE, is_ip = SR_FALSE, is_help = SR_FALSE;
	char *ptr;
	SR_32 rule_id = -1, tuple_id = -1;

	ptr = strtok(NULL, " "); 
	if (!ptr) {
		is_wl = is_rule = is_action = is_can = is_file = is_ip = SR_TRUE;
		goto print;
	}
	if (*ptr == '?') {
		print_show_usage();
		return;
	}
	if (!strcmp(ptr, "rule") || !strcmp(ptr, "wl")) {
		if (!strcmp(ptr, "rule"))
			is_rule = SR_TRUE;
		else
			is_wl = SR_TRUE;
		if (get_rule_type(&is_can, &is_file, &is_ip, &is_help, SR_TRUE) != SR_SUCCESS) {
			printf("error getting rule type\n");
			return;
		}
		get_num_param(&rule_id, &tuple_id);
		get_num_param(&rule_id, &tuple_id);
		goto print;
	} else if (!strcmp(ptr, "action")) {
		is_action = SR_TRUE;
		goto print;
	} else {
		printf("show rule | wl | action\n");
	}

print:
	if (is_action)
		print_actions();
	if (is_file) {
		if (is_rule)
			print_file_rules(SR_FALSE, file_rules, rule_id, tuple_id);
		if (is_wl)
			print_file_rules(SR_TRUE, file_wl, rule_id, tuple_id);
	}
	if (is_ip) {
		if (is_rule)
			print_ip_rules(SR_FALSE, ip_rules, rule_id, tuple_id);
		if (is_wl)
			print_ip_rules(SR_TRUE, ip_wl, rule_id, tuple_id);
	}
	if (is_can) {
		if (is_rule)
			print_can_rules(SR_FALSE, can_rules, rule_id, tuple_id);
		if (is_wl)
			print_can_rules(SR_TRUE, can_wl, rule_id, tuple_id);
	}
}

static SR_BOOL is_valid_msg_ig(char *str)
{
	if (!strcmp(str, "any"))
		return SR_TRUE;
	for (; *str; str++) {
		if (!isxdigit(*str))
			return SR_FALSE;
	}
	return SR_TRUE;
}

static SR_BOOL is_valid_interface(char *interface)
{
	if (if_nametoindex(interface))
		return SR_TRUE;
	return SR_FALSE;
}

static SR_BOOL is_valid_action(char *action_name)
{
	if (!get_action(action_name)) { 
		printf("invalid action: %s \n", action_name);
		return SR_FALSE;
	}

	return SR_TRUE;
}

static SR_BOOL is_valid_dir(char *dir)
{
	return get_dir_id(dir) != -1;
}

static SR_BOOL is_valid_ip_proto(char *ip_proto)
{
	return (!strcmp(ip_proto, "tcp") || !strcmp(ip_proto, "udp") || !strcmp(ip_proto, "any"));
}

static SR_BOOL is_valid_port(char *port)
{
	for (; *port; port++) {
		if (!isdigit(*port))
			return SR_FALSE;
	}

	return SR_TRUE;
}

static SR_BOOL is_perm_valid(char *perm)
{
	if (strlen(perm) > 3)
		return SR_FALSE;

	for(; *perm; perm++) {
		if (*perm != 'r' && *perm != 'w' && *perm != 'x')
			return SR_FALSE;
	}

	return SR_TRUE;
}

static char *get_string_user_input(SR_BOOL is_current, char *def_val, char *prompt, SR_BOOL (*is_valid_cb)(char *data), void (*help_cb)(void))
{
	char buf[512];
	static char input[512];

	sprintf(buf, "%s is %s", is_current ? "current" : "default", def_val ?: "none");
	while (1) { 
		printf(">%s: (%s):", prompt, buf);
		if (!fgets(input, sizeof(input), stdin)) {
			printf("error reading\n");
			continue;
		}
		chop_nl(input);
		if (*input) {
			if (*input == '?') {
				if (help_cb)
					help_cb();
				continue;
			}
			if (is_valid_cb && !is_valid_cb(input)) {
				error("invalid value", SR_FALSE);
				continue;
			}
			return input;
		}
		if (!def_val) {
			error("enter field value", SR_FALSE);
			continue;
		}
		return def_val;
	}

	return NULL;
}

static void msg_id_help(void)
{
	printf("hex digits, for any mid - \"any\", default: \"any\" \n");
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

static SR_BOOL is_valid_program(char *program)
{
	struct stat buf;

	if (*program == '*')
		return SR_TRUE;

	if (stat(program, &buf)) {
		printf("program does not exist\n");
		return SR_FALSE;
	}

        if (!(buf.st_mode & S_IXUSR)) {
		printf("program does reflect an executable\n");
		return SR_FALSE;
	}

	return SR_TRUE;

}

static SR_BOOL is_valid_user(char *user)
{
	if (*user == '*')
		return SR_TRUE;

	if (getpwnam(user))
		return SR_TRUE;

	return SR_FALSE;
}

static SR_BOOL is_valid_file(char *file)
{
	struct stat buf;

	if (stat(file, &buf)) {
		printf("file does not exist\n");
		return SR_FALSE;
	}

	return SR_TRUE;
}

static void file_perm_help(void)
{
	printf("r - read, w - write, x - executable\n");
}

static void ip_proto_help(void)
{
	printf("tcp, udp, any\n");
}

static SR_32 handle_update_can(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	rule_info_t *rule_info, update_rule, *new_rule;
	char *ptr, *msg_id_input, msg_id_def[32], *dir_input, dir_def[16];

	// Check if the rule exists
	rule_info = get_rule_sorted(is_wl ? can_wl[rule_id] : can_rules[rule_id], tuple_id);
	if (rule_info) {
		update_rule = *rule_info;
		printf("> updating an existing rule...\n");
		if (rule_info->can_rule.tuple.msg_id == MSGID_ANY)
			strcpy(msg_id_def, "any");
		else
			sprintf(msg_id_def, "%x", rule_info->can_rule.tuple.msg_id);
		strcpy(dir_def, get_dir_desc(rule_info->can_rule.tuple.direction));
	} else {
		printf("\n> adding a new rule...\n");
		strcpy(msg_id_def, "any");
		strcpy(dir_def, "both");
	}

	msg_id_input = get_string_user_input(rule_info != NULL, msg_id_def , "mid", is_valid_msg_ig, msg_id_help);
	if (!strcmp(msg_id_input, "any"))
		update_rule.can_rule.tuple.msg_id = MSGID_ANY;
	else
		update_rule.can_rule.tuple.msg_id = strtoul(msg_id_input, &ptr, 16);

	strncpy(update_rule.can_rule.tuple.interface, 
		get_string_user_input(rule_info != NULL, rule_info ? rule_info->can_rule.tuple.interface : NULL , "interface", is_valid_interface, can_interface_help), INTERFACE_SIZE);

	dir_input = get_string_user_input(rule_info != NULL, dir_def, "direction (in, out, both)", is_valid_dir, NULL);
	update_rule.can_rule.tuple.direction = get_dir_id(dir_input);

	strncpy(update_rule.can_rule.tuple.program, get_string_user_input(rule_info != NULL, rule_info ? rule_info->can_rule.tuple.program : "*" , "program", is_valid_program, NULL), PROG_NAME_SIZE);
	strncpy(update_rule.can_rule.tuple.user, get_string_user_input(rule_info != NULL, rule_info ? rule_info->can_rule.tuple.user : "*" , "user", is_valid_user, NULL), USER_NAME_SIZE);

	strncpy(update_rule.can_rule.action_name, get_string_user_input(rule_info != NULL, rule_info ? rule_info->can_rule.action_name : NULL , "action", is_valid_action, NULL), ACTION_STR_SIZE);

	update_rule.tuple_id = update_rule.can_rule.tuple.id = tuple_id;
	update_rule.can_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_CAN;

#ifdef CLI_DEBUG
	printf("tuple id :%d \n", update_rule.tuple_id);
	printf("mid :%x \n", update_rule.can_rule.tuple.msg_id);
	printf("interface :%s \n", update_rule.can_rule.tuple.interface);
	printf("direction :%s \n", get_dir_desc(update_rule.can_rule.tuple.direction));
	printf("program :%s \n", update_rule.can_rule.tuple.program);
	printf("user :%s \n", update_rule.can_rule.tuple.user);
	printf("action :%s \n", update_rule.can_rule.action_name);
#endif
	notify_updated_can_rule(rule_id, &update_rule);
	
	if (!rule_info) { 
		if (!(new_rule = malloc(sizeof(rule_info_t)))) {
			return SR_ERROR;
		}
		*new_rule = update_rule;
		insert_rule_sorted(is_wl ? &can_wl[rule_id] : &can_rules[rule_id], new_rule, tuple_id);
	} else {
		*rule_info = update_rule;
	}

	return SR_SUCCESS;
}

static SR_32 handle_update_ip(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	rule_info_t *rule_info, update_rule, *new_rule;
	char *param, src_ip_address_def[IPV4_STR_MAX_LEN], src_netmask_def[IPV4_STR_MAX_LEN];
	char dst_ip_address_def[IPV4_STR_MAX_LEN], dst_netmask_def[IPV4_STR_MAX_LEN], ip_proto_def[8], src_port_def[8], dst_port_def[8];

	// Check if the rule exists
	rule_info = get_rule_sorted(is_wl ? ip_wl[rule_id] : ip_rules[rule_id], tuple_id);
	if (rule_info) {
		update_rule = *rule_info;
		printf("> updating an existing rule...\n");
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.srcaddr.s_addr), src_ip_address_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.dstaddr.s_addr), dst_ip_address_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.srcnetmask.s_addr), src_netmask_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.dstnetmask.s_addr), dst_netmask_def, IPV4_STR_MAX_LEN);
		strcpy(ip_proto_def, get_ip_proto_name(rule_info->ip_rule.tuple.proto)); 
		sprintf(src_port_def, "%d", rule_info->ip_rule.tuple.srcport);
		sprintf(dst_port_def, "%d", rule_info->ip_rule.tuple.dstport);
	} else {
		printf("\n> adding a new rule...\n");
		strcpy(src_ip_address_def, "0.0.0.0");
		strcpy(dst_ip_address_def, "0.0.0.0");
		strcpy(dst_netmask_def, "255.255.255.255");
		strcpy(src_netmask_def, "255.255.255.255");
		strcpy(ip_proto_def, "tcp");
		strcpy(src_port_def, "0");
		strcpy(dst_port_def, "0");
	}

	param = get_string_user_input(rule_info != NULL, src_ip_address_def , "src addr", is_valid_ip, NULL);
	inet_aton(param, &update_rule.ip_rule.tuple.srcaddr);
	param = get_string_user_input(rule_info != NULL, src_netmask_def , "src netmask", is_valid_ip, NULL);
	inet_aton(param, &update_rule.ip_rule.tuple.srcnetmask);
	param = get_string_user_input(rule_info != NULL, dst_ip_address_def , "dst addr", is_valid_ip, NULL);
	inet_aton(param, &update_rule.ip_rule.tuple.dstaddr);
	param = get_string_user_input(rule_info != NULL, dst_netmask_def , "dst netmask", is_valid_ip, NULL);
	inet_aton(param, &update_rule.ip_rule.tuple.dstnetmask);
	param = get_string_user_input(rule_info != NULL, ip_proto_def , "ip proto", is_valid_ip_proto, ip_proto_help);
	update_rule.ip_rule.tuple.proto = get_ip_proto_code(param);
	param = get_string_user_input(rule_info != NULL, src_port_def , "src port", is_valid_port, NULL);
	update_rule.ip_rule.tuple.srcport = atoi(param);
	param = get_string_user_input(rule_info != NULL, dst_port_def , "dst port", is_valid_port, NULL);
	update_rule.ip_rule.tuple.dstport = atoi(param);

	strncpy(update_rule.ip_rule.tuple.program, get_string_user_input(rule_info != NULL, rule_info ? rule_info->ip_rule.tuple.program : "*" , "program", is_valid_program, NULL),
		 PROG_NAME_SIZE);
	strncpy(update_rule.ip_rule.tuple.user, get_string_user_input(rule_info != NULL, rule_info ? rule_info->ip_rule.tuple.user : "*" , "user", is_valid_user, NULL),
		USER_NAME_SIZE);
	strncpy(update_rule.ip_rule.action_name, get_string_user_input(rule_info != NULL, rule_info ? rule_info->ip_rule.action_name : NULL , "action", is_valid_action, NULL), ACTION_STR_SIZE);
	update_rule.tuple_id = update_rule.ip_rule.tuple.id = tuple_id;
	update_rule.ip_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_IP;

	notify_updated_ip_rule(rule_id, &update_rule);

	if (!rule_info) { 
		if (!(new_rule = malloc(sizeof(rule_info_t)))) {
			return SR_ERROR;
		}
		*new_rule = update_rule;
		insert_rule_sorted(is_wl ? &ip_wl[rule_id] : &ip_rules[rule_id], new_rule, tuple_id);
	} else {
		*rule_info = update_rule;
	}

	return SR_SUCCESS;
}

static SR_32 handle_update_file(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	rule_info_t *rule_info, update_rule, *new_rule;

	// Check if the rule exists
	rule_info = get_rule_sorted(is_wl ? file_wl[rule_id] : file_rules[rule_id], tuple_id);
	if (rule_info) {
		update_rule = *rule_info;
		printf("> updating an existing rule...\n");
	} else {
		printf("\n> adding a new rule...\n");
	}

	strncpy(update_rule.file_rule.tuple.filename,
		get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.filename : NULL , "file", is_valid_file, NULL), FILE_NAME_SIZE);
	strncpy(update_rule.file_rule.tuple.permission,
		perm_cli_to_db(get_string_user_input(rule_info != NULL, rule_info ? prem_db_to_cli(rule_info->file_rule.tuple.permission) : NULL , "perm", is_perm_valid,
			 file_perm_help)), 4);
	strncpy(update_rule.file_rule.tuple.program, get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.program : "*" , "program", is_valid_program, NULL), PROG_NAME_SIZE);
	strncpy(update_rule.file_rule.tuple.user, get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.user : "*" , "user", is_valid_user, NULL), USER_NAME_SIZE);
	strncpy(update_rule.file_rule.action_name, get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.action_name : NULL , "action", is_valid_action, NULL), ACTION_STR_SIZE);

	update_rule.tuple_id = update_rule.file_rule.tuple.id = tuple_id;
	update_rule.file_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_FILE;

	notify_updated_file_rule(rule_id, &update_rule);

	if (!rule_info) { 
		if (!(new_rule = malloc(sizeof(rule_info_t)))) {
			return SR_ERROR;
		}
		*new_rule = update_rule;
		insert_rule_sorted(is_wl ? &file_wl[rule_id] : &file_rules[rule_id], new_rule, tuple_id);
	} else {
		*rule_info = update_rule;
	}

	return SR_SUCCESS;
}

static SR_32 handle_delete(rule_type_t rule_type, rule_info_t **rule_info, SR_U32 rule_id, SR_U32 tuple_id)
{
	char rule_type_str[MAX_RULE_TYPE], msg[256]; 

	strcpy(rule_type_str, get_rule_string(rule_type));
	if (delete_rule(rule_info, tuple_id) != SR_SUCCESS) {
		sprintf(msg, "%s delete failed", rule_type_str);
		error(msg, SR_TRUE);
		return SR_ERROR;
	}
	sprintf(msg, "%s rule id:%d tuple id:%d was deleted", rule_type_str, rule_id, tuple_id);
	notify_info(msg);

	return SR_SUCCESS;
}

static SR_32 handle_delete_can(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	return handle_delete(RULE_TYPE_CAN, is_wl ? &can_wl[rule_id] : &can_rules[rule_id], rule_id, tuple_id);
}

static SR_32 handle_delete_ip(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	return handle_delete(RULE_TYPE_IP, is_wl ? &ip_wl[rule_id] : &ip_rules[rule_id], rule_id, tuple_id);
}

static SR_32 handle_delete_file(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	return handle_delete(RULE_TYPE_FILE, is_wl ? &file_wl[rule_id] : &file_rules[rule_id], rule_id, tuple_id);
}

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

static SR_BOOL is_action_exist_in_rule(rule_info_t *table[], char *action_name)
{
	rule_info_t *iter;
	SR_U32 i;
	char *rule_action;

	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			switch (iter->rule_type) {
				case RULE_TYPE_FILE:
					rule_action = iter->file_rule.action_name;
					break;
				case RULE_TYPE_IP:
					rule_action = iter->ip_rule.action_name;
					break;
				case RULE_TYPE_CAN:
					rule_action = iter->can_rule.action_name;
					break;
				default:
					printf("is_action_exists internal error\n");
					return SR_FALSE;
			}
			if (!strcmp(rule_action, action_name))
				return SR_TRUE;
		}
	}

	return SR_FALSE;
}

static SR_32 delete_action(char *action_name)
{
	SR_U32 i;
	char msg[128];

	for (i = 0; i < num_of_actions && strcmp(action_name, actions[i].action_name) != 0; i++);
	if (i == num_of_actions) {
		printf("action %s does not exist\n", action_name);
		return SR_NOT_FOUND;
	}

	/* check if the action exists in any of the rules */
	if (is_action_exist_in_rule(file_rules, action_name)) {
		sprintf(msg, "action %s exists in file rules", action_name);
		error(msg, SR_TRUE);
		return SR_ERROR;
	}
	if (is_action_exist_in_rule(can_rules, action_name)) {
		sprintf(msg, "action %s exists in can rules", action_name);
		error(msg, SR_TRUE);
		return SR_ERROR;
	}
	if (is_action_exist_in_rule(ip_rules, action_name)) {
		sprintf(msg, "action %s exists in ip rules", action_name);
		error(msg, SR_TRUE);
		return SR_ERROR;
	}

	for (; i < num_of_actions - 1; i++) 
		actions[i] = actions[i + 1];
	num_of_actions--;

	return SR_SUCCESS;
}

static SR_32 handle_update_action(SR_BOOL is_delete)
{
	char *action_name, *action_type, *log, *log_facility, msg[256];
	action_t *action;
	log_facility_e log_facility_code = LOG_NONE;
	action_e action_code;

	action_name = strtok(NULL, " ");
	if (!action_name) {
		error("action name is missing!!", SR_TRUE);
		printf("usage: update action action_name action_type (none | allow | drop) [log=syslog | file | none]\n");
		return SR_ERROR;
	}
	if (is_delete)
		return delete_action(action_name);
	action = get_action(action_name);
	if (!action) {
		// Check if a new action can be created
		if (num_of_actions == DB_MAX_NUM_OF_ACTIONS) {
                	printf("max number of action reached (%d)\n", num_of_actions);
                	return SR_ERROR;
		}
		action = &actions[num_of_actions++];
		memset(action, 0, sizeof(action_t));
		strncpy(action->action_name, action_name, ACTION_STR_SIZE);
	}

	action_type = strtok(NULL, " ");
	if (!action_type || (action_code = get_action_code(action_type)) == ACTION_INVALID) {
		error("invalid action type" ,SR_TRUE);
		printf("usage: update action action_name action_type (none | allow | drop) log\n");
		return SR_ERROR;
	}

	log = strtok(NULL, " ");
	if (log) {
		if (memcmp(log, "log=", strlen("log="))) {
			error("invalid action log", SR_TRUE);
			printf("usage: update action action_name action_type (none | allow | drop) [log=syslog | file | none]\n");
			return SR_ERROR;
		}
		log_facility = log + strlen("log=");
		if ((log_facility_code = get_action_log_facility_code(log_facility)) == LOG_INVALID) {
			error("invalid log facility", SR_TRUE);
			printf("usage: update action action_name action_type (none | allow | drop) [log=syslog | file | none]\n");
			return SR_ERROR;
		}
	}

#ifdef CLI_DEBUG
	printf("update action:%s: action type:%s: action code:%d  log:%s log facility code:%d \n",
		action_name, action_type, action_code, log_facility, log_facility_code);
#endif
	sprintf(msg, "action %s was updated", action_name);
	notify_info(msg);
	action->action = action_code;
	action->log_facility = log_facility_code;

	return SR_SUCCESS;
}

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

static void commit_file_buf_cb(rule_info_t *iter, SR_BOOL is_wl, char *buf)
{
	sprintf(buf, "file%s,%d,%d,%s,%s,%s,%s,%s%c",
		is_wl ? "_wl" : "", iter->file_rule.rulenum, iter->file_rule.tuple.id,
		iter->file_rule.action_name, iter->file_rule.tuple.filename,
		iter->file_rule.tuple.permission, iter->file_rule.tuple.user,
		iter->file_rule.tuple.program, SR_CLI_END_OF_ENTITY);
}

static void commit_ip_buf_cb(rule_info_t *iter, SR_BOOL is_wl, char *buf)
{
	char src_addr[IPV4_STR_MAX_LEN], dst_addr[IPV4_STR_MAX_LEN];
	char src_netmask[IPV4_STR_MAX_LEN], dst_netmask[IPV4_STR_MAX_LEN];

	strncpy(src_addr, get_str_ip_address(iter->ip_rule.tuple.srcaddr.s_addr), IPV4_STR_MAX_LEN);
	strncpy(src_netmask, get_str_ip_address(iter->ip_rule.tuple.srcnetmask.s_addr), IPV4_STR_MAX_LEN);
	strncpy(dst_addr, get_str_ip_address(iter->ip_rule.tuple.dstaddr.s_addr), IPV4_STR_MAX_LEN);
	strncpy(dst_netmask, get_str_ip_address(iter->ip_rule.tuple.dstnetmask.s_addr), IPV4_STR_MAX_LEN);
	sprintf(buf, "ip%s,%d,%d,%s,%s,%s,%s,%s,%d,%d,%d,%s,%s%c",
						is_wl ? "_wl" : "", iter->ip_rule.rulenum, iter->ip_rule.tuple.id, iter->ip_rule.action_name,
						src_addr, src_netmask, dst_addr, dst_netmask, iter->ip_rule.tuple.proto,
						iter->ip_rule.tuple.srcport, iter->ip_rule.tuple.dstport, iter->ip_rule.tuple.user, iter->ip_rule.tuple.program,
						SR_CLI_END_OF_ENTITY);
}

static void commit_can_buf_cb(rule_info_t *iter, SR_BOOL is_wl, char *buf)
{
	sprintf(buf, "can%s,%d,%d,%s,%d,%d,%s,%s,%s%c",
		is_wl ? "_wl" : "", iter->can_rule.rulenum, iter->can_rule.tuple.id, iter->can_rule.action_name,
		iter->can_rule.tuple.msg_id, iter->can_rule.tuple.direction, iter->can_rule.tuple.interface,
		iter->can_rule.tuple.user, iter->can_rule.tuple.program, SR_CLI_END_OF_ENTITY);
}

static void rule_type_commit(SR_BOOL is_wl, rule_info_t *table[], SR_32 fd, void (*buf_cb)(rule_info_t *iter, SR_BOOL is_wl, char *buf))
{
	rule_info_t *iter;
	SR_U32 i, len;
	char buf[MAX_BUF_SIZE];

	if (!buf_cb) {
		printf("cannot create buffer !!!\n");
		return;
	}

	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			buf_cb(iter, is_wl, buf);
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

static SR_32 handle_commit(void)
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

static void handle_update(SR_BOOL is_delete)
{
	SR_BOOL is_wl = SR_FALSE, is_can = SR_FALSE, is_file = SR_FALSE, is_ip = SR_FALSE, is_help = SR_FALSE;
	SR_32 rule_id = -1, tuple_id = -1;
	char *ptr;

	ptr = strtok(NULL, " "); 
	if (!ptr) {
		printf("\n");
		print_update_usage();
		return;
	}
	if (*ptr == '?') {
		print_update_usage();
		return;
	}

	if (!strcmp(ptr, "rule") || !strcmp(ptr, "wl")) {
		if (!strcmp(ptr, "wl"))
			is_wl = SR_TRUE;
		if (get_rule_type(&is_can, &is_file, &is_ip, &is_help, SR_FALSE) != SR_SUCCESS) {
			error("error getting rule type", SR_TRUE);
			return;
		}
		if (is_help) {
			printf("\n");
			print_update_rule_usage(SR_TRUE);
			return;
		}
		if (!is_can && !is_ip && !is_file) {
			printf("rule type is missing\n");
			print_update_rule_usage(SR_TRUE);
			return;
		}
		get_num_param(&rule_id, &tuple_id);
		get_num_param(&rule_id, &tuple_id);
		if (rule_id == -1 || tuple_id == -1) {
			error("rule id or tuple id are missing", SR_TRUE);
			print_update_rule_usage(SR_FALSE);
			return;
		}
		if (is_can) {
			if (!is_delete)
				handle_update_can(is_wl, rule_id, tuple_id);
			else
				handle_delete_can(is_wl, rule_id, tuple_id);
		}
		if (is_ip) {
			if (!is_delete)
				handle_update_ip(is_wl, rule_id, tuple_id);
			else
				handle_delete_ip(is_wl, rule_id, tuple_id);
		}
		if (is_file) {
			if (!is_delete)
				handle_update_file(is_wl, rule_id, tuple_id);
			else
				handle_delete_file(is_wl, rule_id, tuple_id);
		}
		is_dirty = SR_TRUE;

	} else if (!strcmp(ptr, "action")) {
		handle_update_action(is_delete);
		is_dirty = SR_TRUE;
	} else {
		printf("invalid agruments\n");
		print_update_usage();
	}
}

static void print_control_usage(void)
{
	printf("\ncontrol [wl | sp | sr_ver]  [learn | apply | print | reset] \n");
}

static void cleanup_rule_table(rule_info_t *table[])
{
	SR_U32 i;
	rule_info_t **iter, *help;

	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = &table[i]; *iter;) {
			help = *iter;
			*iter = (*iter)->next;
			free(help);
		}
	}
}

void db_cleanup(void)
{
	cleanup_rule_table(file_rules);
	cleanup_rule_table(can_rules);
	cleanup_rule_table(ip_rules);
	cleanup_rule_table(file_wl);
	cleanup_rule_table(can_wl);
	cleanup_rule_table(ip_wl);
	num_of_actions = 0;
}

static void handle_engine(void)
{
	char *ptr;

	ptr = strtok(NULL, " "); 
	if (!ptr) { 
		print_engine_usage();
		return;
	}

	if (!strcmp(ptr, "state")) {
		printf("\n state:%s\n", engine_state ? "ON" : "OFF");
		return;
	}
	if (strcmp(ptr, "update") != 0) {
		print_engine_usage();
		return;
	}

	ptr = strtok(NULL, " "); 
	if (!ptr) { 
		print_engine_usage();
		return;
	}
	if (!strcmp(ptr, "on"))
		engine_state = SR_TRUE;
	else if (!strcmp(ptr, "off"))
		engine_state = SR_FALSE;
	else {
		print_engine_usage();
		return;
	}
	notify_info("Engine state changed.");
}

static void handle_control(void)
{
	SR_32 fd, rc;
	char *ptr, cmd[128], buf[512];

	ptr = strtok(NULL, " "); 
	if (!ptr) {
		printf("\n");
		print_control_usage();
		return; 
	}
	if (*ptr == '?') {
		print_control_usage();
		return;
	}
	
	if (get_control_cmd(ptr, cmd) != SR_SUCCESS) {
		error("invalid control command", SR_TRUE);
		print_control_usage();
		return;
	}
	
	if ((fd = engine_connect()) < 0) {
		error("failed engine connect", SR_TRUE);
		return;
	}

	rc = write(fd, cmd , strlen(cmd));
	if (rc < 0) {
		error("write error", SR_TRUE);
		return;
	}
	if (rc < strlen(cmd)) {
		error("partial write", SR_TRUE);
		return;
	}
	
	if (!strcmp(cmd, "sr_ver")) {
		usleep(30000);
		rc = read(fd, buf, 512);
		if (rc < 0) {
			perror("read error");
			return;
		}
		printf("\n%s\n", buf);
       }
	printf("\n");

	close(fd);
}

static void parse_command(char *cmd)
{
	char *ptr;
	char buf[128];

	ptr = strtok(cmd, " ");
	if (!ptr)
		return;
	if (!strcmp(ptr, "help")) {
		print_usage();
		return;
	}
	if (!strcmp(ptr, "quit")) {
		if (is_dirty) {
			printf("\n>there are uncommited changes. are you sure? [Y|n]\n");
			ptr = fgets(buf, 128, stdin);
			if (ptr && *buf == 'n')
				return;
		}
		is_run = SR_FALSE;
		return;
	}
	if (!strcmp(ptr, "show")) {
		return handle_show();
	}
	if (!strcmp(ptr, "update")) {
		return handle_update(SR_FALSE);
	}
	if (!strcmp(ptr, "delete")) {
		return handle_update(SR_TRUE);
	}
	if (!strcmp(ptr, "load")) {
		db_cleanup();
		if (handle_load() != SR_SUCCESS) {
			printf("error handling load\n");
		}
		notify_info("load finished.");
		return;
	}
	if (!strcmp(ptr, "commit")) {
		printf("\ncommitting...\n");
		if (handle_commit() != SR_SUCCESS) {
			printf("commit failed !!!\n");
		}
		return;
	}
	if (!strcmp(ptr, "control")) {
		return handle_control();
	}

	if (!strcmp(ptr, "engine")) {
		return handle_engine();
	}
	error("invalid argument", SR_TRUE);

	print_usage();
}

static void term_reset(int count)
{
	struct termios t;

	tcgetattr(STDIN_FILENO, &t);
	t.c_lflag |= ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &t);

	printf("\033[%dD", count);
	if (system ("/bin/stty cooked")) { 
		printf("error reseting term\n");
		return;
	}
}

static void get_cmd(char *buf, SR_U32 size, char *prompt)
{
	char c;
	char *last_cmd;
	SR_32 ind = 0, count = 0, pos, min_pos;
	struct termios t;
	SR_BOOL is_up = SR_FALSE;

	if (system("/bin/stty raw")) {
		printf("error seting the term\n");
		return;
	}
	tcgetattr(STDIN_FILENO, &t);
	t.c_lflag &= ~ECHO;
	tcsetattr(STDIN_FILENO, TCSANOW, &t);

	memset(buf, 0, size);
	pos = min_pos = strlen(prompt);

	while (1) {
		c = getchar();
		switch (c) {
			case '\033': // Escape
				c = getchar();
				switch (c) { 
					case '[':
						c = getchar();
						switch (c) { 
							case 'A': // up
								last_cmd = is_up ? cmd_get_next(cmds) : cmd_get_first(cmds);
								if (!last_cmd)
									break;
								if (strlen(buf))
									printf("\033[%dD", (int)strlen(buf));
								printf(CLEAR_RIGHT);
								strcpy(buf, last_cmd);
								ind = strlen(buf);
								is_up = SR_TRUE;
								printf("%s", buf);
								pos = strlen(buf) + strlen(prompt);
								break;
							case 'B': // down
								if (!is_up)
									break;
								last_cmd = cmd_get_prev(cmds);
								if (!last_cmd)
									break;
								if (strlen(buf))
									printf("\033[%dD", (int)strlen(buf));
								printf(CLEAR_RIGHT);
								strcpy(buf, last_cmd);
								ind = strlen(buf);
								is_up = SR_TRUE;
								printf("%s", buf);
								pos = strlen(buf) + strlen(prompt);
								break;
							case 'D': // left
								if (pos <= min_pos)
									break;
								pos--;
								printf("\033[1D"); // cursor left
								break;
							case 'C': //right
								printf("\033[1C"); // cursor right
								pos++;
								break;
							default:
								printf("XXXXX char:%c \n", c);
								break;
						}
						break;
					default:
						break;
				}
				break;
			case 0xd: // Enter
				if (!strlen(buf)) {
					printf("\n");
					printf("\033[%dD", (int)strlen(prompt));
				}
				goto out;
			case 0x3: // Cntrl C
				term_reset(count);
				exit(0);
			case 0x7f:  //  backword
				if (pos == min_pos)
					break;
				pos--;
				printf("\033[1D");
				printf(CLEAR_RIGHT);
				buf[--ind] = 0;
				break;
			default:
				if (isprint(c)) {
					count++;
					printf("%c", c);
					pos++;
					buf[ind++] = c;
				} else {
					printf("%x", c);
				}
				break;
		}
	}

out:
	term_reset(count);
}

SR_32 main(int argc, char **argv)
{
	char cmd[MAX_BUF_SIZE];

	if (handle_load() != 0) {
		printf("error handling load\n");
		return SR_ERROR;
	}

	while (is_run) {
		printf(CLI_PROMPT);
		get_cmd(cmd, MAX_BUF_SIZE, CLI_PROMPT);
		if (strlen(cmd))
			cmd_insert(cmds, cmd);
		parse_command(cmd);
	}
	printf("\033[%dD", (int)strlen(CLI_PROMPT));

	return SR_SUCCESS;
}
