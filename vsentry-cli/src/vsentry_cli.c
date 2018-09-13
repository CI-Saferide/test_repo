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

#define NUM_OF_RULES 4096
#define MAX_BUF_SIZE 10000

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
#define CAN_MSG "can_msg"
#define DIRECTION "direction"
#define INTERFACE "interface"
#define ACTION_OBJ "action_obj"
#define ACTION "action"
#define LOG "log"

static action_t *get_action(char *action_name);

SR_BOOL is_run = SR_TRUE;

typedef enum {
	RULE_TYPE_CAN,
	RULE_TYPE_FILE,
	RULE_TYPE_IP,
} rule_type_t;

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

static SR_U8 num_of_actions;

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
	ptr = strtok(NULL, ",");
	strncpy(new_rule->file_rule.action_name, ptr, ACTION_STR_SIZE);

	ptr = strtok(NULL, ",");
	strncpy(new_rule->file_rule.tuple.filename, ptr, FILE_NAME_SIZE);
	ptr = strtok(NULL, ",");
	strncpy(new_rule->file_rule.tuple.permission, ptr, 4);
	ptr = strtok(NULL, ",");
	strncpy(new_rule->file_rule.tuple.user, ptr, USER_NAME_SIZE);
	ptr = strtok(NULL, ",");
	strncpy(new_rule->file_rule.tuple.program, ptr, PROG_NAME_SIZE);
#if DEBUG
	printf("FILE:  tuple:%d action:%s: file:%s perm:%s user:%s prog:%s \n", new_rule->file_rule.tuple.id, new_rule->file_rule.action_name,
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
	ptr = strtok(NULL, ",");
	strncpy(new_rule->can_rule.action_name, ptr, ACTION_STR_SIZE);

	ptr = strtok(NULL, ",");
	new_rule->can_rule.tuple.msg_id = atoi(ptr);
	ptr = strtok(NULL, ",");
	new_rule->can_rule.tuple.direction = atoi(ptr);
	ptr = strtok(NULL, ",");
	strncpy(new_rule->can_rule.tuple.interface, ptr, INTERFACE_SIZE);
	ptr = strtok(NULL, ",");
	strncpy(new_rule->can_rule.tuple.user, ptr, USER_NAME_SIZE);
	ptr = strtok(NULL, ",");
	strncpy(new_rule->can_rule.tuple.program, ptr, PROG_NAME_SIZE);

	return SR_SUCCESS;
}

static SR_32 handle_ip_data(rule_info_t *new_rule, SR_U32 rule_num, SR_U32 tuple_id)
{
	char *ptr;

	new_rule->rule_type = RULE_TYPE_IP;
	new_rule->ip_rule.rulenum= rule_num;
	new_rule->ip_rule.tuple.id = tuple_id;
	ptr = strtok(NULL, ",");
	strncpy(new_rule->ip_rule.action_name, ptr, ACTION_STR_SIZE);
	ptr = strtok(NULL, ",");
	inet_aton(ptr, &(new_rule->ip_rule.tuple.srcaddr));
	ptr = strtok(NULL, ",");
	inet_aton(ptr, &(new_rule->ip_rule.tuple.srcnetmask));
	ptr = strtok(NULL, ",");
	inet_aton(ptr, &(new_rule->ip_rule.tuple.dstaddr));
	ptr = strtok(NULL, ",");
	inet_aton(ptr, &(new_rule->ip_rule.tuple.dstnetmask));
	ptr = strtok(NULL, ",");
	new_rule->ip_rule.tuple.proto = atoi(ptr);
	ptr = strtok(NULL, ",");
	new_rule->ip_rule.tuple.srcport = atoi(ptr);
	ptr = strtok(NULL, ",");
	new_rule->ip_rule.tuple.dstport = atoi(ptr);
	ptr = strtok(NULL, ",");
	strncpy(new_rule->ip_rule.tuple.user, ptr, USER_NAME_SIZE);
	ptr = strtok(NULL, ",");
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

static SR_32 handle_action_load(char *buf)
{
	char *ptr, *help_str = NULL;
	SR_32 rc = SR_SUCCESS;

	if (num_of_actions == DB_MAX_NUM_OF_ACTIONS) {
		printf("MAx number of action reached !!\n");
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
		insert_rule_sorted(is_wl ? &file_wl[rule_id] : &file_rules[rule_id], new_rule, tuple_id);
		rc = handle_file_data(new_rule, rule_id, tuple_id);
		goto out;
	} 
	if (!memcmp(buf, "ip", strlen("ip"))) {
		is_wl = !memcmp(buf, "ip_wl", strlen("ip_wl"));
		insert_rule_sorted(is_wl ? &ip_wl[rule_id] : &ip_rules[rule_id], new_rule, tuple_id);
		rc = handle_ip_data(new_rule, rule_id, tuple_id);
		goto out;
	}
	if (!memcmp(buf, "can", strlen("can"))) {
		is_wl = !memcmp(buf, "can_wl", strlen("can_wl"));
		insert_rule_sorted(is_wl ? &can_wl[rule_id] : &can_rules[rule_id], new_rule, tuple_id);
		rc = handle_can_data(new_rule, rule_id, tuple_id);
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
		printf("Failed engine connect\n");
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
			printf("Failed reading from socket");
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

static void print_show_usage(void) 
{
	printf("show [action|rule|wl] [can|ipv4|file] [rule=x] [tuple=y] \n");
	printf("show tables \n");
	printf("[action|rule|wl] - action table, user defied tabel or white list table\n");
	printf("[can|ipv4|file] - specifies the desired table\n");
	printf("[rule=x] - if exists, shows all tuples on the specific rule\n");
	printf("[tuple=y] - if exists, shows specific tuple\n");
	printf("\n");
}

static void print_update_usage(void)
{
	printf("update|delete [action|rule|wl] [action_obj|can|ipv4|file] [rule=x] [tuple=y]\n");
	printf("  update tables\n");
	printf("[action|rule|wl] - action table, user defied tabel or white list table \n");
	printf("[can|ipv4|file] - specifies the desired table\n");
	printf("[rule=x] - if exists, shows all tuples on the specific rule\n");
	printf("[tuple=y] - if exists, shows specific tuple\n");
	printf("\n");
}

static void print_usage(void)
{
	print_show_usage();
	print_update_usage();
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

	printf("\n%sfile rules:\n", is_wl ? "WL " : "");
	printf("%-6s %-6s %-70s %s %-20s %s %s\n",
		RULE, TUPLE, FILENAME, PERM, PROGRAM, USER, ACTION); 
	printf("--------------------------------------------------------------------------------------------------------------------------------\n");
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->file_rule.tuple.id)) {
				printf("%-6d %-6d %-70s %-4s %-20s %-4s %s\n", 
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

	printf("\n%sip rules:\n", is_wl ? "WL " : "");
	printf("%-6s %-6s %-16s %-16s %-16s %-16s %-5s %-8s %-8s %-24s %-4s %s\n",
		RULE, TUPLE, SRC_IP, SRC_NETMASK, DST_IP, DST_NETMASK, IP_PROTO, SRC_PORT, SDT_PORT, PROGRAM, USER, ACTION); 
	printf("---------------------------------------------------------------------------------------------------------------------------------------------------------\n");
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->ip_rule.tuple.id)) {
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.srcaddr.s_addr), src_addr, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.srcnetmask.s_addr), src_netmask, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.dstaddr.s_addr), dst_addr, IPV4_STR_MAX_LEN);
				inet_ntop(AF_INET, &(iter->ip_rule.tuple.dstnetmask.s_addr), dst_netmask, IPV4_STR_MAX_LEN);
				printf("%-6d %-6d %-16s %-16s %-16s %-16s %-5d %-8d %-8d %-24s %-4s %s\n",
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

	printf("\n%scan rules:\n", is_wl ? "WL " : "");
	printf("%-6s %-6s %-8s %-10s %-10s %-60s %-5s %s\n",
		RULE, TUPLE, CAN_MSG, DIRECTION, INTERFACE, PROGRAM, USER, ACTION); 
	printf("--------------------------------------------------------------------------------------------------------------------------------\n");
	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			if ((rule_id == -1 || rule_id == i) && (tuple_id == -1 || tuple_id == iter->can_rule.tuple.id)) {
				if (iter->can_rule.tuple.msg_id == MSGID_ANY)
					strcpy(msg_id, "any");
				else
					sprintf(msg_id, "%x", iter->can_rule.tuple.msg_id);
				printf("%-6d %-6d %-8s %-10s %-10s %-60s %-5s %s\n", 
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

static SR_32 get_rule_type(SR_BOOL *is_can, SR_BOOL *is_file, SR_BOOL *is_ip, SR_BOOL def_val)
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
	else {
		printf("Invalid show param.");
		return SR_ERROR;;
	}

	return SR_SUCCESS;
} 

static void handle_show(void)
{
	SR_BOOL is_wl = SR_FALSE, is_rule = SR_FALSE, is_action = SR_FALSE, is_can = SR_FALSE, is_file = SR_FALSE, is_ip = SR_FALSE;
	char *ptr;
	SR_32 rule_id = -1, tuple_id = -1;

	ptr = strtok(NULL, " "); 
	if (!ptr) {
		is_wl = is_rule = is_action = is_can = is_file = is_ip = SR_TRUE;
		goto print;
	}
	if (!strcmp(ptr, "rule") || !strcmp(ptr, "wl")) {
		if (!strcmp(ptr, "rule"))
			is_rule = SR_TRUE;
		else
			is_wl = SR_TRUE;
		if (get_rule_type(&is_can, &is_file, &is_ip, SR_TRUE) != SR_SUCCESS) {
			printf("Error getting rule type\n:");
			return;
		}
		get_num_param(&rule_id, &tuple_id);
		get_num_param(&rule_id, &tuple_id);
		goto print;
	} else if (!strcmp(ptr, "action")) {
		is_action = SR_TRUE;
		goto print;
	} else {
		printf("show rule|wl|action\n");
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
		printf("Invalid action: %s \n", action_name);
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

static char *get_string_user_input(SR_BOOL is_current, char *def_val, char *prompt, SR_BOOL (*is_valid_cb)(char *data))
{
	char buf[512];
	static char input[512];

	sprintf(buf, "%s is %s", is_current ? "current" : "default", def_val ?: "NONE");
	while (1) { 
		printf(">%s: (%s):", prompt, buf);
		if (!fgets(input, sizeof(input), stdin)) {
			printf("Error_reading\n");
			continue;
		}
		chop_nl(input);
		if (*input) {
			if (is_valid_cb && !is_valid_cb(input)) {
				printf("Invalid value\n");
				continue;
			}
			return input;
		}
		if (!def_val) {
			printf("Enter field value\n");
			continue;
		}
		return def_val;
	}

	return NULL;
}

static SR_32 handle_update_can(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	rule_info_t *rule_info, update_rule, *new_rule;
	char *ptr, *msg_id_input, msg_id_def[32], *dir_input, dir_def[16];

	// Check if the rule exists
	rule_info = get_rule_sorted(is_wl ? can_wl[rule_id] : can_rules[rule_id], tuple_id);
	if (rule_info) {
		update_rule = *rule_info;
		printf(">Updating an existing rule...\n");
		if (rule_info->can_rule.tuple.msg_id == MSGID_ANY)
			strcpy(msg_id_def, "any");
		else
			sprintf(msg_id_def, "%x", rule_info->can_rule.tuple.msg_id);
		strcpy(dir_def, get_dir_desc(rule_info->can_rule.tuple.direction));
	} else {
		printf(">Adding a new rule...\n");
		strcpy(msg_id_def, "any");
		strcpy(dir_def, "both");
	}

	msg_id_input = get_string_user_input(rule_info != NULL, msg_id_def , "msg_id", is_valid_msg_ig);
	if (!strcmp(msg_id_input, "any"))
		update_rule.can_rule.tuple.msg_id = MSGID_ANY;
	else
		update_rule.can_rule.tuple.msg_id = strtoul(msg_id_input, &ptr, 16);

	strncpy(update_rule.can_rule.tuple.interface, 
		get_string_user_input(rule_info != NULL, rule_info ? rule_info->can_rule.tuple.interface : NULL , "interface", is_valid_interface), INTERFACE_SIZE);

	dir_input = get_string_user_input(rule_info != NULL, dir_def, "direction (in, out, both)", is_valid_dir);
	update_rule.can_rule.tuple.direction = get_dir_id(dir_input);

	strncpy(update_rule.can_rule.tuple.program, get_string_user_input(rule_info != NULL, rule_info ? rule_info->can_rule.tuple.program : "*" , "program", NULL), PROG_NAME_SIZE);
	strncpy(update_rule.can_rule.tuple.user, get_string_user_input(rule_info != NULL, rule_info ? rule_info->can_rule.tuple.user : "*" , "user", NULL), USER_NAME_SIZE);

	strncpy(update_rule.can_rule.action_name, get_string_user_input(rule_info != NULL, rule_info ? rule_info->can_rule.action_name : NULL , "action", is_valid_action), ACTION_STR_SIZE);

	update_rule.tuple_id = update_rule.can_rule.tuple.id = tuple_id;
	update_rule.can_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_CAN;
#ifndef CLI_DEBUG
	printf("tuple id :%d \n", update_rule.tuple_id);
	printf("msg id :%x \n", update_rule.can_rule.tuple.msg_id);
	printf("interface :%s \n", update_rule.can_rule.tuple.interface);
	printf("direction :%s \n", get_dir_desc(update_rule.can_rule.tuple.direction));
	printf("program :%s \n", update_rule.can_rule.tuple.program);
	printf("user :%s \n", update_rule.can_rule.tuple.user);
	printf("action :%s \n", update_rule.can_rule.action_name);
#endif
	
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
		printf(">Updating an existing rule...\n");
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.srcaddr.s_addr), src_ip_address_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.dstaddr.s_addr), dst_ip_address_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.srcnetmask.s_addr), src_netmask_def, IPV4_STR_MAX_LEN);
		inet_ntop(AF_INET, &(rule_info->ip_rule.tuple.dstnetmask.s_addr), dst_netmask_def, IPV4_STR_MAX_LEN);
		strcpy(ip_proto_def, get_ip_proto_name(rule_info->ip_rule.tuple.proto)); 
		sprintf(src_port_def, "%d", rule_info->ip_rule.tuple.srcport);
		sprintf(dst_port_def, "%d", rule_info->ip_rule.tuple.dstport);
	} else {
		printf(">Adding a new rule...\n");
		strcpy(src_ip_address_def, "0.0.0.0");
		strcpy(dst_ip_address_def, "0.0.0.0");
		strcpy(dst_netmask_def, "255.255.255.255");
		strcpy(src_netmask_def, "255.255.255.255");
		strcpy(ip_proto_def, "tcp");
		strcpy(src_port_def, "0");
		strcpy(dst_port_def, "0");
	}

	param = get_string_user_input(rule_info != NULL, src_ip_address_def , "source addr", is_valid_ip);
	inet_aton(param, &update_rule.ip_rule.tuple.srcaddr);
	param = get_string_user_input(rule_info != NULL, src_netmask_def , "source netmask", is_valid_ip);
	inet_aton(param, &update_rule.ip_rule.tuple.srcnetmask);
	param = get_string_user_input(rule_info != NULL, dst_ip_address_def , "dest addr", is_valid_ip);
	inet_aton(param, &update_rule.ip_rule.tuple.dstaddr);
	param = get_string_user_input(rule_info != NULL, dst_netmask_def , "dest netmask", is_valid_ip);
	inet_aton(param, &update_rule.ip_rule.tuple.dstnetmask);
	param = get_string_user_input(rule_info != NULL, ip_proto_def , "ip proto", is_valid_ip_proto);
	update_rule.ip_rule.tuple.proto = get_ip_proto_code(param);
	param = get_string_user_input(rule_info != NULL, src_port_def , "src port", is_valid_port);
	update_rule.ip_rule.tuple.srcport = atoi(param);
	param = get_string_user_input(rule_info != NULL, dst_port_def , "dst port", is_valid_port);
	update_rule.ip_rule.tuple.dstport = atoi(param);

	strncpy(update_rule.ip_rule.tuple.program, get_string_user_input(rule_info != NULL, rule_info ? rule_info->ip_rule.tuple.program : "*" , "program", NULL), PROG_NAME_SIZE);
	strncpy(update_rule.ip_rule.tuple.user, get_string_user_input(rule_info != NULL, rule_info ? rule_info->ip_rule.tuple.user : "*" , "user", NULL), USER_NAME_SIZE);
	strncpy(update_rule.ip_rule.action_name, get_string_user_input(rule_info != NULL, rule_info ? rule_info->ip_rule.action_name : NULL , "action", is_valid_action), ACTION_STR_SIZE);
	update_rule.tuple_id = update_rule.ip_rule.tuple.id = tuple_id;
	update_rule.ip_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_IP;

#ifdef CLI_DEBUG
	printf("src addr:%-8x \n", update_rule.ip_rule.tuple.srcaddr);
	printf("src netmask:%-8x \n", update_rule.ip_rule.tuple.srcnetmask);
	printf("dst addr:%8x \n", update_rule.ip_rule.tuple.dstaddr);
	printf("dst netmask:%-8x \n", update_rule.ip_rule.tuple.dstnetmask);
	printf("ip proto:%d \n", update_rule.ip_rule.tuple.proto);
	printf("src port:%d \n", update_rule.ip_rule.tuple.srcport);
	printf("dst port:%d \n", update_rule.ip_rule.tuple.dstport);
	printf("user :%s \n", update_rule.ip_rule.tuple.user);
	printf("user :%s \n", update_rule.ip_rule.tuple.user);
	printf("program :%s \n", update_rule.ip_rule.tuple.program);
#endif

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
		printf("prems:%s: clip:%s:\n",  rule_info->file_rule.tuple.permission, prem_db_to_cli(rule_info->file_rule.tuple.permission));
		printf(">Updating an existing rule...\n");
	} else {
		printf(">Adding a new rule...\n");
	}

	strncpy(update_rule.file_rule.tuple.filename,
		get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.filename : NULL , "file", NULL), FILE_NAME_SIZE);
	strncpy(update_rule.file_rule.tuple.permission,
		perm_cli_to_db(get_string_user_input(rule_info != NULL, rule_info ? prem_db_to_cli(rule_info->file_rule.tuple.permission) : NULL , "premission", is_perm_valid)), 4);
	strncpy(update_rule.file_rule.tuple.program, get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.program : "*" , "program", NULL), PROG_NAME_SIZE);
	strncpy(update_rule.file_rule.tuple.user, get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.tuple.user : "*" , "user", NULL), USER_NAME_SIZE);
	strncpy(update_rule.file_rule.action_name, get_string_user_input(rule_info != NULL, rule_info ? rule_info->file_rule.action_name : NULL , "action", is_valid_action), ACTION_STR_SIZE);

#ifndef CLI_DEBUG
	printf("file :%s \n", update_rule.file_rule.tuple.filename);
	printf("permission :%s \n", update_rule.file_rule.tuple.permission);
	printf("user :%s \n", update_rule.file_rule.tuple.user);
	printf("program :%s \n", update_rule.file_rule.tuple.program);
#endif
	update_rule.tuple_id = update_rule.file_rule.tuple.id = tuple_id;
	update_rule.file_rule.rulenum = rule_id;
	update_rule.rule_type = RULE_TYPE_FILE;

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

static SR_32 handle_delete_can(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	return delete_rule(is_wl ? &can_wl[rule_id] : &can_rules[rule_id], tuple_id);
}

static SR_32 handle_delete_ip(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	return delete_rule(is_wl ? &ip_wl[rule_id] : &ip_rules[rule_id], tuple_id);
}

static SR_32 handle_delete_file(SR_BOOL is_wl, SR_U32 rule_id, SR_U32 tuple_id)
{
	return delete_rule(is_wl ? &file_wl[rule_id] : &file_rules[rule_id], tuple_id);
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

	for (i = 0; i < num_of_actions && strcmp(action_name, actions[i].action_name) != 0; i++);
	if (i == num_of_actions) {
		printf("Action %s does not exist\n", action_name);
		return SR_NOT_FOUND;
	}

	/* check if the action exists in any of the rules */
	if (is_action_exist_in_rule(file_rules, action_name)) {
		printf("Action %s exists in file rules\n", action_name);
		return SR_ERROR;
	}
	if (is_action_exist_in_rule(can_rules, action_name)) {
		printf("Action %s exists in can rules\n", action_name);
		return SR_ERROR;
	}
	if (is_action_exist_in_rule(ip_rules, action_name)) {
		printf("Action %s exists in ip rules\n", action_name);
		return SR_ERROR;
	}

	for (; i < num_of_actions - 1; i++) 
		actions[i] = actions[i + 1];
	num_of_actions--;

	return SR_SUCCESS;
}

static SR_32 handle_update_action(SR_BOOL is_delete)
{
	char *action_name, *action_type, *log, *log_facility;
	action_t *action;
	log_facility_e log_facility_code = LOG_NONE;
	action_e action_code;

	action_name = strtok(NULL, " ");
	if (!action_name) {
		printf("action name is missing!!\n");
		printf("usage: update action action_name action_type (none|allow|drop) [log=syslog|file|none]\n");
		return SR_ERROR;
	}
	if (is_delete)
		return delete_action(action_name);
	action = get_action(action_name);
	if (!action) {
		// Check if a new action can be created
		if (num_of_actions == DB_MAX_NUM_OF_ACTIONS) {
                	printf("MAx number of action reached !!\n");
                	return SR_ERROR;
		}
		action = &actions[num_of_actions++];
		memset(action, 0, sizeof(action_t));
		strncpy(action->action_name, action_name, ACTION_STR_SIZE);
	}

	action_type = strtok(NULL, " ");
	if (!action_type || (action_code = get_action_code(action_type)) == ACTION_INVALID) {
		printf("Invalid action type \n");
		printf("usage: update action action_name action_type (none|allow|drop) log\n");
		return SR_ERROR;
	}

	log = strtok(NULL, " ");
	if (log) {
		if (memcmp(log, "log=", strlen("log="))) {
			printf("Invalid action type \n");
			printf("usage: update action action_name action_type (none|allow|drop) [log=syslog|file|none]\n");
			return SR_ERROR;
		}
		log_facility = log + strlen("log=");
		if ((log_facility_code = get_action_log_facility_code(log_facility)) == LOG_INVALID) {
			printf("Invalid log facility\n");
			printf("usage: update action action_name action_type (none|allow|drop) [log=syslog|file|none]\n");
			return SR_ERROR;
		}
	}

#ifdef CLI_DEBUG
	printf("update action:%s: action type:%s: action code:%d  log:%s log facility code:%d \n",
		action_name, action_type, action_code, log_facility, log_facility_code);
#endif
	action->action = action_code;
	action->log_facility = log_facility_code;

	return SR_SUCCESS;
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
                        printf("Write to engine failed !!\n");
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
		printf("Cannot create buffer !!!\n");
		return;
	}

	for (i = 0; i < NUM_OF_RULES; i++) {
		for (iter = table[i]; iter; iter = iter->next) {
			buf_cb(iter, is_wl, buf);
			len = strlen(buf);
			if (write(fd, buf, len) < len) {
				printf("Write to engine failed !!\n");
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
		printf("Failed engine connect\n");
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
            printf("Failed reading from socket");
            st = SR_ERROR;
            goto out;
        }

	actions_commit(fd);
	rules_commit(fd);
	buf[0] = SR_CLI_END_OF_TRANSACTION;
	if (write(fd, buf, 1) < 1)
		printf("write of SR_CLI_END_OF_TRANSACTION failed!\n");
	sleep(1);
	len = read(fd, &cval, 1);
	if (!len) {
		printf("Failed reading from socket");
		st = SR_ERROR;
		goto out;
	}

out:
        close(fd);

	return st;
}

static void handle_update(SR_BOOL is_delete)
{
	SR_BOOL is_wl = SR_FALSE, is_can = SR_FALSE, is_file = SR_FALSE, is_ip = SR_FALSE;
	SR_32 rule_id = -1, tuple_id = -1;
	char *ptr;

	ptr = strtok(NULL, " "); 
	if (!ptr) {
		print_update_usage();
		return;
	}

	if (!strcmp(ptr, "rule") || !strcmp(ptr, "wl")) {
		if (!strcmp(ptr, "wl"))
			is_wl = SR_TRUE;
		if (get_rule_type(&is_can, &is_file, &is_ip, SR_FALSE) != SR_SUCCESS) {
			printf("Error getting rule type\n:");
			return;
		}
		if (!is_can && !is_ip && !is_file) {
			printf("Rule type is missing\n");
			print_update_usage();
			return;
		}
		get_num_param(&rule_id, &tuple_id);
		get_num_param(&rule_id, &tuple_id);
		if (rule_id == -1 || tuple_id == -1) {
			printf("Rule id or tuple id are missing\n");
			print_update_usage();
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

	} else if (!strcmp(ptr, "action")) {
		handle_update_action(is_delete);
	} else {
		printf("Invalid agruments\n");
		print_update_usage();
	}
}

static void parse_command(char *cmd)
{
	char *ptr;

	ptr = strtok(cmd, " ");
	if (!ptr)
		return;
	if (!strcmp(ptr, "help")) {
		print_usage();
		return;
	}
	if (!strcmp(ptr, "quit")) {
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
	if (!strcmp(ptr, "commit")) {
		if (handle_commit() != SR_SUCCESS) {
			printf("Commit failed !!!\n");
		}
		return;
	}
	printf("Invalid argument\n");
	print_usage();
}

SR_32 main(int argc, char **argv)
{
	char cmd[1000];

	if (handle_load() != 0) {
		printf("Error handling load\n");
		return SR_ERROR;
	}

	while (is_run) {
		printf("vsentry cli>");
		if (!fgets(cmd, sizeof(cmd), stdin))
			continue;
		chop_nl(cmd);
		parse_command(cmd);
	}

	return SR_SUCCESS;
}

