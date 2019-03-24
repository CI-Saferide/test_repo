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
#include <unistd.h>
#include "sr_cls_wl_common.h"

#define MAX_LIST_NAME 64
#define MAX_LIST_VALUES 256
#define GROUP_NAME_SIZE 64
#define IP_ADDR_SIZE 32
#define IP_NETMASK_SIZE 4
#define PROTO_SIZE 8
#define PORT_SIZE 16
#define MAX_GROUP 32

static redisContext *c;

typedef struct group_info {
	char group_name[GROUP_NAME_SIZE];
	SR_BOOL (*valid_cb)(char *val);
	list_type_e list_type;
} group_info_t;

static SR_BOOL is_valid_file(char *file);
static SR_BOOL is_valid_program(char *program);
static SR_BOOL is_valid_user(char *user);
static SR_BOOL is_valid_msg_id(char *str);
static SR_BOOL is_valid_interface(char *interface);
static SR_BOOL is_valid_ip_addr(char *ip_addr);
static SR_BOOL is_valid_port(char *port);
static SR_BOOL is_valid_ip_proto(char *ip_proto);

static group_info_t group_info[MAX_GROUP + 1] = {
	{.group_name = "file-group", .valid_cb = is_valid_file, .list_type = LIST_FILES},
	{.group_name = "program-group", .valid_cb = is_valid_program, .list_type = LIST_PROGRAMS},
	{.group_name = "user-group", .valid_cb = is_valid_user, .list_type = LIST_USERS},
	{.group_name = "mid-group", .valid_cb = is_valid_msg_id, .list_type = LIST_MIDS},
	{.group_name = "can-intf-group", .valid_cb = is_valid_interface, .list_type = LIST_CAN_INTF},
	{.group_name = "addr-group", .valid_cb = is_valid_ip_addr, .list_type = LIST_ADDRS},
	{.group_name = "port-group", .valid_cb = is_valid_port, .list_type = LIST_PORTS},
	{.group_name = "proto-group", .valid_cb = is_valid_ip_proto, .list_type = LIST_PROTOCOLS},
};

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

static void print_action_usage(void)
{
	printf("action update action action_name [action allow | drop] [log vasentry | syslog] [rate_limit_action allow | drop] [rate_limit_log vsentry | syslog] \n");
}

static void print_control_usage(void)
{
	printf("control wl | sp | net [learn | apply | print | reset]\n");
}

static void print_update_group_usage(void)
{
	printf("vsentry-cli update group type group-name item1 item2 \n");
}

static void print_update_usage(void)
{
	print_action_usage();
	print_update_group_usage();
}

static void print_show_usage(void)
{
	printf("vsnetry_cli show [rule | wl ] [section (can, ip, file) rule_number 99]  \n");
	printf("vsnetry_cli show action [action name] \n");
	printf("vsnetry_cli show group [group name] \n");
}

static void print_delete_group_usage(void)
{
	printf("usage: delete group ... \n");
}

static void print_delete_usage(void)
{
	printf("usage: delete ... \n");
}

static void print_usage(char *prog)
{
	printf("usgae: %s\n", prog);
}

static SR_BOOL is_valid_rule_id(char *type, char *section, char *rule_str)
{
	SR_U32 rule;
	char *p;

	for (p = rule_str; *p; p++) {
		if (!isdigit(*p))
			return SR_FALSE;
	}
	rule = atoi(rule_str);

	if (!strcmp(section, "can")) {
		if (!strcmp(type, "wl")) {
			return (rule >= SR_CAN_WL_START_RULE_NO && rule <= SR_CAN_WL_END_RULE_NO);
		}
		return (rule < SR_CAN_WL_START_RULE_NO);
	}
	if (!strcmp(section, "file")) {
		if (!strcmp(type, "wl")) {
			return (rule >= SR_FILE_WL_START_RULE_NO && rule <= SR_FILE_WL_END_RULE_NO);
		}
		return (rule < SR_FILE_WL_START_RULE_NO);
	}
	if (!strcmp(section, "ip")) {
		if (!strcmp(type, "wl")) {
			return (rule >= SR_IP_WL_START_RULE_NO && rule <= SR_IP_WL_END_RULE_NO);
		}
		return (rule < SR_IP_WL_START_RULE_NO);
	}

	return SR_TRUE;
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

static SR_BOOL is_valid_dir(char *dir)
{
	return (!strcmp(dir, "in") || !strcmp(dir, "out") || !strcmp(dir, "both"));
}

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

static SR_BOOL is_valid_interface(char *interface)
{
        if (if_nametoindex(interface))
                return SR_TRUE;
        if (is_special_interface(interface))
                return SR_TRUE;
        return SR_FALSE;
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

static SR_BOOL is_valid_msg_id(char *str)
{
        if (!strcmp(str, "any"))
                return SR_TRUE;
        for (; *str; str++) {
                if (!isxdigit(*str))
                        return SR_FALSE;
        }
        return SR_TRUE;
}

static SR_BOOL is_valid_perm(char *perm)
{
	if (strlen(perm) > 3)
		return 0;

	for(; *perm; perm++) {
		if (*perm != 'r' && *perm != 'w' && *perm != 'x') {
			return SR_FALSE;
		}
	}

	return SR_TRUE;
}

static SR_BOOL is_valid_action(char *action)
{
	return SR_TRUE;
}

static SR_BOOL is_valid_type(char *type)
{
	return (!strcmp(type, "rule") || !strcmp(type, "wl"));
}

static SR_BOOL is_valid_section(char *section)
{
	return (!strcmp(section, "can") || !strcmp(section, "file") || !strcmp(section, "ip"));
}

static SR_BOOL is_valid_ip_addr(char *ip_addr)
{
	char ip[IP_ADDR_SIZE], netmask[IP_NETMASK_SIZE];
	SR_U32 i;

	for (i =0 ; ip_addr[i] && ip_addr[i] != '/'; i++);
	if (!ip_addr[i])
		return SR_FALSE; // No net mask.
	memcpy(ip, ip_addr, i);
	ip[i] = 0;
	strcpy(netmask, ip_addr + i + 1);
	if (!*netmask)
		return SR_FALSE; // No net mask.

	if (!is_valid_ip(ip))
		return SR_FALSE;

	for (i = 0; netmask[i]; i++) {
		if (!isdigit(netmask[i]))
			return SR_FALSE;
	}
	if (atoi(netmask) > 255)
		return SR_FALSE;
	
	return SR_TRUE;
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

static SR_BOOL is_valid_action_type(char *type)
{
	return (!strcmp(type, "drop") ||  !strcmp(type, "allow"));
}

static SR_BOOL is_valid_log_facility(char *log)
{
	return (!strcmp(log, "syslog") || !strcmp(log, "vsentry"));
}

static SR_BOOL is_valid_mid_group(char *mid_group)
{
	return redis_mng_has_list(c, LIST_MIDS, mid_group) == 1; 
}

static SR_U32 handle_param(char *param, char *field, int field_size, int argc, int *i, char **argv, SR_BOOL (*is_valid_cb)(char *value)) 
{
	if (!strcmp(argv[*i], param)) {
		(*i)++;
		if (*i == argc) {
			printf("%s value is misssing.\n", param);
			return SR_ERROR;
		}
		if (!is_valid_cb(argv[*i])) {
			printf("%s is invalid.\n", param);
			return SR_ERROR;
		}
		strncpy(field, argv[*i], field_size);
	}
	return SR_SUCCESS;
}

#define HANDLE_COMMON_PARAMS \
	if (handle_param("program", program, sizeof(program), argc, &i, argv, is_valid_program) != SR_SUCCESS) \
		return SR_ERROR;  \
	if (handle_param("user", user, sizeof(user), argc, &i, argv, is_valid_user) != SR_SUCCESS) \
		return SR_ERROR;  \
	if (handle_param("action", action, sizeof(action), argc, &i, argv, is_valid_action) != SR_SUCCESS) \
		return SR_ERROR; \

#define INIT_COMMON_PARAMS \
	*action = 0; \
	strcpy(program, "*"); \
	strcpy(user, "*");

#define UPDATE_INIT_COMMON_PARAMS \
	*action = 0; \
	*program = 0; \
	*user = 0;

#define EMPTY2NULL(field) *field ? field : NULL

#define CHECK_MISSING_PARAM(param, param_str) \
	if (!is_update && !*param) { \
		printf("%s is missing\n", param_str); \
		return SR_ERROR; \
	}

static SR_32 handle_update_can(SR_U32 rule_id, SR_BOOL is_wl, int argc, char **argv)
{
	int i;
	char mid[MAX_LIST_NAME], interface[64], dir[32], user[USER_NAME_SIZE], program[PROG_NAME_SIZE], action[ACTION_STR_SIZE];
	SR_32 ret, is_update;

	if ((is_update = redis_mng_has_can_rule(c, rule_id)) == SR_ERROR)
 		return SR_ERROR;

	*interface = 0;
	if (!is_update) {
		INIT_COMMON_PARAMS
		strcpy(mid, "any");
		strcpy(dir, "both");
	} else  {
		UPDATE_INIT_COMMON_PARAMS
	}

	for (i = 0; i < argc; i++) {
		if (handle_param("mid", mid, sizeof(mid), argc, &i, argv, is_valid_msg_id) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("mid-group", mid, sizeof(mid), argc, &i, argv, is_valid_mid_group) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("interface", interface, sizeof(interface), argc, &i, argv, is_valid_interface) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("dir", dir, sizeof(dir), argc, &i, argv, is_valid_dir) != SR_SUCCESS)
			return SR_ERROR; 
		HANDLE_COMMON_PARAMS
	}
	if (!is_wl) {
		CHECK_MISSING_PARAM(action, "action")
	}
	CHECK_MISSING_PARAM(interface, "interface")

	ret = redis_mng_update_can_rule(c, rule_id, EMPTY2NULL(mid), EMPTY2NULL(interface), EMPTY2NULL(program), EMPTY2NULL(user),
		EMPTY2NULL(action), EMPTY2NULL(dir));
	if (ret != SR_SUCCESS) {
		printf("update rule failed");
		return ret;
	}
#ifdef DEBUG
	printf("handle can %d %d mid:%s interface:%s program:%s user:%s ret:%d \n", rule_id, is_wl, mid, interface, program, user, ret); 
#endif

	return SR_SUCCESS;
} 

static SR_32 handle_update_file(SR_U32 rule_id, SR_BOOL is_wl, int argc, char **argv)
{
	int i;
	char filename[32], perm[FILE_NAME_SIZE];
	char user[USER_NAME_SIZE], program[PROG_NAME_SIZE], action[ACTION_STR_SIZE];
	SR_32 ret, is_update;

	if ((is_update = redis_mng_has_file_rule(c, rule_id)) == SR_ERROR)
 		return SR_ERROR;

	*filename = 0;
	*perm = 0;
	if (!is_update) {
		INIT_COMMON_PARAMS
	} else {
		UPDATE_INIT_COMMON_PARAMS
	}

	for (i = 0; i < argc; i++) {
		if (handle_param("filename", filename, sizeof(filename), argc, &i, argv, is_valid_file) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("perm", perm, sizeof(perm), argc, &i, argv, is_valid_perm) != SR_SUCCESS)
			return SR_ERROR; 
		HANDLE_COMMON_PARAMS
	}
	if (!is_wl) {
		CHECK_MISSING_PARAM(action, "action")
	}
	CHECK_MISSING_PARAM(filename, "filename")
	CHECK_MISSING_PARAM(perm, "perm")

	ret = redis_mng_update_file_rule(c, rule_id, EMPTY2NULL(filename), EMPTY2NULL(program), EMPTY2NULL(user), EMPTY2NULL(action), *perm ? perm_cli_to_db(perm) : NULL);
	if (ret != SR_SUCCESS) {
		printf("update rule failed");
		return ret;
	}
#ifdef DEBUG
	printf("handle file rule %d %d filename:%s perm:%s program:%s user:%s action:%s ret:%d \n", rule_id, is_wl, filename, perm_cli_to_db(perm), program, user, action, ret); 
#endif

	return SR_SUCCESS;
} 

static SR_32 handle_update_ip(SR_U32 rule_id, SR_BOOL is_wl, int argc, char **argv)
{
	int i;
	char src_addr[IP_ADDR_SIZE + IP_NETMASK_SIZE + 1], dst_addr[IP_ADDR_SIZE + IP_NETMASK_SIZE + 1], proto[PROTO_SIZE], src_port[PORT_SIZE], dst_port[PORT_SIZE];
	char user[USER_NAME_SIZE], program[PROG_NAME_SIZE], action[ACTION_STR_SIZE];
	SR_32 ret, is_update;

	if ((is_update = redis_mng_has_net_rule(c, rule_id)) == SR_ERROR)
 		return SR_ERROR;

	if (!is_update) {
		INIT_COMMON_PARAMS
		strcpy(proto, "any");
		strcpy(src_addr, "0.0.0.0/32");
		strcpy(dst_addr, "0.0.0.0/32");
		strcpy(src_port, "0");
		strcpy(dst_port, "0");
	} else {
		UPDATE_INIT_COMMON_PARAMS
		*proto = *src_addr = *dst_addr = *src_port = *dst_port = 0;
	}
	for (i = 0; i < argc; i++) {
		if (handle_param("src_addr", src_addr, sizeof(src_addr), argc, &i, argv, is_valid_ip_addr) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("dst_addr", dst_addr, sizeof(dst_addr), argc, &i, argv, is_valid_ip_addr) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("proto", proto, sizeof(proto), argc, &i, argv, is_valid_ip_proto) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("src_port", src_port, sizeof(src_port), argc, &i, argv, is_valid_port) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("dst_port", dst_port, sizeof(dst_port), argc, &i, argv, is_valid_port) != SR_SUCCESS)
			return SR_ERROR; 
		HANDLE_COMMON_PARAMS
	}

	if (!is_wl) {
		CHECK_MISSING_PARAM(action, "action")
	}

	ret = redis_mng_update_net_rule(c, rule_id, EMPTY2NULL(src_addr), EMPTY2NULL(dst_addr), EMPTY2NULL(proto),
		EMPTY2NULL(src_port), EMPTY2NULL(dst_port), EMPTY2NULL(program), EMPTY2NULL(user), EMPTY2NULL(action));
 	if (ret != SR_SUCCESS) {
		printf("update rule failed");
		return ret;
	}
#ifdef DEBUG
	printf("handle ip rule %d %d src_addr:%s dst_addr:%s proto:%s sport:%s dport:%s program:%s user:%s action:%s ret:%d \n",
		rule_id, is_wl, src_addr, dst_addr, proto, src_port, dst_port, program, user, action, ret); 
#endif

	return SR_SUCCESS;
} 

static SR_32 get_group_index(char *type)
{
	SR_U32 i;

	for (i =0 ; i <= MAX_GROUP && *(group_info[i].group_name); i++) {
		if (!strcmp(group_info[i].group_name, type))
			return i;
	}
	return -1;
}

static void print_groups_types(void)
{
	SR_U32 i;

	for (i =0 ; i <= MAX_GROUP && *(group_info[i].group_name); i++) {
		printf("%s\n", group_info[i].group_name);
	}
}

static SR_32 handle_update_group(int argc, char **argv)
{
	char *type, *name;
	SR_32 group_id, i, n, rc = SR_SUCCESS, ret;
	char *list_values[MAX_LIST_VALUES] = {};

	if (argc < 3) {
		print_update_group_usage();
		return SR_ERROR;
	}

	type = argv[0];
	if ((group_id = get_group_index(type)) < 0) {
		printf(" group type %s is not valid \n", type);
		return SR_ERROR;
	}
	name = argv[1];

	// If list exits, delete it, the recreate it
	if ((ret = redis_mng_has_list(c, group_info[group_id].list_type, name)) == SR_ERROR){
		printf("redis_mng_has_list failed\n");
		return SR_ERROR;
	}
	if (ret == 1) {	
		// Delete list
		if (redis_mng_destroy_list(c, group_info[group_id].list_type, name) != SR_SUCCESS) {
			printf("Delete failed\n");
			return SR_ERROR;
		}
	}

#ifdef DEBUG
	printf("update group type:%s name:%s \n", type, name);
#endif
	n = argc - 2;
	if (n >  MAX_LIST_VALUES) { 
		printf("Number of items excees maximun of %d \n", MAX_LIST_VALUES);
	}
	for (i = 2; i < argc; i++) {
		if (strlen(argv[i]) > MAX_LIST_VAL_LEN) {
			printf("Item %s exceed maximun length of %d \n", argv[i], MAX_LIST_VAL_LEN);
			rc = SR_ERROR;
			goto out;
		}
		if (group_info[group_id].valid_cb && !group_info[group_id].valid_cb(argv[i])) {
			printf("Value %s is invalid \n", argv[i]);
			return SR_ERROR;
		}
		if (!(list_values[i - 2] = strdup(argv[i]))) {
			printf("Failed allocating memory\n");
			return SR_ERROR;
		}
	}

	if (redis_mng_add_list(c, group_info[group_id].list_type, name, n, list_values)) {
		printf("Redis list add Failed !!\n");
		rc = SR_ERROR;
	}

out:
	for (i = 0; i < MAX_LIST_VALUES && list_values[i]; i++) {
		free(list_values[i]);
	}
	fflush(stdout);

	return rc;
}

static SR_32 handle_update_action(int argc, char **argv)
{
	char *name;
	char log[LOG_FACILITY_SIZE] = {}, rl_log[LOG_FACILITY_SIZE] = {};
	char rl_action[ACTION_STR_SIZE] = {}, action[ACTION_STR_SIZE] = {};
	int ret, i;

	if (argc < 3) {
		print_action_usage();
		return SR_ERROR;
	}

	name = argv[0];
	
	for (i = 1; i < argc; i++) {
		if (handle_param("action", action, sizeof(action), argc, &i, argv, is_valid_action_type) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("log", log, sizeof(log), argc, &i, argv, is_valid_log_facility) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("rate_limit_action", rl_action, sizeof(rl_action), argc, &i, argv, is_valid_action_type) != SR_SUCCESS)
			return SR_ERROR; 
		if (handle_param("rate_limit_log", rl_log, sizeof(rl_action), argc, &i, argv, is_valid_log_facility) != SR_SUCCESS)
			return SR_ERROR; 
	}

#if DEBUG
	printf("action name:%s action:%s action log facility:%s rl actioin :%s: rl action log:%s:\n", name, action, log, rl_action, rl_log);
#endif

	return SR_SUCCESS;
}

static SR_32 handle_update(int argc, char **argv)
{
	char *type, *section;
	SR_U32 rule_id;

	if (argc < 3) {
		print_update_usage();
		return SR_ERROR;
	}

	type = argv[0];
	if (!strcmp(type, "group"))
		return handle_update_group(argc - 1 , argv + 1);
	if (!strcmp(type, "action"))
		return handle_update_action(argc - 1 , argv + 1);

	section = argv[1];

	if (strcmp(argv[2], "rule_number") != 0) {
		printf("Rule id is missing\n");
		return SR_ERROR;
	}
	if (!is_valid_rule_id(type, section, argv[3])) {
		printf("Invalid rule id\n");
		return SR_ERROR;
	}
	rule_id = atoi(argv[3]);

	if (!strcmp(section, "can")) 
		return handle_update_can(rule_id, strcmp(type, "wl") == 0, argc - 4, argv + 4);
	if (!strcmp(section, "file")) 
		return handle_update_file(rule_id, strcmp(type, "wl") == 0, argc - 4, argv + 4);
	if (!strcmp(section, "ip")) 
		return handle_update_ip(rule_id, strcmp(type, "wl") == 0, argc - 4, argv + 4);

	return SR_SUCCESS;
}

static SR_32 show_version(void)
{
	int fd, rc;
	char buf2[256];

	if ((fd = engine_connect()) < 0) {
		printf("failed engine connect");
		return SR_ERROR;
	}
	rc = write(fd, "sr_ver", strlen("sr_ver"));
	if (rc < 0) {
 		printf("write error");
		return SR_ERROR;
        }
	if (rc < strlen("sr_ver")) {
		printf("partial write");
		return SR_ERROR;
	}

	usleep(30000);
	rc = read(fd, buf2, 256);
	if (rc < 0) {
		printf("read error");
		return SR_ERROR;
	}
	printf("%s\n", buf2);

	close(fd);

	return SR_SUCCESS;
}

static SR_32 show_group(int argc, char **argv)
{
	char *type, *name;
	SR_32 group_id;

	if (!argc) {
		printf("Show all the list types:\n");
		print_groups_types();
		return SR_SUCCESS;
	}

	type = argv[0];
	if ((group_id = get_group_index(type)) < 0) {
		printf(" group type %s is not valid \n", type);
		return SR_ERROR;
	}

	if (argc == 1) {
		redis_mng_print_all_list_names(c, group_info[group_id].list_type);
		return SR_SUCCESS;
	}

	name = argv[1];
	printf("Showing group type:%d name:%s:\n", group_info[group_id].list_type, name);
	redis_mng_print_list(c, group_info[group_id].list_type, name);

	return SR_SUCCESS;
}

static SR_32 handle_show(int argc, char **argv)
{
	SR_BOOL is_can = SR_FALSE, is_file = SR_FALSE, is_ip = SR_FALSE;
	SR_32 from = -1, to = -1;

	if (!argc) {
		print_show_usage();
		return SR_SUCCESS;
	}

	if (!strcmp(argv[0], "version"))
		return show_version();
	if (!strcmp(argv[0], "group"))
		return show_group(argc - 1, argv + 1);

	if (argc < 2) {
		is_can = is_file = is_ip = SR_TRUE;
		goto print;
	}
	if (!strcmp(argv[1], "can"))
		is_can = SR_TRUE;
	if (!strcmp(argv[1], "ip"))
		is_ip = SR_TRUE;
	if (!strcmp(argv[1], "file"))
		is_file = SR_TRUE;
	
	if (argc > 2)
		from = to = atoi(argv[1]);
print:
	if (is_can) {
		printf("Can rules :\n");
		redis_mng_print_rules(c, RULE_TYPE_CAN, from, to);
	}
	if (is_file) {
		printf("File rules :\n");
		redis_mng_print_rules(c, RULE_TYPE_FILE, from, to);
	}
	if (is_ip) {
		printf("IP rules :\n");
		redis_mng_print_rules(c, RULE_TYPE_IP, from, to);
	}

	return SR_SUCCESS;
}

static SR_32 handle_delete_group(int argc, char **argv)
{
	char *type, *name;
	SR_32 group_id;

	if (argc < 2) {
		print_delete_group_usage();
		return SR_ERROR;
	}

	type = argv[0];
	if ((group_id = get_group_index(type)) < 0) {
		printf(" group type %s is not valid \n", type);
		return SR_ERROR;
	}
	name = argv[1];

	if (redis_mng_destroy_list(c, group_info[group_id].list_type, name) != SR_SUCCESS) {
		printf("Delete failed\n");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

static SR_32 handle_delete(int argc, char **argv)
{
	char *type, *section;
	SR_U32 from_rule = -1, to_rule = -1;
	SR_BOOL is_can = SR_FALSE, is_file = SR_FALSE, is_ip = SR_FALSE, is_force = SR_TRUE;

	if (argc < 1) {
		print_delete_usage();
		return SR_ERROR;
	}

	if (!strcmp(argv[0], "group"))
		return handle_delete_group(argc - 1, argv + 1);

	type = argv[0];
	if (!is_valid_type(type)) {
		printf("Invalid %s type.\n", type);
		print_delete_usage();
		return SR_ERROR;
	}
	
	section = argv[1];
	if (!is_valid_section(section)) {
		printf("Invalid section: %s.\n", section);
		print_delete_usage();
		return SR_ERROR;
	}
	if (!strcmp(section, "can")) {
		is_can = SR_TRUE;
		if (!strcmp(type, "rule")) {
			from_rule = 0;
			to_rule = SR_CAN_WL_START_RULE_NO - 1;
		} else if (!strcmp(type, "wl")) {
			from_rule = SR_CAN_WL_START_RULE_NO;
			to_rule = SR_CAN_WL_END_RULE_NO;
		}
	}
	else if (!strcmp(section, "file")) {
		is_file = SR_TRUE;
		if (!strcmp(type, "rule")) {
			from_rule = 0;
			to_rule = SR_FILE_WL_START_RULE_NO - 1;
		} else if (!strcmp(type, "wl")) {
			from_rule = SR_FILE_WL_START_RULE_NO;
			to_rule = SR_FILE_WL_END_RULE_NO;
		}
	} else if (!strcmp(section, "ip")) {
		is_ip = SR_TRUE;
		if (!strcmp(type, "rule")) {
			from_rule = 0;
			to_rule = SR_IP_WL_START_RULE_NO - 1;
		} else if (!strcmp(type, "wl")) {
			from_rule = SR_IP_WL_START_RULE_NO;
			to_rule = SR_IP_WL_END_RULE_NO;
		}
	}
	if (argc < 3) {
		printf("Delete all %s rules of %s type ? [y/N]:", section, type);
		if (getc(stdin) != 'y')
			return SR_SUCCESS;
		goto delete;
	}

	is_force = SR_FALSE;
	if (strcmp(argv[2], "rule_number") != 0) {
		printf("Invalid parameter, rule_number is expected \n");
		return SR_ERROR;
	}
	if (!is_valid_rule_id(type, section, argv[3])) {
		printf("Invalid rule id\n");
		return SR_ERROR;
	}
	from_rule = to_rule = atoi(argv[3]);

delete:
#if DEBUG
	printf("deleting can:%d file:%d ip:%d from:%d to:%d force:%d \n", is_can, is_file, is_ip, from_rule, to_rule, is_force);
#endif
	if (is_file) {
		if (redis_mng_del_file_rule(c, from_rule, to_rule, is_force) != SR_SUCCESS) {
			printf("File rules %d-%d failed\n", from_rule, to_rule);
			return SR_ERROR;
		}
	}
	if (is_ip) {
		if (redis_mng_del_net_rule(c, from_rule, to_rule, is_force) != SR_SUCCESS) {
			printf("IP rules %d-%d failed\n", from_rule, to_rule);
			return SR_ERROR;
		}
	}
	if (is_can) {
		if (redis_mng_del_can_rule(c, from_rule, to_rule, is_force) != SR_SUCCESS) {
			printf("CAN rules %d-%d failed\n", from_rule, to_rule);
			return SR_ERROR;
		}
	}

	return SR_SUCCESS;

}

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
                printf("failed engine connect");
                return;
        }
        rc = write(fd, cmd, strlen(cmd));
        if (rc < 0) {
                printf("write error");
                return;
        }
        if (rc < strlen(cmd)) {
                printf("partial write");
                return;
        }

        if (is_print) {
                if (cli_handle_reply(fd, handle_print_cb) != SR_SUCCESS)
                        printf("print Failed\n");
        }

        close(fd);

	if (msg)
		printf("%s\n", msg);
}

static void handle_apply(void)
{
        SR_32 fd;
        int ret = 0, rc, counter = 0;
        char line[4] = {'|', '/', '-', '\\'}, cval;
        fd_set fds;
        struct timeval tv;

        if ((fd = engine_connect()) < 0) {
                printf("failed engine connect");
                return;
        }
        rc = write(fd, "wl_apply", strlen("wl_apply"));
        if (rc < 0) {
                printf("write error");
                return;
        }
        if (rc < strlen("wl_apply")) {
                printf("partial write");
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

        printf("\napply finished.\n");

	close(fd);
}

static SR_32 handle_wl(int argc, char **argv)
{
	if (!argc) {
		print_control_usage();
		return SR_ERROR;
	}
	if (!strcmp(argv[0], "learn")) {
		handle_cmd_gen("wl_learn", "learning...", SR_FALSE);
		return SR_SUCCESS;
	}
	if (!strcmp(argv[0], "apply")) {
		handle_apply();
		return SR_SUCCESS;
	}
	if (!strcmp(argv[0], "print")) {
		handle_cmd_gen("wl_print", NULL, SR_TRUE);
		return SR_SUCCESS;
	}

	return SR_SUCCESS;
}

static SR_32 handle_control(int argc, char **argv)
{
	if (!argc) {
		print_control_usage();
		return SR_ERROR;
	}
	if (!strcmp(argv[0], "wl")) 
		return handle_wl(argc - 1, argv + 1);

	return SR_SUCCESS;
}

SR_32 main(int argc, char **argv)
{
	if (!(c = redis_mng_session_start(1))) {
                printf("ERROR: redis_mng_session_start failed\n");
                redis_mng_session_end(c);
                return SR_ERROR;
        }

	if (argc < 2) {
		print_usage(argv[0]);
		return SR_ERROR;
	}

	if (!strcmp(argv[1], "update"))
		return handle_update(argc - 2, argv + 2);
	if (!strcmp(argv[1], "show"))
		return handle_show(argc - 2, argv + 2);
	if (!strcmp(argv[1], "delete"))
		return handle_delete(argc - 2, argv + 2);
	if (!strcmp(argv[1], "control"))
		return handle_control(argc - 2, argv + 2);

	return SR_SUCCESS;
}

