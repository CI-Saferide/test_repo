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
#include <unistd.h>

#define MAX_LIST_NAME 64
#define IP_ADDR_SIZE 32
#define IP_NETMASK_SIZE 4
#define PROTO_SIZE 8
#define PORT_SIZE 16

static redisContext *c;

static void print_update_usage(void)
{
	printf("update ... \n");
}

static void print_usage(char *prog)
{
	printf("usgae: %s\n", prog);
}

static SR_BOOL is_valid_rule_id(char *rule_str)
{
	for (; *rule_str; rule_str++) {
		if (!isdigit(*rule_str))
			return SR_FALSE;
	}

	return SR_TRUE;
}

static SR_BOOL is_valid_file(char *file)
{
        struct stat buf;

        if (stat(file, &buf)) {
                printf("file does not exist\n");
                return 0;
        }

        return 1;
}

static SR_BOOL is_valid_msg_id(char *str)
{
        if (!strcmp(str, "any"))
                return 1;
        for (; *str; str++) {
                if (!isxdigit(*str))
                        return 0;
        }
        return 1;
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

static SR_U32 handle_param(char *param, char *field, int field_size, int argc, int *i, char **argv, SR_BOOL (*is_valid_db)(char *value)) 
{
	if (!strcmp(argv[*i], param)) {
		(*i)++;
		if (*i == argc) {
			printf("%s value is misssing.\n", param);
			return SR_ERROR;
		}
		if (!is_valid_db(argv[*i])) {
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
	char mid[32], interface[64], dir[32], user[USER_NAME_SIZE], program[PROG_NAME_SIZE], action[ACTION_STR_SIZE];
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

	ret = redis_mng_add_can_rule(c, rule_id, mid, interface, program, user, action, dir);
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

	ret = redis_mng_add_file_rule(c, rule_id, filename, program, user, action, perm_cli_to_db(perm));
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

	ret = redis_mng_add_net_rule(c, rule_id, EMPTY2NULL(src_addr), EMPTY2NULL(dst_addr), EMPTY2NULL(proto),
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

static SR_32 handle_update(int argc, char **argv)
{
	char *type, *section;
	SR_U32 rule_id;

	if (argc < 5) {
		print_update_usage();
		return SR_ERROR;
	}

	type = argv[0];
	section = argv[1];

	if (strcmp(argv[2], "rule_number") != 0) {
		printf("Rule id is missing\n");
		return SR_ERROR;
	}
	if (!is_valid_rule_id(argv[3])) {
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

static void print_can_rules(redisContext *c, SR_BOOL is_wl, SR_32 rule_id)
{
        redis_mng_print_db(c, RULE_TYPE_CAN, rule_id);
}

static void print_net_rules(redisContext *c, SR_BOOL is_wl, SR_32 rule_id)
{
        redis_mng_print_db(c, RULE_TYPE_IP, rule_id);
}

static void print_file_rules(redisContext *c, SR_BOOL is_wl, SR_32 rule_id)
{
        redis_mng_print_db(c, RULE_TYPE_FILE, rule_id);
}

static SR_32 handle_show(int argc, char **argv)
{
	print_can_rules(c, SR_FALSE, -1);
	print_net_rules(c, SR_FALSE, -1);
	print_file_rules(c, SR_FALSE, -1);

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

	return SR_SUCCESS;
}

