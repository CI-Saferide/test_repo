#include <string.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <linux/vsentry/vsentry.h>
#include <linux/vsentry/vsentry_drv.h>
#include "classifier.h"
#include "can_cls.h"
#include "uid_cls.h"
#include "prog_cls.h"
#include "heap.h"
#include "net_cls.h"
#include "port_cls.h"
#include "ip_proto_cls.h"
#include "file_cls.h"

#define DB_FILE 	"/etc/vsentry/db.mem"
#define EXEC_FILE 	"/etc/vsentry/cls.bin"
#define PAD_SIZE 	4096

static void *dbmem = NULL;
static int dbmem_size = 0;
static void *execmem = NULL;
static int execsize = 0;
static FILE *db_file = NULL;
#ifdef USE_BIN
static int (*cls_event)(vsentry_ev_type_e ev_type, vsentry_event_t *event, bool atomic) = NULL;
#else
static int (*cls_event)(vsentry_ev_type_e ev_type, vsentry_event_t *event) = cls_handle_event;
#endif

#define CLI_STR_INT_SIZE 	32
#define CLI_STR_HEX_SIZE 	32

static void read_char(unsigned char *ptr, char *str, int size)
{
	memset(str, 0, size);
	if (fgets(str, size, stdin))
		*ptr = (unsigned char)atoi(str);
}

static void read_string(char *ptr, int size)
{
	char *nl;

	memset(ptr, 0, size);
	if (fgets(ptr, size, stdin)) {
		nl = strchr(ptr, '\n');
		if (nl)
			*nl = 0;
	}
}

static void read_short(unsigned short *ptr, char *str, int size)
{
	memset(str, 0, size);
	if (fgets(str, size, stdin))
		*ptr = (unsigned short)atoi(str);
}

static void read_int(unsigned int *ptr, char *str, int size)
{
	memset(str, 0, size);
	if (fgets(str, size, stdin))
		*ptr = atoi(str);
}

static void read_long(unsigned long *ptr, char *str, int size)
{
	memset(str, 0, size);
	if (fgets(str, size, stdin))
		*ptr = atol(str);
}

static void read_hex(unsigned int *ptr, char *str, int size)
{
	memset(str, 0, size);
	if (fgets(str, size, stdin))
		*ptr = strtol(str, NULL, 16);
}

static int read_ip(unsigned int *ptr, char *str, int size)
{
	int a, b, c, d;

	memset(str, 0, size);
	if (fgets(str, size, stdin)) {
		if (sscanf(str, "%d.%d.%d.%d", &a, &b, &c, &d) != 4) {
			fprintf(stderr, "invalid ip addr\n");
			return VSENTRY_ERROR;
		}

		*ptr = (((d&0xFF)<<24) | ((c&0xFF)<<16) | ((b&0xFF)<<8) | (a&0xFF));
	}
	return VSENTRY_SUCCESS;
}

static int get_can_msgid(unsigned int *msg_id)
{
	char str[CLI_STR_HEX_SIZE];

	fprintf(stdout, "enter can msg_id (hex): ");

	read_hex(msg_id, str, CLI_STR_HEX_SIZE);

	if ((*msg_id > MAX_CAN_MSG_ID) && (*msg_id !=  MSGID_ANY)) {
		fprintf(stderr, "invalid msg_id\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int get_file_type(unsigned int *type)
{
	char str[CLI_STR_HEX_SIZE];

	fprintf(stdout, "enter file type (0-reg, 1-sysfs, 2-procfs): ");

	read_int(type, str, CLI_STR_HEX_SIZE);

	if (*type >= FILE_TYPE_TOTAL ) {
		fprintf(stderr, "invalid type\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int get_file_mode(unsigned int *mode)
{
	char str[CLI_STR_HEX_SIZE];

	fprintf(stdout, "enter file mode (hex): ");

	read_hex(mode, str, CLI_STR_HEX_SIZE);

	if (*mode > (FILE_MODE_EXEC | FILE_MODE_WRITE | FILE_MODE_READ)) {
		fprintf(stderr, "invalid mode\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int get_dir(unsigned int *dir)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "enter direction (0 src / 1 dst): ");

	read_int(dir, str, CLI_STR_INT_SIZE);

	if (*dir >= DIR_TOTAL) {
		fprintf(stderr, "invalid direction\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

#define CAN_IF_MAX 	10

static int get_can_if(unsigned int *interface)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "enter can if (0-256): ");

	read_int(interface, str, CLI_STR_INT_SIZE);

	if (*interface >= CAN_IF_MAX) {
		fprintf(stderr, "invalid interface number\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int get_rule_num(unsigned int *rule)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "enter rule number (0-4095) :");

	read_int(rule, str, CLI_STR_INT_SIZE);

	if (*rule >= MAX_RULES) {
		fprintf(stderr, "invalid rule number\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int get_rule_num_with_default(unsigned int *rule)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "enter rule number (0-4095/4096 default):");

	read_int(rule, str, CLI_STR_INT_SIZE);

	if (*rule > MAX_RULES) {
		fprintf(stderr, "invalid rule number\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int get_type(unsigned int *type)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "enter type (0-ip, 1-can, 2-file) : ");

	read_int(type, str, CLI_STR_INT_SIZE);

	if (*type >= CLS_TOTAL_RULE_TYPE) {
		fprintf(stderr, "invalid type\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int get_limit(unsigned int *limit)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "enter limit : ");

	read_int(limit, str, CLI_STR_INT_SIZE);

	return VSENTRY_SUCCESS;
}

static int get_action(unsigned int *action_map)
{
	char str[CLI_STR_HEX_SIZE];

	fprintf(stdout, "enter action (hex): ");

	read_hex(action_map, str, CLI_STR_HEX_SIZE);

	return VSENTRY_SUCCESS;
}

static int get_int(unsigned int *ptr, char *prompt)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "%s", prompt);

	read_int(ptr, str, CLI_STR_INT_SIZE);

	return VSENTRY_SUCCESS;
}

static int get_long(unsigned long *ptr, char *prompt)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "%s", prompt);

	read_long(ptr, str, CLI_STR_INT_SIZE);

	return VSENTRY_SUCCESS;
}

static int get_short(unsigned short *ptr, char *prompt)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "%s", prompt);

	read_short(ptr, str, CLI_STR_INT_SIZE);

	return VSENTRY_SUCCESS;
}

static int get_char(unsigned char *ptr, char *prompt)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "%s", prompt);

	read_char(ptr, str, CLI_STR_INT_SIZE);

	return VSENTRY_SUCCESS;
}

static int get_string(char *ptr, int size, char *prompt)
{
	fprintf(stdout, "%s", prompt);

	read_string(ptr, size);

	return VSENTRY_SUCCESS;
}

static int get_ip(unsigned int *ptr, char *prompt)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "%s", prompt);

	return read_ip(ptr, str, CLI_STR_INT_SIZE);
}

static int get_ip_proto(unsigned int *ip_proto)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "enter ip_proto (0-255, -1 any): ");

	read_int(ip_proto, str, CLI_STR_INT_SIZE);

	if ( (*ip_proto != (unsigned int)(-1)) && (*ip_proto > 255)) {
		fprintf(stderr, "invalid ip_proto\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static int get_port(unsigned int *port)
{
	char str[CLI_STR_INT_SIZE];

	fprintf(stdout, "enter port (0-65535, -1 any): ");

	read_int(port, str, CLI_STR_INT_SIZE);

	if ( (*port != (unsigned int)(-1)) && (*port > 65535)) {
		fprintf(stderr, "invalid port\n");
		return VSENTRY_ERROR;
	}

	return VSENTRY_SUCCESS;
}

static void rule(bool add)
{
	act_t act;
	int ret;
	unsigned int rule, type, limit;

	if (get_type(&type) != VSENTRY_SUCCESS)
		return;

	if (get_rule_num_with_default(&rule) != VSENTRY_SUCCESS)
		return;

	if (add) {
		if (get_limit(&limit) != VSENTRY_SUCCESS)
			return;

		if (rule == MAX_RULES) {
			get_action(&act.action_bitmap);
			ret = cls_default_action(type, &act, limit);
		} else {
			get_string(act.name, ACTION_NAME_SIZE, "enter action name: ");
			act.name_len = strlen(act.name);
			ret = cls_add_rule(type, rule, act.name, act.name_len, limit);
		}
	} else {
		ret = cls_del_rule(type, rule);
	}

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

static void can_rule(bool add)
{
	unsigned int rule;
	can_header_t can_data;
	unsigned int dir;
	int ret;

	memset(&can_data, 0, sizeof(can_data));

	if (get_can_msgid(&can_data.msg_id) != VSENTRY_SUCCESS)
		return;

	if (can_data.msg_id != MSGID_ANY) {
		if (get_can_if(&can_data.if_index) != VSENTRY_SUCCESS)
			return;
	}

	if (get_dir(&dir) != VSENTRY_SUCCESS)
		return;

	if (get_rule_num(&rule) != VSENTRY_SUCCESS)
		return;

	if (add)
		ret = can_cls_add_rule(rule, &can_data, dir);
	else
		ret = can_cls_del_rule(rule, &can_data, dir);

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

static void uid_rule(bool add)
{
	unsigned int rule, uid, type;
	int ret;

	get_int(&uid, "enter uid : ");

	if (get_type(&type) != VSENTRY_SUCCESS)
		return;

	if (get_rule_num(&rule) != VSENTRY_SUCCESS)
		return;

	if (add)
		ret = uid_cls_add_rule(type, rule, uid);
	else
		ret = uid_cls_del_rule(type, rule, uid);

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

static void prog_rule(bool add)
{
	unsigned int rule, exec_ino, type;
	char progname[4096];
	int ret;

	if (get_type(&type) != VSENTRY_SUCCESS)
		return;

	if (get_rule_num(&rule) != VSENTRY_SUCCESS)
		return;

	if (get_string(progname, 4096, "enter prog name: ") != VSENTRY_SUCCESS)
		return;

	if (add) {
		get_int(&exec_ino, "enter exec_ino : ");

		ret = prog_cls_add_rule(type, rule, progname, exec_ino, strlen(progname));
	} else {
		ret = prog_cls_del_rule(type, rule, progname);
	}

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

static void net_rule(bool add)
{
	unsigned int ip, mask, rule, dir;
	int ret;

	if (get_rule_num(&rule) != VSENTRY_SUCCESS)
		return;

	if (get_dir(&dir) != VSENTRY_SUCCESS)
		return;

	if (get_ip(&ip, "enter ip addres: ") != VSENTRY_SUCCESS)
		return;

	if (get_ip(&mask, "enter mask: ") != VSENTRY_SUCCESS)
		return;

	if (add)
		ret = net_cls_add_rule(rule, ip, mask, dir);
	else
		ret = net_cls_del_rule(rule, ip, mask, dir);

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

static void file_rule(bool add)
{
	char filename[4096];
	unsigned int rule;
	file_event_t file_ev;
	int ret;

	if (get_rule_num(&rule) != VSENTRY_SUCCESS)
		return;

	if (get_file_type(&file_ev.type) != VSENTRY_SUCCESS)
		return;

	if (file_ev.type == FILE_TYPE_REG) {
		get_string(filename, 4096, "enter file name: ");
		file_ev.filename = filename;
		file_ev.filename_len = vs_strlen(file_ev.filename);

		get_long(&file_ev.file_ino, "enter file_ino : ");
	}

	if (add) {
		if (get_file_mode(&file_ev.mode) != VSENTRY_SUCCESS)
			return;

		ret = file_cls_add_rule(rule, &file_ev);
	} else {
		ret = file_cls_del_rule(rule, &file_ev);
	}

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

static void port_rule(bool add)
{
	unsigned int port, ip_proto, rule, dir;
	int ret;

	if (get_rule_num(&rule) != VSENTRY_SUCCESS)
		return;

	if (get_dir(&dir) != VSENTRY_SUCCESS)
		return;

	get_ip_proto(&ip_proto);
	if (ip_proto != IPPROTO_TCP && ip_proto != IPPROTO_UDP) {
		fprintf(stderr, "invalid prot (only tcp(6) or udp(17)\n");
		return;
	}

	if (get_port(&port) != VSENTRY_SUCCESS)
		return;

	if (add)
		ret = port_cls_add_rule(rule, port, ip_proto, dir);
	else
		ret = port_cls_del_rule(rule, port, ip_proto, dir);

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

static void ip_proto_rule(bool add)
{
	unsigned int ip_proto, rule;
	int ret;

	if (get_rule_num(&rule) != VSENTRY_SUCCESS)
		return;

	if (get_ip_proto(&ip_proto) != VSENTRY_SUCCESS)
		return;

	if (add)
		ret = ip_proto_cls_add_rule(rule, ip_proto);
	else
		ret = ip_proto_cls_del_rule(rule, ip_proto);

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

static void action(bool add)
{
	act_t act;
	int ret;

	get_string(act.name, ACTION_NAME_SIZE, "enter action name: ");
	act.name_len = strlen(act.name);

	if (add)
		get_action(&act.action_bitmap);

	if (add)
		ret = action_cls_add(&act);
	else
		ret = action_cls_del(act.name, strlen(act.name));

	if (ret == VSENTRY_SUCCESS)
		fprintf(stdout, "Done\n");
	else
		fprintf(stdout, "Error\n");
}

void test_cls_can_ev(void)
{
	int ret;
	vsentry_event_t event;

	memset(&event, 0, sizeof(vsentry_event_t));

	get_int(&event.event_id.uid, "enter uid : ");
	get_long(&event.event_id.exec_ino, "enter exec_ino : ");

	if (get_can_msgid(&event.can_event.can_header.msg_id) != VSENTRY_SUCCESS)
		return;

	if (get_dir(&event.dir) != VSENTRY_SUCCESS)
		return;

	if (get_can_if(&event.can_event.can_header.if_index) != VSENTRY_SUCCESS)
		return;

#ifdef USE_BIN_CLS
	ret = cls_func(VSENTRY_CAN_EVENT, &event, true);
#else
	ret = cls_handle_event(VSENTRY_CAN_EVENT, &event);
#endif

	fprintf(stdout, "cls_func ret 0x%x\n", ret);
}

void test_cls_net_ev(void)
{
	int ret;
	vsentry_event_t event;

	memset(&event, 0, sizeof(vsentry_event_t));

	get_int(&event.event_id.uid, "enter uid : ");
	get_long(&event.event_id.exec_ino, "enter exec_ino : ");

	get_dir(&event.dir);

	if (get_ip(&event.ip_event.saddr.v4addr, "enter src ip addres: ") != VSENTRY_SUCCESS)
		return;

	if(get_ip(&event.ip_event.daddr.v4addr, "enter dst ip addres: ") != VSENTRY_SUCCESS)
		return;

	get_char(&event.ip_event.ip_proto, "enter porto: (6-tcp, 17-udp): ");

	if (event.ip_event.ip_proto == IPPROTO_TCP || event.ip_event.ip_proto == IPPROTO_UDP) {
		get_short(&event.ip_event.sport, "enter src port: ");
		get_short(&event.ip_event.dport, "enter dst port: ");
	}

	ret = cls_handle_event(VSENTRY_IP_EVENT, &event);

	fprintf(stdout, "cls_func ret 0x%x\n", ret);
}

void test_cls_file_ev(void)
{
	int ret;
	vsentry_event_t event;
	char filename[4096], execname[4096];

	memset(&event, 0, sizeof(vsentry_event_t));

	get_int(&event.event_id.uid, "enter uid : ");
	get_long(&event.event_id.exec_ino, "enter exec_ino : ");

	if (get_string(execname, 4096, "enter exec name: ") != VSENTRY_SUCCESS)
		return;

	event.event_id.exec_name = execname;
	event.event_id.exec_name_len = strlen(execname);

	if (get_file_type(&event.file_event.type) != VSENTRY_SUCCESS)
		return;

	if (event.file_event.type == FILE_TYPE_REG) {
		get_string(filename, 4096, "enter file name: ");
		event.file_event.filename = filename;
		event.file_event.filename_len = vs_strlen(filename);

		get_long(&event.file_event.file_ino, "enter file_ino : ");
		get_long(&event.file_event.ancestor_ino, "enter ancestor_ino : ");
	}

	if (get_file_mode(&event.file_event.mode) != VSENTRY_SUCCESS)
		return;

	ret = cls_handle_event(VSENTRY_FILE_EVENT, &event);

	fprintf(stdout, "cls_func ret %d\n", ret);
}

void trim_file_rules(void)
{
	file_cls_trim(3, 10);
}

void trim_file_rules_by_path(void)
{
	char filename[4096];

	get_string(filename, 4096, "enter file name to trim from: ");
	file_cls_trim_by_name(filename, strlen(filename));
}

void clear_rules(void)
{
#ifdef ENABLE_LEARN
	unsigned int start, stop;

	get_int(&start, "enter rule num start: ");
	get_int(&stop, "enter rule num end: ");
	cls_clear_rules(start, stop);
#endif
}

static unsigned long get_file_inode(char *filename)
{
	struct stat buf = {};

	if(stat(filename, &buf))
		return 0;

	fprintf(stdout, "file %s inode %lu\n", filename, buf.st_ino);

	return buf.st_ino;
}

void update_files_inode(void)
{
	file_cls_update_tree_inodes(get_file_inode);
	prog_cls_update_tree_inodes(get_file_inode);
}

#define TEST_CAN_MID_MAX 	10
#define TEST_CAN_MAX_IF_INDEX 	3
#define TEST_ACTIONS_NUM 	4
#define TEST_RULES_MAX 		10
#define TEST_MAX_UID 		5
#define TEST_MAX_PROG 		7
#define TEST_MAX_FILES		9
#define TEST_IP_ADDR_START 	0xc0a80101
#define TEST_IP_ADDR_MAX 	0xc0a80110
#define TEST_START_PORT 	5000
#define TEST_MAX_PORT 		5020

static act_t act_array[TEST_ACTIONS_NUM] = {
	{
		.name = "allow-log",
		.action_bitmap = VSENTRY_ACTION_ALLOW | VSENTRY_ACTION_LOG,
	},
	{
		.name = "allow",
		.action_bitmap = VSENTRY_ACTION_ALLOW,
	},
	{
		.name = "drop-log",
		.action_bitmap = VSENTRY_ACTION_DROP | VSENTRY_ACTION_LOG,
	},
	{
		.name = "drop",
		.action_bitmap = VSENTRY_ACTION_DROP,
	},
};

static char *prog_name[TEST_MAX_PROG] = {
	"/usr/lib/udev/cdrom_id",
	"/usr/lib/udev/ata_id",
	"/usr/bin/bash",
	"/usr/bin/ip",
	"/usr/bin/cangen",
	"/usr/bin/iperf",
	"/home/alarm/unit_test_drv",
};

static char *file_name[TEST_MAX_FILES] = {
	"/usr/lib/libc1.so",
	"/usr",
	"/usr/bin",
	"/usr/lib/libc2.so",
	"/usr/lib",
	"/usr/bin/file",
	"/home",
	"/etc",
	"/home/db.mem",
};

void unitest(void)
{
	unsigned int i, j, k;
	can_header_t can_data;

	/* set actions */
	for (i=0; i<TEST_ACTIONS_NUM; i++) {
		act_array[i].name_len = strlen(act_array[i].name);
		action_cls_add(&act_array[i]);
	}

	/* set default rules with drop-log*/
	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
		if (cls_default_action(i, &act_array[2], 0) != VSENTRY_SUCCESS)
			return;
	}

	/* set rules, uids, progs, ipproto*/
	for (i=0; i<TEST_RULES_MAX; i++) {
		for (j=0; j<CLS_TOTAL_RULE_TYPE; j++) {
			/* rules */
			if (cls_add_rule(j, i, act_array[i%TEST_ACTIONS_NUM].name,
					act_array[i%TEST_ACTIONS_NUM].name_len, 0) != VSENTRY_SUCCESS)
				return;

			/* set uids */
			for (k=0; k<TEST_MAX_UID; k++) {
				if (uid_cls_add_rule(j, i, k) != VSENTRY_SUCCESS)
					return;
			}

			/* set prog */
			for (k=0; k<TEST_MAX_PROG; k++) {
				if (prog_cls_add_rule(j, i, prog_name[k], k, strlen(prog_name[k])) != VSENTRY_SUCCESS)
					return;
			}
		}

		/* set ipproto rules */
		if (ip_proto_cls_add_rule(i, IPPROTO_TCP) != VSENTRY_SUCCESS)
			return;

		if (ip_proto_cls_add_rule(i, IPPROTO_UDP) != VSENTRY_SUCCESS)
			return;
	}

	for (j=0; j<TEST_MAX_FILES; j++) {
		file_event_t ev = {
			.mode = FILE_MODE_READ | FILE_MODE_WRITE,
			.filename = file_name[j],
			.type = FILE_TYPE_REG,
			.filename_len = vs_strlen(file_name[j]),
		};

		if (file_cls_add_rule(j, &ev) != VSENTRY_SUCCESS)
			return;
	}

	/* set can rules */
	for (j=0; j<TEST_CAN_MID_MAX; j++) {
		can_data.msg_id = j;

		for (k=0; k<TEST_CAN_MAX_IF_INDEX; k++) {
			can_data.if_index = k;

			if (can_cls_add_rule(j%TEST_RULES_MAX, &can_data, DIR_IN) != VSENTRY_SUCCESS)
				return;

			if (can_cls_add_rule(j%TEST_RULES_MAX, &can_data, DIR_OUT) != VSENTRY_SUCCESS)
				return;
		}
	}

	/* set ip rules */
	for (j=TEST_IP_ADDR_START; j<TEST_IP_ADDR_MAX; j++) {
		if (net_cls_add_rule(j%TEST_RULES_MAX, htonl(j), 0xffffffff, CLS_NET_DIR_SRC) != VSENTRY_SUCCESS)
			return;

		if (net_cls_add_rule(j%TEST_RULES_MAX, htonl(j), 0xffffffff, CLS_NET_DIR_DST) != VSENTRY_SUCCESS)
			return;
	}

	/* set port rules */
	for (j=TEST_START_PORT; j<TEST_MAX_PORT; j++) {
		if (port_cls_add_rule(j%TEST_RULES_MAX, j, IPPROTO_TCP, CLS_NET_DIR_SRC) != VSENTRY_SUCCESS)
			return;

		if (port_cls_add_rule(j%TEST_RULES_MAX, j, IPPROTO_TCP, CLS_NET_DIR_DST) != VSENTRY_SUCCESS)
			return;

		if (port_cls_add_rule(j%TEST_RULES_MAX, j, IPPROTO_UDP, CLS_NET_DIR_SRC) != VSENTRY_SUCCESS)
			return;

		if (port_cls_add_rule(j%TEST_RULES_MAX, j, IPPROTO_UDP, CLS_NET_DIR_DST) != VSENTRY_SUCCESS)
			return;
	}
}

//static void classifier_test(void)
//{
//	unsigned int i, rand_res;
//	vsentry_event_t event;
//
//	for (i=0; i< 5000; i++) {
//		rand_res = rand();
//		event.ts = i;
//		event.event_id.exec_ino = i%TEST_MAX_UID;
//		event.event_id.uid = i%TEST_MAX_UID;
//		event.dir = (rand_res%DIR_TOTAL);
//
//		/* check ip event */
//		event.ip_event.len = 10;
//
//		event.ip_event.saddr.v4addr = TEST_IP_ADDR_START + (rand_res%(TEST_IP_ADDR_MAX + 1 - TEST_IP_ADDR_START));
//		event.ip_event.daddr.v4addr = TEST_IP_ADDR_START + (rand_res%(TEST_IP_ADDR_MAX + 1 - TEST_IP_ADDR_START));
//		event.ip_event.sport = TEST_START_PORT + (rand_res%(TEST_MAX_PORT + 1 - TEST_START_PORT));
//		event.ip_event.dport = TEST_START_PORT + (rand_res%(TEST_MAX_PORT + 1 - TEST_START_PORT));
//		event.ip_event.ip_proto = IPPROTO_TCP;
//		cls_handle_event(VSENTRY_IP_EVENT, &event);
//		event.ip_event.ip_proto = IPPROTO_UDP;
//		cls_handle_event(VSENTRY_IP_EVENT, &event);
//
//		event.can_event.payload_len = 4;
//		event.can_event.can_header.if_index = rand_res%TEST_CAN_MAX_IF_INDEX;
//		event.can_event.can_header.msg_id = rand_res%TEST_CAN_MID_MAX;
//		cls_handle_event(VSENTRY_CAN_EVENT, &event);
//	}
//
//	fprintf(stdout, "DONE\n");
//}

static void vsentry_cli_help(void)
{
	fprintf(stdout, "b - break, exit program\n");
	fprintf(stdout, "a - add classifier element\n");
	fprintf(stdout, "d - delete classifier element\n");
	fprintf(stdout, "m - get/set classifier mode\n");
	fprintf(stdout, "p - print classifier db\n");
	fprintf(stdout, "t - run classifier test event\n");
	fprintf(stdout, "u - run classifier event test\n");
	fprintf(stdout, "o - run file classification optimization (reduction)\n");
	fprintf(stdout, "i - run file inode update\n");
	fprintf(stdout, "f - consolidate sub folders rules to parent folder rules\n");
	fprintf(stdout, "c - clear rule to/from rule num\n");
}

/* this function will open the dbfile. if it does not exist, it will creat it */
unsigned char pad[PAD_SIZE];
static int init_db_file(char *dbfile)
{
	struct stat sb;

	/* check if the db file exist and its size. if not, re/create the file
	 * with the heap in it */
	if ((stat(dbfile, &sb) == -1) || (sb.st_size != SHMEM_BUFFER_SIZE)) {
		int size = SHMEM_BUFFER_SIZE;

		db_file = fopen(dbfile, "w+");
		if (!db_file) {
			fprintf(stderr, "failed to create db file\n");
			return VSENTRY_ERROR;
		}

		memset(pad, 0, PAD_SIZE);

		while (size) {
			fwrite(pad, 1, PAD_SIZE, db_file);
			size -= PAD_SIZE;
		}

		fclose(db_file);

		fprintf(stdout, "created new db file %s\n", dbfile);
	}

	return VSENTRY_SUCCESS;
}

/* this function will map the dbfile to this process memory */
static int init_db_mem(char *dbfile)
{
	struct stat st;
	int fd;

	/* open (may create) the db file */
	if (init_db_file(dbfile) != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init db file\n");
		return VSENTRY_ERROR;
	}

	db_file = fopen(dbfile, "r+");
	if (!db_file) {
		fprintf(stderr, "failed to open db file %s. error %s\n",
				dbfile, strerror(errno));
		return VSENTRY_ERROR;
	}

	fseek(db_file, 0L, SEEK_SET);

	fd = fileno(db_file);
	if (fd <= 0) {
		fprintf(stderr, "failed extract dbfile fd\n");
		return VSENTRY_ERROR;
	}

	if (stat(dbfile, &st)) {
		fprintf(stderr, "failed to run stat on %s\n", dbfile);
		return VSENTRY_ERROR;
	}

	/* map file to memory */
	/* MAP_LOCKED is marked as it result an error when mapping large files */
	dbmem = mmap(NULL, st.st_size, (PROT_READ | PROT_WRITE),
		(MAP_SHARED/*| MAP_LOCKED*/ ) ,fd, 0);
	if (dbmem == MAP_FAILED) {
		fprintf(stderr, "failed to alloc dbmem. %s\n", strerror(errno));
		return VSENTRY_ERROR;
	}

	dbmem_size = st.st_size;

	fprintf(stdout, "database memory %p mmaped successfully (file %s)\n",
		dbmem, dbfile);

	return VSENTRY_SUCCESS;
}

#ifdef USE_BIN
static int init_execmem(char *execfile)
{
	struct stat st;
	FILE *bin_file = NULL;

	/* check if execfile exist */
	if (stat(execfile, &st)) {
		fprintf(stderr, "failed to run stat on %s\n", execfile);
		return VSENTRY_ERROR;
	}

	execsize = st.st_size;

	/* allocate exec memory and write the execfile to it */
	execmem = mmap(NULL, execsize, (PROT_READ|PROT_WRITE|PROT_EXEC),
		(MAP_ANON | MAP_SHARED| MAP_LOCKED) , -1, 0);
	if (!execmem) {
		fprintf(stderr, "failed to mmap\n");
		return VSENTRY_ERROR;
	}

	/* copy the bin file to the execution memory */
	bin_file = fopen(execfile, "r");
	if (!bin_file) {
		fprintf(stderr, "failed to open execfile %s. error %s\n",
				execfile, strerror(errno));
		return VSENTRY_ERROR;
	}

	if (fread(execmem, 1, execsize, bin_file) != execsize) {
		fprintf(stderr, "failed to copy bin file\n");
		return VSENTRY_ERROR;
	}

	fclose(bin_file);

	cls_event = execmem;

	fprintf(stdout, "execution memory %p - %p initialized successfully (file %s)\n",
			execmem, (void*)((unsigned int)execmem + execsize), execfile);

	return VSENTRY_SUCCESS;
}
#endif

int main(int argc, char **argv)
{
	int opt;
	int ret = VSENTRY_SUCCESS;
#ifdef USE_BIN
	char *execfile = EXEC_FILE;
#endif
	char *dbfile = DB_FILE;
	bool run = true;

	while ((opt = getopt (argc, argv, "e:f:h")) != -1) {
		switch (opt) {
#ifdef USE_BIN
		case 'e':
			execfile = optarg;
			break;
#endif
		case 'f':
			dbfile = optarg;
			break;

		case 'h':
			fprintf(stderr, "usage: %s [-e execfile] [-f dbfile] -h]\n", argv[0]);
			fprintf(stderr, "	-e execfile. specify the binfile to execute\n");
			fprintf(stderr, "	-f dbfile. specify the database file\n");
			fprintf(stderr, "	-h : print this help\n");
			exit(EXIT_SUCCESS);
			break;
		default:
			break;
		}
	}

	fprintf(stdout, "using dbfile %s\n", dbfile);
#ifdef USE_BIN
	fprintf(stdout, "using execfile %s\n", execfile);

	ret = init_execmem(execfile);
	if (ret != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to execution memory\n");
		goto exit_err;
	}
#endif

	/* open the db mem */
	ret = init_db_mem(dbfile);
	if (ret != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init db file\n");
		goto exit_err;
	}

	cls_event(VSENTRY_REGISTER_PRINTF, (void*)printf);

	/* init classifier database used by binary */
	ret = cls_event(VSENTRY_CLASIFFIER_INIT, dbmem);
	if (ret != VSENTRY_SUCCESS) {
		fprintf(stderr, "failed to init standalone classifier\n");
		goto exit_err;
	}

	while (run) {
		char input[3];
		bool add = false;

		if (fgets(input, 3, stdin) == NULL)
			continue;

		switch (input[0]) {
		case 'b':
			run = 0;
			break;

		case 'a':
		case 'd':
			if (input[0] == 'a')
				add = true;

			fprintf(stdout, "enter type (a-action, r-rule, c-can, u-uid, i-prog, n-ip, f-file, p-port, t-ipproto): ");
			if (fgets(input, 3, stdin) == NULL)
				continue;

			switch (input[0]) {
			case 'a':
				action(add);
				break;
			case 'r':
				rule(add);
				break;
			case 'c':
				can_rule(add);
				break;
			case 'u':
				uid_rule(add);
				break;
			case 'i':
				prog_rule(add);
				break;
			case 'n':
				net_rule(add);
				break;
			case 'f':
				file_rule(add);
				break;
			case 'p':
				port_rule(add);
				break;
			case 't':
				ip_proto_rule(add);
				break;
			default:
				fprintf(stderr, "invalid input\n");
				break;
			}
			break;

		case 'm':
			fprintf(stdout, "enter mode (e-enforce, p-permissive l-learn): ");
			if (fgets(input, 3, stdin) == NULL)
				continue;

			switch (input[0]) {
			case 'e':
				cls_set_mode(VSENTRY_MODE_ENFORCE);
				break;
			case 'p':
				cls_set_mode(VSENTRY_MODE_PERMISSIVE);
				break;
#ifdef ENABLE_LEARN
			case 'l':
				cls_set_mode(VSENTRY_MODE_LEARN);
				break;
#endif
			default:
				{
					int mode = cls_get_mode();
					switch (mode) {
					case VSENTRY_MODE_ENFORCE:
						fprintf(stdout, "current mode enforce\n");
						break;
					case VSENTRY_MODE_PERMISSIVE:
						fprintf(stdout, "current mode permissive\n");
						break;
#ifdef ENABLE_LEARN
					case VSENTRY_MODE_LEARN:
						fprintf(stdout, "current mode learn\n");
						break;
#endif
					default:
						fprintf(stdout, "current mode unknown\n");
						break;
					}
				};
				break;
			}
			break;

		case 't':
			fprintf(stdout, "enter type (c-can, n-net, f-file): ");
			if (fgets(input, 3, stdin) == NULL)
				continue;

			switch (input[0]) {
			case 'c':
				test_cls_can_ev();
				break;
			case 'n':
				test_cls_net_ev();
				break;
			case 'f':
				test_cls_file_ev();
				break;
			default:
				break;
			}
			break;

		case 'u':
			unitest();
//			classifier_test();
			break;

		case 'p':
			cls_print_db();
			break;

		case 'h':
			vsentry_cli_help();
			break;

		case 'o':
			trim_file_rules();
			break;
		case 'i':
			update_files_inode();
			break;
		case 'f':
			trim_file_rules_by_path();
			break;
		case 'c':
			clear_rules();
			break;
		default:
			fprintf(stderr, "invalid input (press h for help)\n");
			break;
		}
	}

exit_err:
	if (db_file) {
		fsync(fileno(db_file));
		fclose(db_file);
	}

	if (dbmem)
		munmap(dbmem, dbmem_size);

	if (execmem)
		munmap(execmem, execsize);

	exit(ret);
}

