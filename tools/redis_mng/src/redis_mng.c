#include "sr_cls_network_common.h"
#include "sr_actions_common.h"
#include "sr_msg.h"
#include "sentry.h"
#include "action.h"
#include "ip_rule.h"
#include "file_rule.h"
#include "can_rule.h"
#include "jsmn.h"
#include <string.h>
#include <ctype.h>
#include "redis_mng.h"
#include "sr_cls_wl_common.h"
#include "db_tools.h"
#include "sr_config.h"
#include "read.h"

#ifdef NO_CEF
#define REASON 		"reason" // shut up GCC
#define MESSAGE 	"msg" // shut up GCC AGAIN
#define CEF_log_event(f1, f2, f3, ...) printf(__VA_ARGS__)
#else
#include "sr_log.h"
#endif

// fixme remove
#define DEBUG
#ifdef DEBUG
#define AUTH		"AUTH"
#define DEL			"DEL"
#else
#define AUTH		"O5TBQ23IBTIGBV9WWAHTG9824G"
#define DEL			"205Y38YHBJNSNBNESROTHY309HL"
#endif
#define PASS_128	"a95qaewbe13dr68tayb45u63i8o9fepac[b]0069 \
					 ea4s1bcd7ef8g90chfbj8k40flc;02d'5/2be.45 \
					 ,4m299n41bcvc15vf5c9xe41zcb17`ef63c5425= \
					 /-.0,m7v"

#define REDIS_SERVER_STARTUP_FILENAME	"/etc/vsentry/dump.rdb.stu"
#define REDIS_SERVER_RUNNING_FILENAME	"/etc/vsentry/dump.rdb.run"

#define ENGINE		 	"engine"
#define ACTION_PREFIX   "a:"
#define LIST_PREFIX		"l:"
// rule types
#define CAN_PREFIX   	"c:"
#define NET_PREFIX    	"n:"
#define FILE_PREFIX  	"f:"
// fields
#define PROGRAM_ID 		"prog"
#define USER_ID 		"user"
#define ACTION 			"act"
#define DIRECTION		"dir"
#define INTERFACE		"intf"
#define RATE_LIMIT		"rl"
// CAN rule specific fields
#define MID 			"mid"
// IP rule specific fields
#define SRC_ADDR		"sa"
#define DST_ADDR	 	"da"
#define PROTOCOL 		"prot"
#define SRC_PORT		"sp"
#define DST_PORT	 	"dp"
#define UP_RL		 	"url"
#define DOWN_RL	 		"drl"
// file rule specific fields
#define FILENAME		"file"
#define PERMISSION	 	"perm"
// action specific fields
#define ACTION_BITMAP	"abm"
#define ACTION_LOG		"al"
//#define LOG_FACILITY	"al"
//#define LOG_SEVERITY	"ls"
#define RL_BITMAP 		"rlbm"
#define RL_LOG	 		"rll"
//#define SMS		 	"sms"
//#define EMAIL	 		"mail"

#define SYSTEM_POLICER_PREFIX   	"sp:"
#define SP_TIME 			"time"
#define SP_BYTES_READ 		"br"
#define SP_BYTES_WRITE 		"bw"
#define SP_VM_ALLOC 		"vma"
#define SP_THREADS_NO 		"tn"
#define GROUP_NAME_LEN 32
#define PROTO_MAX 8
#define PROTO_NAME_MAX 32
#define INF_MAX 8

static int redis_changes;

typedef struct group_item {
	char *name;
	struct group_item *next;
} group_item_t;

typedef struct group_db_group {
	char name[GROUP_NAME_LEN];
	struct group_db_group *next;
	group_item_t *items;
} group_db_group_t;

typedef struct {
	SR_U16  rulenum;
	//handle_rule_f_t cb;
	void (*cb)(void *data, redis_entity_type_t type, SR_32 *status);
	sr_net_item_type_t net_item_type;
	SR_U8 proto;
	SR_32 *rc;
} net_rule_cb_params_t;

typedef struct {
	SR_U16  rulenum;
	//handle_rule_f_t cb;
	void (*cb)(void *data, redis_entity_type_t type, SR_32 *status);
	sr_can_item_type_t can_item_type;
	char inf[INTERFACE_LEN];
	char dir[8];
	SR_32 *rc;
} can_rule_cb_params_t;

typedef struct {
	SR_U16  rulenum;
	//handle_rule_f_t cb;
	void (*cb)(void *data, redis_entity_type_t type, SR_32 *status);
	sr_file_item_type_t file_item_type;
	SR_32 *rc;
} file_rule_cb_params_t;

typedef struct {
	SR_32 num_of_protos;
	char protocols[PROTO_MAX][PROTO_NAME_MAX];
} handle_proto_group_cb_params_t;

typedef struct {
	SR_32 num_of_interfaces;
	char interfaces[INF_MAX][INTERFACE_LEN];
} handle_inf_group_cb_params_t;

static group_db_group_t *group_db[LIST_TYPE_MAX + 1];

static SR_32 exec_for_all_group(list_type_e type, char *group, SR_32 (*cb)(char *item, void *data), void *param);

static char *get_field(char *field, int n, redisReply *reply)
{
	int i;

	for (i = 0; i < n - 1; i += 2) {
		if (!strcmp(reply->element[i]->str, field))
			return reply->element[i + 1]->str;
	}
	
	return NULL;
}

redisContext *redis_mng_session_start(void/*SR_BOOL is_tcp*/)
{ 
	redisContext *c;
#ifndef DEBUG
	redisReply *reply;
#endif
	// choose connection type
//	if (is_tcp)
//		c = redisConnect("127.0.0.1", 6379);
//	else // unix sockets
	c = redisConnectUnix("/dev/redis.sock");
	// verify success here, else return NULL
	if (c == NULL || c->err) {
			printf("ERROR: %s failed, ret %d\n", /*is_tcp ? "redisConnect" :*/ "redisConnectUnix", c ? c->err : 0);
			return NULL;
	}
#ifndef DEBUG
	// authenticate
	reply = redisCommand(c,"%s %s", AUTH, PASS_128);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS || strcmp(reply->str, "OK")) {
		printf("ERROR: redis_mng_session_start auth failed, %d, %s\n", reply ? reply->type : -1, reply->str ? reply->str : "NULL");
		freeReplyObject(reply);
		redisFree(c);
		return NULL;
	}
	freeReplyObject(reply);
#endif
	redis_changes = 0;
	return c;
}

void redis_mng_session_end(redisContext *c)
{
	redisFree(c);
}

void file_op_convert(SR_U8 file_op, char *perms)
{
	//SR_U8 res = 0;

	if (file_op & SR_FILEOPS_READ) 
		//res |= 4;
		sprintf(perms, "R");
	if (file_op & SR_FILEOPS_WRITE) 
		//res |= 2;
		sprintf(perms, "W");
	if (file_op & SR_FILEOPS_EXEC) 
		//res |= 1;
		sprintf(perms, "X");

	//sprintf(perms, "77%d", res);
}

SR_32 print_action(void *data)
{
	sr_action_record_t *action = (sr_action_record_t *)data;
	char log_target[LOG_TARGET_LEN], rl_log_target[LOG_TARGET_LEN];
	
	if (!action) return SR_ERROR;

	strncpy(log_target, get_action_log_facility_string(action->log_target), LOG_TARGET_LEN);
	strncpy(rl_log_target, get_action_log_facility_string(action->rl_log_target), LOG_TARGET_LEN);

	printf("%s %d %s %d %s \n",
		action->name,
		action->actions_bitmap,
		log_target,
		action->rl_actions_bitmap,
		rl_log_target);

	return SR_SUCCESS;
}

SR_32 redis_mng_exec_all_actions(redisContext *c, SR_32 (*cb)(void *data))
{
	int i, j;
	redisReply *reply;
	redisReply **replies;
	sr_action_record_t action = {};
	char *field;

	if (!cb) return SR_ERROR;

	// get all keys
	reply = redisCommand(c,"KEYS %s*", ACTION_PREFIX);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_actions failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	replies = malloc(sizeof(redisReply*) * reply->elements);
	if (!replies) {
		printf("ERROR: redis_mng_print_actions allocation failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);

	for (i = 0; i < (int)reply->elements; i++) {
		if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
			printf("ERROR: redisGetReply %d failed\n", i);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->elements != ACTION_FIELDS) {
			printf("ERROR: ACTION redisGetReply %d length is wrong %d instead of 8\n", i, (int)replies[i]->elements);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}

		strncpy(action.name, reply->element[i]->str + strlen(ACTION_PREFIX), MAX_ACTION_NAME);
		field = get_field(ACTION_BITMAP, replies[i]->elements, replies[i]);
		action.actions_bitmap = field ? atoi(field) : 0;
		field = get_field(ACTION_LOG, replies[i]->elements, replies[i]);
		action.log_target = get_log_facility_enum(field);
		field = get_field(RL_BITMAP, replies[i]->elements, replies[i]);
		action.rl_actions_bitmap = field ? atoi(field) : 0;
		field = get_field(RL_LOG, replies[i]->elements, replies[i]);
		action.rl_log_target = get_log_facility_enum(field);
		if (cb(&action) != SR_SUCCESS) {
			printf("ERROR: Failed run cb for action :%s \n", reply->element[i]->str + strlen(ACTION_PREFIX));
		}
	}

	// free replies
	for (i = 0; i < reply->elements; i++)
		freeReplyObject(replies[i]);
	free(replies);
	freeReplyObject(reply);

	return SR_SUCCESS;
}

SR_32 redis_mng_print_actions(redisContext *c) {
	return redis_mng_exec_all_actions(c, print_action);
}

static SR_32 print_value(char *val)
{
	printf("%-64s ", val);

	return SR_SUCCESS;
}

SR_32 redis_mng_exec_list(redisContext *c, list_type_e type, char *name, SR_32 (*cb)(char *val))
{
	int j;
	redisReply *reply;

	if (!name) {
		printf("ERROR: redis_mng_print_list list name is NULL\n");
		return SR_ERROR;
	}
	if (!cb) return SR_ERROR;

	// get specific key
	reply = redisCommand(c,"LRANGE %d%s%s 0 -1", type, LIST_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_list failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (j = 0; j < reply->elements; j++) {
		cb(reply->element[j]->str);
	}

	freeReplyObject(reply);

	return SR_SUCCESS;
}

SR_32 redis_mng_print_list(redisContext *c, list_type_e type, char *name)
{
	redis_mng_exec_list(c, type, name, print_value);
	printf("\n");

	return SR_SUCCESS;
}

static SR_32 print_list_name(list_type_e type, char *name)
{
	printf("%s\n", name);

	return SR_SUCCESS;
}

SR_32 redis_mng_exec_all_list_names(redisContext *c, list_type_e type, SR_32 (*cb)(list_type_e type, char *name))
{
	int i;
	redisReply *reply;

	if (!cb) return SR_ERROR;

	// get all keys
	reply = redisCommand(c,"KEYS %d%s*", type, LIST_PREFIX);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_all_list_names failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		cb(type, reply->element[i]->str);

	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_print_all_list_names(redisContext *c, list_type_e type)
{
	return redis_mng_exec_all_list_names(c, type, print_list_name);
}

static SR_32 print_can(SR_32 num, void *rule)
{
	redis_mng_can_rule_t *can_rule = (redis_mng_can_rule_t *)rule;

	printf("%d %s %s %s %s %s %s \n", num, can_rule->mid, can_rule->dir, can_rule->interface, can_rule->exec, can_rule->user, can_rule->action);

	return SR_SUCCESS;
}

static SR_32 print_ip(SR_32 num, void *rule)
{
	redis_mng_net_rule_t *net_rule = (redis_mng_net_rule_t *)rule;

	printf("%d %-32s %-32s %s %s %s %-24.24s %-24.24s %s %s %s \n",
		num, 
		net_rule->src_addr_netmask,
		net_rule->dst_addr_netmask,
		net_rule->proto,
		net_rule->src_port,
		net_rule->dst_port,
		net_rule->exec,
		net_rule->user,
		net_rule->up_rl,
		net_rule->down_rl,
		net_rule->action);

	return SR_SUCCESS;
}

static SR_32 print_file(SR_32 num, void *rule)
{
	redis_mng_file_rule_t *file_rule = (redis_mng_file_rule_t *)rule;
	printf("%-6d %-88.88s %-4s %-24.24s %-24.24s %-24.24s\n",
		num,
		file_rule->file_name,
		file_rule->file_op,
		file_rule->exec,
		file_rule->user,
		file_rule->action);

	return SR_SUCCESS;
}

SR_32 redis_mng_print_rules(redisContext *c, rule_type_t type, SR_32 rule_id_start, SR_32 rule_id_end)
{
	switch (type) {
		case RULE_TYPE_CAN:
			return redis_mng_exec_all_rules(c, type, rule_id_start, rule_id_end, print_can);
		case RULE_TYPE_IP:
			return redis_mng_exec_all_rules(c, type, rule_id_start, rule_id_end, print_ip);
		case RULE_TYPE_FILE:
			return redis_mng_exec_all_rules(c, type, rule_id_start, rule_id_end, print_file);
		default:
			printf("ERROR: exec all rules - invalid rule type :%d \n", type);
			return SR_ERROR;
			
	}

	return SR_SUCCESS;
}

SR_32 redis_mng_exec_all_rules(redisContext *c, rule_type_t type, SR_32 rule_id_start, SR_32 rule_id_end, SR_32 (*cb)(SR_32 rule_num, void *rule))
{
	int i, j, num;
	redisReply *reply;
	redisReply **replies;
	void *rule;
	redis_mng_can_rule_t can_rule;
	redis_mng_net_rule_t ip_rule;
	redis_mng_file_rule_t file_rule;

	if (!cb) return SR_ERROR;

	// get all keys
	reply = redisCommand(c,"KEYS %s*", type == RULE_TYPE_CAN ? CAN_PREFIX : (type == RULE_TYPE_IP ? NET_PREFIX : FILE_PREFIX));
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_rules failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	replies = malloc(sizeof(redisReply*) * reply->elements);
	if (!replies) {
		printf("ERROR: redis_mng_print_rules allocation failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);

	for (i = 0; i < (int)reply->elements; i++) {
		if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
			printf("ERROR: redisGetReply %d failed\n", i);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}

		switch (type) {
			case RULE_TYPE_CAN:
				num = atoi(reply->element[i]->str + strlen(CAN_PREFIX));
				memset(&can_rule, 0, sizeof(can_rule));
				can_rule.mid = get_field(MID, replies[i]->elements, replies[i]);
				can_rule.dir = get_field(DIRECTION, replies[i]->elements, replies[i]);
				can_rule.interface = get_field(INTERFACE, replies[i]->elements, replies[i]);
				can_rule.exec = get_field(PROGRAM_ID, replies[i]->elements, replies[i]);
				can_rule.user = get_field(USER_ID, replies[i]->elements, replies[i]);
				can_rule.action = get_field(ACTION, replies[i]->elements, replies[i]);
				rule = &can_rule;
				break;
			case RULE_TYPE_IP:
				num = atoi(reply->element[i]->str + strlen(NET_PREFIX));
				ip_rule.src_addr_netmask = get_field(SRC_ADDR, replies[i]->elements, replies[i]);
				ip_rule.dst_addr_netmask = get_field(DST_ADDR, replies[i]->elements, replies[i]);
				ip_rule.proto = get_field(PROTOCOL, replies[i]->elements, replies[i]);
				ip_rule.src_port = get_field(SRC_PORT, replies[i]->elements, replies[i]);
				ip_rule.dst_port = get_field(DST_PORT, replies[i]->elements, replies[i]);
				ip_rule.exec = get_field(PROGRAM_ID, replies[i]->elements, replies[i]);
				ip_rule.user = get_field(USER_ID, replies[i]->elements, replies[i]);
				ip_rule.up_rl = get_field(UP_RL, replies[i]->elements, replies[i]);
				ip_rule.down_rl = get_field(DOWN_RL, replies[i]->elements, replies[i]);
				ip_rule.action = get_field(ACTION, replies[i]->elements, replies[i]);
				rule = &ip_rule;
				break;
			case RULE_TYPE_FILE:
				num = atoi(reply->element[i]->str + strlen(FILE_PREFIX));
				file_rule.file_name = get_field(FILENAME, replies[i]->elements, replies[i]);
				file_rule.file_op = get_field(PERMISSION, replies[i]->elements, replies[i]);
				file_rule.exec = get_field(PROGRAM_ID, replies[i]->elements, replies[i]);
				file_rule.user = get_field(USER_ID, replies[i]->elements, replies[i]);
				file_rule.action = get_field(ACTION, replies[i]->elements, replies[i]);
				rule = &file_rule;
				break;
			default:
				printf("ERROR: exec all rules - invalid rule type :%d \n", type);
				return SR_ERROR;
		}
		if (!(((rule_id_start == -1) && (rule_id_end == -1)) || ((num >= rule_id_start) && (num <= rule_id_end))))
			continue;
		if (cb(num, rule) != SR_SUCCESS) {
			printf("ERROR: exec all rules - failed for  rule :%d \n", num);
		}
	}

	// free replies
	for (i = 0; i < reply->elements; i++)
		freeReplyObject(replies[i]);
	free(replies);
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_clean_db(redisContext *c)
{
	redisReply *reply;
	reply = redisCommand(c,"FLUSHDB");
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: flush db failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

static char *get_group_name(char *field)
{
	SR_U32 i, n;

	if (!field) return NULL;
	
	n = strlen(field) - strlen(LIST_PREFIX);
	for (i = 1; i < n; i++) {
		if (!memcmp(field + 1, LIST_PREFIX, strlen(LIST_PREFIX)))
			return field + i + strlen(LIST_PREFIX);
	}
	
	return NULL;
}

static list_type_e get_list_id(char *field)
{
	char list_id[8] = {}, i;
	int id;
	
	if (!field) return LIST_NONE;

	for (i = 1; i < strlen(field) - strlen(LIST_PREFIX); i++) {
		if (!memcmp(field + i, LIST_PREFIX, strlen(LIST_PREFIX))) {
			memcpy(list_id, field, i);
			break;
		}
	}
	
	if (!*list_id) return LIST_NONE;
	id = atoi(list_id);

	return id < LIST_TYPE_MAX + 1 ? id : LIST_NONE;
} 

static SR_32 load_can_cb(char *item, void *param)
{
	can_rule_cb_params_t *can_rule_params = (can_rule_cb_params_t *)param;
	sr_can_record_t can_rule = {};


	can_rule.rulenum = can_rule_params->rulenum;
	can_rule.can_item.can_item_type = can_rule_params->can_item_type;
	switch (can_rule_params->can_item_type) {
		case CAN_ITEM_MSG:
			can_rule.can_item.u.msg.id = strtol(item, NULL, 16);
			strncpy(can_rule.can_item.u.msg.dir, can_rule_params->dir, sizeof(can_rule.can_item.u.msg.dir));
			strncpy(can_rule.can_item.u.msg.inf, can_rule_params->inf, sizeof(can_rule.can_item.u.msg.inf));
			break;
		case CAN_ITEM_PROGRAM:
			strncpy(can_rule.can_item.u.program, item, sizeof(can_rule.can_item.u.program));
			break;
		case CAN_ITEM_USER:
			strncpy(can_rule.can_item.u.user, item, sizeof(can_rule.can_item.u.user));
			break;
		default:
			printf("ERROR load_can_cb invalid item type:%d \n", can_rule_params->can_item_type);
			return SR_ERROR;
	}
	can_rule_params->cb(&can_rule, ENTITY_TYPE_CAN_RULE, can_rule_params->rc);
#ifdef DEBUG
	printf("-------------ZZZZZZZZZZZZZZZZZZZZZZZZZZz in load_can_cb rule:%d type:%d item:%s dir:%s: inf:%s:  rc:%d \n",
			can_rule.rulenum, can_rule_params->can_item_type, item, can_rule.can_item.u.msg.dir, can_rule.can_item.u.msg.inf, *(can_rule_params->rc));
			
#endif

	return SR_SUCCESS;
}

static SR_32 handle_list_can(SR_32 rule_id, sr_can_item_type_t type, handle_rule_f_t cb, SR_32 list_id, char *group, char *inf, char *dir)
{
	SR_32 rc = SR_SUCCESS;
	can_rule_cb_params_t params;

	params.rulenum = rule_id;
	params.cb = cb;
	params.can_item_type = type;
	if (inf)
		strncpy(params.inf, inf, sizeof(params.inf));
	if (dir)
		strncpy(params.dir, dir, sizeof(params.dir));
	params.rc = &rc;
	exec_for_all_group(list_id, get_group_name(group), load_can_cb, &params);

	if (rc != SR_SUCCESS) {
		printf("ERROR: handle_list_net field for list:%d group:%s\n", list_id, group);
	}

	return rc;
}

static SR_32 handle_inf_group_cb(char *item, void *param)
{
	handle_inf_group_cb_params_t *cb_params = (handle_inf_group_cb_params_t *)param;

	strncpy(cb_params->interfaces[cb_params->num_of_interfaces], item, INTERFACE_LEN);
	++(cb_params->num_of_interfaces);

	return SR_SUCCESS;
}

static SR_32 handle_can_ids(SR_U16 rule_id, char *mid, char *dir, char *inf, handle_rule_f_t cb)
{
	SR_32 list_id, i, rc;
	handle_inf_group_cb_params_t inf_params = {};
	sr_can_record_t can_rule = {};

	can_rule.rulenum = rule_id;
	can_rule.can_item.can_item_type = CAN_ITEM_MSG;

	list_id = get_list_id(inf);
	if (list_id == LIST_NONE) {
		inf_params.num_of_interfaces = 1;
		strncpy(inf_params.interfaces[0], inf, INTERFACE_LEN);
	} else {
		exec_for_all_group(list_id, get_group_name(inf), handle_inf_group_cb, &inf_params);
	}
	
	for (i = 0; i < inf_params.num_of_interfaces; i++) {
		list_id = get_list_id(mid);
		if (list_id == LIST_NONE) {
			can_rule.can_item.u.msg.id = strtol(mid, NULL, 16);
			strncpy(can_rule.can_item.u.msg.dir, dir, DIR_LEN);
			strncpy(can_rule.can_item.u.msg.inf, inf_params.interfaces[i], INTERFACE_LEN);
			cb(&can_rule, ENTITY_TYPE_CAN_RULE, &rc);
			if (rc != SR_SUCCESS) return rc;
		} else {
			if ((rc = handle_list_can(rule_id, CAN_ITEM_MSG, cb, list_id, mid, inf_params.interfaces[i], dir)) != SR_SUCCESS)
				return rc;
		}
	}

	return SR_SUCCESS;
}

static SR_32 load_can(SR_32 rule_id, SR_32 n, redisReply *reply, handle_rule_f_t cb)
{
	SR_32 rc = SR_SUCCESS, list_id;
	sr_can_record_t can_rule = {};
	char *field;

	can_rule.rulenum = rule_id;

	field = get_field(ACTION, n, reply);
	can_rule.can_item.can_item_type = CAN_ITEM_ACTION;
	strncpy(can_rule.can_item.u.action, field, MAX_ACTION_NAME);
	cb(&can_rule, ENTITY_TYPE_CAN_RULE, &rc);
	if (rc != SR_SUCCESS) return rc;

	if ((rc = handle_can_ids(rule_id, get_field(MID, n, reply), get_field(DIRECTION, n, reply), get_field(INTERFACE, n, reply), cb)) != SR_SUCCESS) 
		return rc;

	field = get_field(PROGRAM_ID, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		can_rule.can_item.can_item_type = CAN_ITEM_PROGRAM;
		strncpy(can_rule.can_item.u.program, field, MAX_PATH);
		cb(&can_rule, ENTITY_TYPE_CAN_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_can(rule_id, CAN_ITEM_PROGRAM, cb, list_id, field, NULL, NULL)) != SR_SUCCESS)
			return rc;
	}

	field = get_field(USER_ID, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		can_rule.can_item.can_item_type = CAN_ITEM_USER;
		strncpy(can_rule.can_item.u.user, field, MAX_USER_NAME);
		cb(&can_rule, ENTITY_TYPE_CAN_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_can(rule_id, CAN_ITEM_USER, cb, list_id, field, NULL, NULL)) != SR_SUCCESS)
			return rc;
	}

	return rc;
}

static SR_32 load_file_cb(char *item, void *param)
{
	file_rule_cb_params_t *file_rule_params = (file_rule_cb_params_t *)param;
	sr_file_record_t file_rule = {};

	file_rule.rulenum = file_rule_params->rulenum;
	file_rule.file_item.file_item_type = file_rule_params->file_item_type;
	switch (file_rule_params->file_item_type) {
		case FILE_ITEM_FILENAME:
			strncpy(file_rule.file_item.u.filename, item, sizeof(file_rule.file_item.u.filename));
			break;
		case FILE_ITEM_PROGRAM:
			strncpy(file_rule.file_item.u.program, item, sizeof(file_rule.file_item.u.program));
			break;
		case FILE_ITEM_USER:
			strncpy(file_rule.file_item.u.user, item, sizeof(file_rule.file_item.u.user));
			break;
		default:
			printf("ERROR load_file_cb invalid item type:%d \n", file_rule_params->file_item_type);
			return SR_ERROR;
	}
	file_rule_params->cb(&file_rule, ENTITY_TYPE_FILE_RULE, file_rule_params->rc);
#ifdef DEBUG
	printf("-------------ZZZZZZZZZZZZZZZZZZZZZZZZZZz in load_file_cb rule:%d type:%d item:%s rc:%d \n",
			file_rule.rulenum, file_rule_params->file_item_type, item, *(file_rule_params->rc));
			
#endif

	return *(file_rule_params->rc);
}


static SR_32 handle_list_file(SR_32 rule_id, sr_file_item_type_t type, handle_rule_f_t cb, SR_32 list_id, char *group)
{
	SR_32 rc = SR_SUCCESS;
	file_rule_cb_params_t params;

	params.rulenum = rule_id;
	params.cb = cb;
	params.file_item_type = type;
	params.rc = &rc;
	exec_for_all_group(list_id, get_group_name(group), load_file_cb, &params);

	if (rc != SR_SUCCESS) {
		printf("ERROR: handle_list_net field for list:%d group:%s\n", list_id, group);
	}

	return rc;
}

static SR_32 load_file(SR_32 rule_id, SR_32 n, redisReply *reply, handle_rule_f_t cb)
{
	SR_32 rc = SR_SUCCESS, list_id;
	sr_file_record_t file_rule = {};
	char *field;

	file_rule.rulenum = rule_id;

	field = get_field(ACTION, n, reply);
	file_rule.file_item.file_item_type = FILE_ITEM_ACTION;
	strncpy(file_rule.file_item.u.action, field, MAX_ACTION_NAME);
	cb(&file_rule, ENTITY_TYPE_FILE_RULE, &rc);
	if (rc != SR_SUCCESS) return rc;

	field = get_field(FILENAME, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		file_rule.file_item.file_item_type = FILE_ITEM_FILENAME;
		strncpy(file_rule.file_item.u.filename, field, MAX_PATH);
		cb(&file_rule, ENTITY_TYPE_FILE_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_file(rule_id, FILE_ITEM_FILENAME, cb, list_id, field)) != SR_SUCCESS)
			return rc;
	}

	field = get_field(PERMISSION, n, reply);
	file_rule.file_item.file_item_type = FILE_ITEM_PERM;
	strncpy(file_rule.file_item.u.perm, field, MAX_PATH);
	cb(&file_rule, ENTITY_TYPE_FILE_RULE, &rc);
	if (rc != SR_SUCCESS) return rc;

	field = get_field(PROGRAM_ID, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		file_rule.file_item.file_item_type = FILE_ITEM_PROGRAM;
		strncpy(file_rule.file_item.u.program, field, MAX_PATH);
		cb(&file_rule, ENTITY_TYPE_FILE_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_file(rule_id, FILE_ITEM_PROGRAM, cb, list_id, field)) != SR_SUCCESS)
			return rc;
	}

	field = get_field(USER_ID, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		file_rule.file_item.file_item_type = FILE_ITEM_USER;
		strncpy(file_rule.file_item.u.user, field, MAX_USER_NAME);
		cb(&file_rule, ENTITY_TYPE_FILE_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_file(rule_id, FILE_ITEM_USER, cb, list_id, field)) != SR_SUCCESS)
			return rc;
	}

	return rc;
}

static SR_32 load_net_cb(char *item, void *param)
{
	net_rule_cb_params_t *net_rule_params = (net_rule_cb_params_t *)param;
	sr_net_record_t net_rule = {};

	net_rule.rulenum = net_rule_params->rulenum;
	net_rule.net_item.net_item_type = net_rule_params->net_item_type;
	switch (net_rule_params->net_item_type) {
		case NET_ITEM_SRC_ADDR:
			strncpy(net_rule.net_item.u.src_addr, item, MAX_ADDR_LEN);
			break;
		case NET_ITEM_DST_ADDR:
			strncpy(net_rule.net_item.u.dst_addr, item, MAX_ADDR_LEN);
			break;
		case NET_ITEM_PROTO:
			net_rule.net_item.u.proto = get_ip_proto_code(item);
			break;
		case NET_ITEM_SRC_PORT:
		case NET_ITEM_DST_PORT:
			net_rule.net_item.u.port.proto = net_rule_params->proto;
			net_rule.net_item.u.port.port = atoi(item);
			break;
		case NET_ITEM_PROGRAM:
			strncpy(net_rule.net_item.u.program, item, MAX_PATH);
			break;
		case NET_ITEM_USER:
			strncpy(net_rule.net_item.u.program, item, MAX_USER_NAME);
			break;
		default:
			printf("ERROR load_net_cb invalid item type:%d \n", net_rule_params->net_item_type);
			return SR_ERROR;
	}
	net_rule_params->cb(&net_rule, ENTITY_TYPE_IP_RULE, net_rule_params->rc);
#ifdef DEBUG
	printf("-------------ZZZZZZZZZZZZZZZZZZZZZZZZZZz in load_net_cb rule:%d type:%d proto:%d item:%s rc:%d \n", net_rule.rulenum, net_rule_params->net_item_type, net_rule_params->proto, 
			item, *(net_rule_params->rc));
#endif

	return SR_SUCCESS;
}

static SR_32 handle_port_group_cb(char *item, void *param)
{
	handle_proto_group_cb_params_t *cb_params = (handle_proto_group_cb_params_t *)param;

	strncpy(cb_params->protocols[cb_params->num_of_protos], item, PROTO_NAME_MAX);
	++(cb_params->num_of_protos);

	return SR_SUCCESS;
}

static SR_32 handle_list_net(SR_32 rule_id, sr_net_item_type_t type, handle_rule_f_t cb, SR_32 list_id, char *group, SR_U8 proto)
{
	net_rule_cb_params_t params;
	SR_32 rc = SR_SUCCESS;

	params.proto = proto;
	params.rulenum = rule_id;
	params.cb = cb;
	params.net_item_type = type;
	params.rc = &rc;
	exec_for_all_group(list_id, get_group_name(group), load_net_cb, &params);

	if (rc != SR_SUCCESS) {
		printf("ERROR: handle_list_net field for list:%d group:%s\n", list_id, group);
	}

	return rc;
}

static SR_32 handle_port(SR_32 rule_id, char *ip_proto, handle_rule_f_t cb, char *port, sr_net_item_type_t type)
{
	SR_32 list_id, rc;
	sr_net_record_t net_rule = {};

	list_id = get_list_id(port);
	if (list_id == LIST_NONE) {
		net_rule.rulenum = rule_id;
		net_rule.net_item.net_item_type = type;
		net_rule.net_item.u.port.proto = get_ip_proto_code(ip_proto);
		net_rule.net_item.u.port.port = atoi(port);
		cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_net(rule_id, type, cb, list_id, port, get_ip_proto_code(ip_proto))) != SR_SUCCESS)
			return rc;
	}

	return SR_SUCCESS;
}

static SR_32 handle_prots(SR_32 rule_id, char *ip_proto, handle_rule_f_t cb, char *src_port, char *dst_port) 
{
	SR_32 list_id, i, rc;
	handle_proto_group_cb_params_t proto_params = {};

	list_id = get_list_id(ip_proto);
        if (list_id == LIST_NONE) {
		proto_params.num_of_protos = 1;
		strncpy(proto_params.protocols[0], ip_proto, PROTO_NAME_MAX);
	} else {
		exec_for_all_group(list_id, get_group_name(ip_proto), handle_port_group_cb, &proto_params);
	}

	for (i = 0; i < proto_params.num_of_protos; i++) {
		if ((rc = handle_port(rule_id, proto_params.protocols[i], cb, src_port, NET_ITEM_SRC_PORT)) != SR_SUCCESS)
			return rc;
		if ((rc = handle_port(rule_id, proto_params.protocols[i], cb, dst_port, NET_ITEM_DST_PORT)) != SR_SUCCESS)
			return rc;
	}

	return SR_SUCCESS;
}

static SR_32 load_net(SR_32 rule_id, SR_32 n, redisReply *reply, handle_rule_f_t cb)
{
	SR_32 rc = SR_SUCCESS, list_id, proto_list_id;
	sr_net_record_t net_rule = {};
	char *field, ip_proto_name[GROUP_NAME_LEN];

	net_rule.rulenum = rule_id;

	field = get_field(ACTION, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_ACTION;
	strncpy(net_rule.net_item.u.action, field, MAX_ACTION_NAME);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
	if (rc != SR_SUCCESS) return rc;

	field = get_field(SRC_ADDR, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		net_rule.net_item.net_item_type = NET_ITEM_SRC_ADDR;
		strncpy(net_rule.net_item.u.src_addr, field, MAX_ADDR_LEN);
		cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_net(rule_id, NET_ITEM_SRC_ADDR, cb, list_id, field, 0)) != SR_SUCCESS)
			return rc;
	}

	field = get_field(DST_ADDR, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		net_rule.net_item.net_item_type = NET_ITEM_DST_ADDR;
		strncpy(net_rule.net_item.u.dst_addr, field, MAX_ADDR_LEN);
		cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else  {
		if ((rc = handle_list_net(rule_id, NET_ITEM_DST_ADDR, cb, list_id, field, 0)) != SR_SUCCESS)
			return rc;
	}

	field = get_field(PROTOCOL, n, reply);
	strncpy(ip_proto_name, field, sizeof(ip_proto_name));
	proto_list_id = get_list_id(field);
	if (proto_list_id == LIST_NONE) {
		net_rule.net_item.net_item_type = NET_ITEM_PROTO;
		net_rule.net_item.u.proto = get_ip_proto_code(field);
		cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_net(rule_id, NET_ITEM_PROTO, cb, proto_list_id, field, 0)) != SR_SUCCESS)
			return rc;
	}

	if (handle_prots(rule_id, ip_proto_name, cb, get_field(SRC_PORT, n, reply), get_field(DST_PORT, n, reply)) != SR_SUCCESS) {
		printf("ERROR : handle_ports faield \n");
		return rc;
	}

	field = get_field(UP_RL, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_UP_RL;
	net_rule.net_item.u.up_rl = atoi(field);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
	if (rc != SR_SUCCESS) return rc;

	field = get_field(DOWN_RL, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_DOWN_RL;
	net_rule.net_item.u.down_rl = atoi(field);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
	if (rc != SR_SUCCESS) return rc;

	field = get_field(PROGRAM_ID, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		net_rule.net_item.net_item_type = NET_ITEM_PROGRAM;
		strncpy(net_rule.net_item.u.program, field, MAX_PATH);
		cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_net(rule_id, NET_ITEM_PROGRAM, cb, list_id, field, 0)) != SR_SUCCESS)
			return rc;
	}

	field = get_field(USER_ID, n, reply);
	list_id = get_list_id(field);
	if (list_id == LIST_NONE) {
		net_rule.net_item.net_item_type = NET_ITEM_USER;
		strncpy(net_rule.net_item.u.user, field, MAX_USER_NAME);
		cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
		if (rc != SR_SUCCESS) return rc;
	} else {
		if ((rc = handle_list_net(rule_id, NET_ITEM_USER, cb, list_id, field, 0)) != SR_SUCCESS)
			return rc;
	}

	return rc;
}

static SR_BOOL is_supported(char *name) {
	return (!memcmp(name, CAN_PREFIX, strlen(CAN_PREFIX)) ||
		!memcmp(name, NET_PREFIX, strlen(NET_PREFIX)) ||
		!memcmp(name, FILE_PREFIX, strlen(FILE_PREFIX)) ||
		!memcmp(name, ACTION_PREFIX, strlen(ACTION_PREFIX)));
}

/*
typedef struct group_item {
	char *name;
	struct group_db *next;
} group_item_t;

typedef struct group_db_group {
	char name[GROUP_NAME_LEN];
	struct group_db_group *next;
	group_item_t *items;
} group_db_group_t;

*/

static void print_groups_db(void)
{
	list_type_e type;
	group_db_group_t *group_iter;
	group_item_t *item_iter;

	for (type = LIST_TYPE_MIN; type <= LIST_TYPE_MAX; type++) {
		printf(" Type:%d \n", type);
		for (group_iter = group_db[type]; group_iter; group_iter = group_iter->next)  {
			printf("  group :%s \n", group_iter->name);
			for (item_iter = group_iter->items; item_iter; item_iter = item_iter->next)
				printf("      item :%s: \n", item_iter->name);
		}
	}
}

static SR_32 load_list_names(list_type_e type, char *name)
{
	group_db_group_t *new_group;
	char type_str[16];

	snprintf(type_str, sizeof(type_str), "%d", type);
	if (!(new_group = calloc(sizeof(group_db_group_t), 1))) {
		printf("Error malloc got new group!\n");
		return SR_ERROR;
	}
	strncpy(new_group->name, name + strlen(type_str) + strlen(LIST_PREFIX), GROUP_NAME_LEN);
	new_group->next = group_db[type];
	group_db[type] = new_group;
	
	return SR_SUCCESS;
}

static group_item_t **g_item_p;

static SR_32 add_value_to_list(char *value)
{
	group_item_t *new_item;

	if (!(new_item = calloc(sizeof(group_item_t), 1))) {
		printf("Error malloc new item!\n");
		return SR_ERROR;
	}

	if (!(new_item->name = strdup(value))) {
		free(new_item);
		printf("Error strdup got new item!\n");
		return SR_ERROR;
	}
	new_item->next = *g_item_p;
	*g_item_p = new_item;
	g_item_p = &(new_item->next);

	return SR_SUCCESS;
}

static SR_32 load_all_groups(redisContext *c)
{
	list_type_e type;
	group_db_group_t *g_iter;

	for (type = LIST_TYPE_MIN; type <= LIST_TYPE_MAX; type++) {
		if (redis_mng_exec_all_list_names(c, type, load_list_names)) {
			printf("Error redis_mng_exec_all_list_names\n");
			return SR_ERROR;
		}
	}

	for (type = LIST_TYPE_MIN; type <= LIST_TYPE_MAX; type++) {
		for (g_iter = group_db[type]; g_iter; g_iter = g_iter->next)  {
			g_item_p = &(g_iter->items);
			redis_mng_exec_list(c, type, g_iter->name, add_value_to_list);
		}
	}
	
	return SR_SUCCESS;
}

static void cleanup_groups()
{
	list_type_e type;
	group_db_group_t *group_iter, *del_group;
	group_item_t *item_iter, *del_item;

	for (type = LIST_TYPE_MIN; type <= LIST_TYPE_MAX; type++) {
		for (group_iter = group_db[type]; group_iter; )  {
			for (item_iter = group_iter->items; item_iter; ) {
				free(item_iter->name);
				del_item = item_iter;
				item_iter = item_iter->next;
				free(del_item);
			}
			del_group = group_iter;
			group_iter = group_iter->next;
			free(del_group);
		}
		group_db[type] = NULL;
	}
}

static SR_32 exec_for_all_group(list_type_e type, char *group, SR_32 (*cb)(char *item, void *data), void *param)
{
	group_db_group_t *group_iter;
	group_item_t *item_iter;

	if (!cb) return SR_ERROR;

	for (group_iter = group_db[type]; group_iter && strcmp(group_iter->name, group); group_iter = group_iter->next);
	if (!group_iter) {
		printf("Error: group name not found\n");
		return SR_ERROR;
	}
	
	for (item_iter = group_iter->items; item_iter; item_iter = item_iter->next) {
		if (cb(item_iter->name, param) != SR_SUCCESS) {	
			printf("ERROR : exec_for_all_group cb failed \n");
			return SR_ERROR;
		}
	}

	return SR_SUCCESS;
}

SR_32 redis_mng_load_db(redisContext *c, int pipelined, handle_rule_f_t cb_func)
{
	int i, j;
	redisReply *reply;
	redisReply **replies;
	SR_32 rc = SR_SUCCESS;

	// get all keys
	reply = redisCommand(c,"KEYS *");
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_load_db failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
#ifdef DEBUG
	printf("Redis has %d keys\n", (int)reply->elements);
#endif

	load_all_groups(c);
#ifdef DEBUG
	printf(">>> print group db !!:\n");
	print_groups_db();
#endif

	if (!pipelined) {
		printf("ERROR : only pipelin is supprted\n");
		rc = SR_ERROR;
		goto out;
	}
	
	replies = calloc(sizeof(redisReply*) * reply->elements, 1);
	if (!replies) {
		printf("ERROR: redis_mng_load_db allocation failed\n");
		freeReplyObject(reply);
		rc = SR_ERROR;
		goto out;
	}

	for (i = 0; i < reply->elements; i++) {
		if (!is_supported(reply->element[i]->str))
			continue;
		redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);
	}

	for (i = 0; i < (int)reply->elements; i++) {
		if (!is_supported(reply->element[i]->str))
			continue;
		if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
			printf("ERROR: redisGetReply %d failed\n", i);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			rc = SR_ERROR;
			goto out;
		}
		if (replies[i]->type != REDIS_REPLY_ARRAY) {
			printf("e1 ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			rc = SR_ERROR;
			goto out;
		}
		// check type and call cb func
		// todo change to new struct without tuples
		if (!memcmp(reply->element[i]->str, CAN_PREFIX, strlen(CAN_PREFIX))) { // can rule

			// ACTION, action, MID, mid, DIRECTIN, dir_str, INTERFACE, interface, PROGRAM_ID, exec, USER_ID, user
			if (replies[i]->elements != CAN_RULE_FIELDS) {
				printf("ERROR: CAN redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements,
						CAN_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				rc = SR_ERROR;
				goto out;
			}
			if (load_can(atoi(reply->element[i]->str + strlen(CAN_PREFIX)), replies[i]->elements, replies[i], cb_func) != SR_SUCCESS) {
				printf("ERROR: handle CAN rule %s failed \n", reply->element[i]->str + strlen(CAN_PREFIX));
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				rc = SR_ERROR;
				goto out;
			}

		} else if (!memcmp(reply->element[i]->str, NET_PREFIX, strlen(NET_PREFIX))) { // net rule

			// ACTION, action, SRC_ADDR, src_addr_netmask, DST_ADDR, dst_addr_netmask, PROGRAM_ID, exec, USER_ID, user,
			// PROTOCOL, proto, SRC_PORT, src_port, DST_PORT, dst_port
			if (replies[i]->elements != NET_RULE_FIELDS) {
				printf("ERROR: NET redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements,
						NET_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				rc = SR_ERROR;
				goto out;
			}
			if (load_net(atoi(reply->element[i]->str + strlen(NET_PREFIX)), replies[i]->elements, replies[i], cb_func) != SR_SUCCESS) {
				printf("ERROR: handle NET rule %s failed \n", reply->element[i]->str + strlen(NET_PREFIX));
				for (j = 0; j < i; j++) {
					if (replies[j])
						freeReplyObject(replies[j]);
				}
				free(replies);
				freeReplyObject(reply);
				rc = SR_ERROR;
				goto out;
			}
		} else if (!memcmp(reply->element[i]->str, FILE_PREFIX, strlen(FILE_PREFIX))) { // file rule

			// ACTION, action, FILENAME, file_name, PERMISSION, perms, PROGRAM_ID, exec, USER_ID, user
			if (replies[i]->elements != FILE_RULE_FIELDS) {
				printf("ERROR: FILE redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, FILE_RULE_FIELDS);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				rc = SR_ERROR;
				goto out;
			}
			if (load_file(atoi(reply->element[i]->str + strlen(FILE_PREFIX)), replies[i]->elements, replies[i], cb_func) != SR_SUCCESS) {
				printf("ERROR: handle CAN rule %s failed \n", reply->element[i]->str + strlen(FILE_PREFIX));
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				rc = SR_ERROR;
				goto out;
			}
		}
	}

	// free replies
	for (i = 0; i < reply->elements; i++)
		freeReplyObject(replies[i]);
	free(replies);

	freeReplyObject(reply);
out:
	cleanup_groups();

	return rc;
}

SR_32 redis_mng_add_action(redisContext *c, char *name, redis_mng_action_t *action)
{
    redisReply *reply;

	reply = redisCommand(c,"HMSET %s%s %s %s %s %s %s %s %s %s", ACTION_PREFIX, name,
			ACTION_BITMAP, action->action_bm ? action->action_bm : "NULL",
			ACTION_LOG, action->action_log ? action->action_log : "NULL",
			RL_BITMAP, action->rl_bm ? action->rl_bm : "NULL", RL_LOG, action->rl_log ? action->rl_log : "NULL");
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: Redis mng add action failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_action(redisContext *c, char *name)
{
    redisReply *reply;

	reply = redisCommand(c,"%s %s%s", DEL, ACTION_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
		printf("ERROR: Redis mng delete action failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

/*
SR_32 redis_mng_add_list(redisContext *c, list_type_e type, char *name, SR_U32 length, char **values)
{
	redisReply *reply;
	int i, len = 0;
	char *cmd;

	if (length < 1) {
		printf("ERROR: redis_mng_add_list failed, invalid length %d\n", length);
		return SR_ERROR;
	}
	cmd = malloc(length * MAX_LIST_VAL_LEN);
	if (!cmd) {
		printf("ERROR: redis_mng_add_list failed, allocation failed\n");
		return SR_ERROR;
	}
	for (i = 0; i < length; i++)
		len += sprintf(cmd + len, " %s", values[i]);

	reply = redisCommand(c,"LPUSH %d%s%s %s", type, LIST_PREFIX, name, cmd);
	printf(">>>>>>>>>> list cmd:LPUSH %d%s%s %s: reply:%d \n", type, LIST_PREFIX, name, cmd, reply ? reply->integer : -1);
	free(cmd);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
		printf("ERROR: redis_mng_add_list failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}
*/
SR_32 redis_mng_add_list(redisContext *c, list_type_e type, char *name, SR_U32 length, char **values)
{
	redisReply *reply;
	int i;

	if (length < 1) {
		printf("ERROR: redis_mng_add_list failed, invalid length %d\n", length);
		return SR_ERROR;
	}

	for (i = 0 ; i < length; i++) {
		reply = redisCommand(c,"LPUSH %d%s%s %s", type, LIST_PREFIX, name, values[i]);
		if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer < 1) {
			printf("ERROR: redis_mng_add_list failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		freeReplyObject(reply);
	}

	return SR_SUCCESS;
}

SR_32 redis_mng_del_list(redisContext *c, list_type_e type, char *name, SR_U32 length, char **values)
{
	redisReply *reply;
	int i;

	if (length < 1) {
		printf("ERROR: redis_mng_del_list failed, invalid length %d\n", length);
		return SR_ERROR;
	}
	for (i = 0; i < length; i++) {
		reply = redisCommand(c,"LREM %d%s%s 0 %s", type, LIST_PREFIX, name, values[i]);
		if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
			printf("ERROR: redis_mng_del_list % d failed, type %d, i %d\n", i,
					reply ? reply->type : -1, reply ? (int)reply->integer : 0);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		freeReplyObject(reply);
	}
	return SR_SUCCESS;
}

SR_32 redis_mng_destroy_list(redisContext *c, list_type_e type, char *name)
{
	redisReply *reply;

	reply = redisCommand(c,"%s %d%s%s", DEL, type, LIST_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
		printf("ERROR: redis_mng_destroy_list failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_update_file_rule(redisContext *c, SR_32 rule_id, redis_mng_file_rule_t *rule)
{
	redisReply *reply;
	char *cmd;
	int len;

	cmd = malloc(FILE_RULE_FIELDS * MAX_LIST_NAME_LEN);
	if (!cmd) {
		printf("ERROR: redis_mng_update_file_rule allocation failed\n");
		return SR_ERROR;
	}

	len = sprintf(cmd, "HMSET %s%d", FILE_PREFIX, rule_id);
	if (rule->action)
		len += sprintf(cmd + len, " %s %s", ACTION, rule->action);
	if (rule->file_name) {
		if (rule->file_names_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", FILENAME, LIST_FILES, LIST_PREFIX, rule->file_name);
		else // single value
			len += sprintf(cmd + len, " %s %s", FILENAME, rule->file_name);
	}
	if (rule->file_op)
		len += sprintf(cmd + len, " %s %s", PERMISSION, rule->file_op);
	if (rule->exec) {
		if (rule->execs_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", PROGRAM_ID, LIST_PROGRAMS, LIST_PREFIX, rule->exec);
		else // single value
			len += sprintf(cmd + len, " %s %s", PROGRAM_ID, rule->exec);
	}
	if (rule->user) {
		if (rule->users_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", USER_ID, LIST_USERS, LIST_PREFIX, rule->user);
		else // single value
			len += sprintf(cmd + len, " %s %s", USER_ID, rule->user);
	}

	reply = redisCommand(c, cmd);
	free(cmd);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_update_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_file_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force)
{
    redisReply *reply;
    SR_32 rule_id;

    for (rule_id = rule_id_start; rule_id <= rule_id_end; rule_id++) {
    	reply = redisCommand(c,"%s %s%d", DEL, FILE_PREFIX, rule_id);
    	if (!force && (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)) {
    		printf("ERROR: redis_mng_del_file_rule failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
    		freeReplyObject(reply);
    		return SR_ERROR;
    	}
    	freeReplyObject(reply);
    }
	return SR_SUCCESS;
}

#if 0
SR_32 redis_mng_get_file_rule(redisContext *c, SR_32 rule_id, redis_mng_reply_t *my_reply)
{
	int i;
	redisReply *reply;

	reply = redisCommand(c,"HGETALL %s%d", FILE_PREFIX, rule_id);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_get_file_rule %d failed, %d\n", rule_id, reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	if (reply->elements != FILE_RULE_FIELDS) {
		printf("ERROR: redis_mng_get_file_rule %d length is wrong %d instead of %d\n", rule_id, (int)reply->elements, FILE_RULE_FIELDS);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	my_reply->num_fields = 10;
	for (i = 0; i < reply->elements; i++)
		memcpy(my_reply->feilds[i], reply->element[i]->str, strlen(reply->element[i]->str));

	freeReplyObject(reply);
	return SR_SUCCESS;
}
#endif

#if 0
SR_32 redis_mng_create_file_rule(redisContext *c, SR_32 rule_id, char *file_name, char *exec, char *user, char *action, SR_U8 file_op)
{
	char perms[4];

	file_op_convert(file_op, perms);
	redisAppendCommand(c,"HMSET %s%d %s %s %s %s %s %s %s %s %s %s %s %s", FILE_PREFIX, rule_id, ACTION, action,
			FILENAME, file_name, PERMISSION, perms, PROGRAM_ID, exec, USER_ID, user);
	redis_changes++;
	return SR_SUCCESS;
}
#endif

SR_32 redis_mng_update_net_rule(redisContext *c, SR_32 rule_id, redis_mng_net_rule_t *rule)
{
	redisReply *reply;
	char *cmd;
	int len;

	cmd = malloc(NET_RULE_FIELDS * MAX_LIST_NAME_LEN);
	if (!cmd) {
		printf("ERROR: redis_mng_update_net_rule allocation failed\n");
		return SR_ERROR;
	}

	//printf("4.1.1\n");fflush(stdout);
	len = sprintf(cmd, "HMSET %s%d", NET_PREFIX, rule_id);
	//printf("4.1.1.1\n");fflush(stdout);
	if (rule->action)
		len += sprintf(cmd + len, " %s %s", ACTION, rule->action);
	//printf("4.1.1.2\n");fflush(stdout);
	if (rule->src_addr_netmask) {
		if (rule->src_addr_netmasks_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", SRC_ADDR, LIST_ADDRS, LIST_PREFIX, rule->src_addr_netmask);
		else // single value
			len += sprintf(cmd + len, " %s %s", SRC_ADDR, rule->src_addr_netmask);
	}
	//printf("4.1.1.3\n");fflush(stdout);
	if (rule->dst_addr_netmask) {
		if (rule->dst_addr_netmasks_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", DST_ADDR, LIST_ADDRS, LIST_PREFIX, rule->dst_addr_netmask);
		else // single value
			len += sprintf(cmd + len, " %s %s", DST_ADDR, rule->dst_addr_netmask);
	}
	//printf("4.1.1.4\n");fflush(stdout);
	if (rule->exec) {
		if (rule->execs_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", PROGRAM_ID, LIST_PROGRAMS, LIST_PREFIX, rule->exec);
		else // single value
			len += sprintf(cmd + len, " %s %s", PROGRAM_ID, rule->exec);
	}
	//printf("4.1.1.5\n");fflush(stdout);
	if (rule->user) {
		if (rule->users_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", USER_ID, LIST_USERS, LIST_PREFIX, rule->user);
		else // single value
			len += sprintf(cmd + len, " %s %s", USER_ID, rule->user);
	}
	//printf("4.1.1.6\n");fflush(stdout);
	if (rule->proto) {
		if (rule->protos_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", PROTOCOL, LIST_PROTOCOLS, LIST_PREFIX, rule->proto);
		else // single value
			len += sprintf(cmd + len, " %s %s", PROTOCOL, rule->proto);
	}
	//printf("4.1.1.7\n");fflush(stdout);
	if (rule->src_port) {
		if (rule->src_ports_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", SRC_PORT, LIST_PORTS, LIST_PREFIX, rule->src_port);
		else // single value
			len += sprintf(cmd + len, " %s %s", SRC_PORT, rule->src_port);
	}
	//printf("4.1.1.8\n");fflush(stdout);
	if (rule->dst_port) {
		if (rule->dst_ports_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", DST_PORT, LIST_PORTS, LIST_PREFIX, rule->dst_port);
		else // single value
			len += sprintf(cmd + len, " %s %s", DST_PORT, rule->dst_port);
	}
	//printf("4.1.1.9\n");fflush(stdout);
	if (rule->up_rl)
		len += sprintf(cmd + len, " %s %s", UP_RL, rule->up_rl);
	//printf("4.1.1.10\n");fflush(stdout);
	if (rule->down_rl)
		len += sprintf(cmd + len, " %s %s", DOWN_RL, rule->down_rl);
	//printf("4.1.2\n");fflush(stdout);

#ifdef DEBUG
	printf(">>>>>  cmd:%s: \n", cmd);
#endif
	reply = redisCommand(c, cmd);
#ifdef DEBUG
	printf(">>> reply type:%d \n", reply ? reply->type : -1);
#endif
	//printf("4.1.3\n");fflush(stdout);
	free(cmd);
	//printf("4.1.4\n");fflush(stdout);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_update_net_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_net_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force)
{
    redisReply *reply;
    SR_32 rule_id;

    for (rule_id = rule_id_start; rule_id <= rule_id_end; rule_id++) {
    	reply = redisCommand(c,"%s %s%d", DEL, NET_PREFIX, rule_id);
    	if (!force && (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)) {
    		printf("ERROR: redis_mng_del_net_rule failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
    		freeReplyObject(reply);
    		return SR_ERROR;
    	}
    	freeReplyObject(reply);
    }
	return SR_SUCCESS;
}

#if 0
SR_32 redis_mng_create_net_rule(redisContext *c, SR_32 rule_id, char *src_addr, char *src_netmask,
	char *dst_addr, char *dst_netmask, SR_U8 ip_proto, SR_U16 src_port, SR_U16 dst_port, char *exec, char *user, char *action)
{
	redisAppendCommand(c,"HMSET %s%d %s %s %s %s/%d %s %s/%d %s %s %s %s %s %d %s %d %s %d", NET_PREFIX, rule_id, ACTION, action,
			SRC_ADDR, src_addr, src_netmask, DST_ADDR, dst_addr, dst_netmask, PROGRAM_ID, exec, USER_ID, user,
			PROTOCOL, ip_proto, SRC_PORT, src_port, DST_PORT, dst_port);
	redis_changes++;
	return SR_SUCCESS;
}
#endif

SR_32 redis_mng_update_can_rule(redisContext *c, SR_32 rule_id, redis_mng_can_rule_t *rule)
{
	redisReply *reply;
	char *cmd;
	int len;

	cmd = malloc(CAN_RULE_FIELDS * MAX_LIST_NAME_LEN);
	if (!cmd) {
		printf("ERROR: redis_mng_update_can_rule allocation failed\n");
		return SR_ERROR;
	}

	len = sprintf(cmd, "HMSET %s%d", CAN_PREFIX, rule_id);
	if (rule->action)
		len += sprintf(cmd + len, " %s %s", ACTION, rule->action);
	if (rule->mid) {
		if (rule->mids_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", MID, LIST_MIDS, LIST_PREFIX, rule->mid);
		else // single value
			len += sprintf(cmd + len, " %s %s", MID, rule->mid);
	}
	if (rule->dir)
		len += sprintf(cmd + len, " %s %s", DIRECTION, rule->dir);
	if (rule->interface) {
		if (rule->interfaces_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", INTERFACE, LIST_CAN_INTF, LIST_PREFIX, rule->interface);
		else // single value
			len += sprintf(cmd + len, " %s %s", INTERFACE, rule->interface);
	}
	if (rule->exec) {
		if (rule->execs_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", PROGRAM_ID, LIST_PROGRAMS, LIST_PREFIX, rule->exec);
		else // single value
			len += sprintf(cmd + len, " %s %s", PROGRAM_ID, rule->exec);
	}
	if (rule->user) {
		if (rule->users_list) // list
			len += sprintf(cmd + len, " %s %d%s%s", USER_ID, LIST_USERS, LIST_PREFIX, rule->user);
		else // single value
			len += sprintf(cmd + len, " %s %s", USER_ID, rule->user);
	}

	reply = redisCommand(c, cmd);
	free(cmd);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_update_can_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_del_can_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force)
{
    redisReply *reply;
    SR_32 rule_id;

    for (rule_id = rule_id_start; rule_id <= rule_id_end; rule_id++) {
    	reply = redisCommand(c,"%s %s%d", DEL, CAN_PREFIX, rule_id);
    	if (!force && (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1)) {
    		printf("ERROR: redis_mng_del_can_rule failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
    		freeReplyObject(reply);
    		return SR_ERROR;
    	}
    	freeReplyObject(reply);
    }
	return SR_SUCCESS;
}

SR_32 redis_mng_has_file_rule(redisContext *c, SR_32 rule_id)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %s%d", FILE_PREFIX, rule_id);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_file_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}

SR_32 redis_mng_has_net_rule(redisContext *c, SR_32 rule_id)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %s%d", NET_PREFIX, rule_id);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_net_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}

SR_32 redis_mng_has_can_rule(redisContext *c, SR_32 rule_id)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %s%d", CAN_PREFIX, rule_id);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_can_rule failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}

SR_32 redis_mng_has_action(redisContext *c, char *name)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %s%s", ACTION_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_action failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}

SR_32 redis_mng_has_list(redisContext *c, list_type_e type, char *name)
{
    redisReply *reply;
    SR_32 ret;

	reply = redisCommand(c,"EXISTS %d%s%s", type, LIST_PREFIX, name);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER) {
		printf("ERROR: redis_mng_has_list failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	ret = reply->integer;
	freeReplyObject(reply);
	return ret;
}
#if 0
SR_32 redis_mng_create_canbus_rule(redisContext *c, SR_32 rule_id, SR_U32 msg_id, char *interface, char *exec, char *user, char *action, SR_U8 dir)
{
	char msgid_str[9];
	char dir_str[4];
	
	sprintf(msgid_str, "%08x", msg_id);
	strcpy(dir_str, get_dir_desc(dir));
	// todo dir and int instead of in_int and out_int - fix
	redisAppendCommand(c,"HMSET %s%d %s %s %s %s %s %s %s %s %s %s %s %s", CAN_PREFIX, rule_id, ACTION, action,
			MID, msgid_str, DIRECTION, dir_str, INTERFACE, interface, PROGRAM_ID, exec, USER_ID, user);
	redis_changes++;
	return SR_SUCCESS;
}
#endif

#if 0
SR_32 redis_mng_commit(redisContext *c)
{
	int rc, i, j;
	redisReply **replies;

	replies = malloc(sizeof(redisReply*) * redis_changes);
	if (replies == NULL)
		return SR_ERROR; // todo CEF

	// verify all operations succeeded
	for (i = 0; i < redis_changes; i++) {
		rc = redisGetReply(c, (void*)&replies[i]);
		if (rc) { // != REDIS_OK
			for (j = 0; j <= i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			return SR_ERROR; // todo CEF
		}
	}

	for (i = 0; i < redis_changes; i++)
		freeReplyObject(replies[i]);
	free(replies);

	redis_changes = 0; // reset for next time
	return SR_SUCCESS;
}
#endif

SR_32 redis_mng_update_engine_state(redisContext *c, SR_BOOL is_on)
{
	// todo is this in the DB ?
	redisAppendCommand(c,"SET %s %s", ENGINE, is_on ? "start" : "stop");
	redis_changes++;
	return SR_SUCCESS;
}

SR_32 redis_mng_add_system_policer(redisContext *c, char *exec, redis_system_policer_t *sp)
{
	redisReply *reply;
	
	reply = redisCommand(c,"HMSET %s%s %s %lu %s %u %s %u %s %u %s %u", SYSTEM_POLICER_PREFIX, exec,
		SP_TIME, sp->time,
		SP_BYTES_READ, sp->bytes_read,
		SP_BYTES_WRITE, sp->bytes_write,
		SP_VM_ALLOC, sp->vm_allocated,
		SP_THREADS_NO, sp->num_of_threads);
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS) {
		printf("ERROR: redis_mng_add_system_policer failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);

	return SR_SUCCESS;
}

#define CHECK_PRINT(n) (replies[i]->elements > n) ?  replies[i]->element[n]->str : ""

static SR_32 print_cb(char *exec, redis_system_policer_t *sp)
{
	printf("exec:%s time:%llu byte read:%u byte write:%u vm alloc:%u num of threads:%u \n",
				exec, sp->time, sp->bytes_read, sp->bytes_write, sp->vm_allocated, sp->num_of_threads);
	return SR_SUCCESS;
}

SR_32 redis_mng_print_system_policer(redisContext *c)
{
	return redis_mng_exec_all_system_policer(c, print_cb);
}

SR_32 redis_mng_exec_all_system_policer(redisContext *c, SR_32 (*cb)(char *exec, redis_system_policer_t *sp))
{
	int i, j;
	redisReply *reply;
	redisReply **replies;
	redis_system_policer_t sp = {};
	char *field;

	// get all keys
	reply = redisCommand(c,"KEYS %s*", SYSTEM_POLICER_PREFIX);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_system_policer failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	replies = malloc(sizeof(redisReply*) * reply->elements);
	if (!replies) {
		printf("ERROR: redis_mng_print_system_policer allocation failed\n");
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		redisAppendCommand(c,"HGETALL %s", reply->element[i]->str);

	for (i = 0; i < (int)reply->elements; i++) {
		if (redisGetReply(c, (void*)&replies[i]) != REDIS_OK) {
			printf("ERROR: redisGetReply %d failed\n", i);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}
		if (replies[i]->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
			for (j = 0; j < i; j++)
				freeReplyObject(replies[j]);
			free(replies);
			freeReplyObject(reply);
			return SR_ERROR;
		}

		memset(&sp, 0, sizeof(sp));
		if ((field = get_field(SP_TIME, replies[i]->elements, replies[i])))
			sp.time = atol(field);
		if ((field = get_field(SP_BYTES_READ, replies[i]->elements, replies[i])))
			sp.bytes_read = atol(field);
		if ((field = get_field(SP_BYTES_WRITE, replies[i]->elements, replies[i])))
			sp.bytes_write = atol(field);
		if ((field = get_field(SP_VM_ALLOC, replies[i]->elements, replies[i])))
			sp.vm_allocated = atol(field);
		if ((field = get_field(SP_THREADS_NO, replies[i]->elements, replies[i])))
			sp.num_of_threads = atol(field);
		if (cb)
			cb(reply->element[i]->str + strlen(SYSTEM_POLICER_PREFIX), &sp);
	}

	// free replies
	for (i = 0; i < reply->elements; i++)
		freeReplyObject(replies[i]);
	free(replies);
	freeReplyObject(reply);
	return SR_SUCCESS;
}

SR_32 redis_mng_commit(redisContext *c)
{
	/* synchronous save of the dataset:
	 * producing a point in time snapshot of all the data inside the Redis instance, in the form of an RDB file.
	 * it will block all the other clients
	 */
	redisReply *reply = redisCommand(c,"SAVE");
	if (reply == NULL || reply->type != REDIS_REPLY_STATUS || strcmp(reply->str, "OK")) {
		printf("ERROR: redis_mng_commit failed, %d, %s\n", reply ? reply->type : -1, reply ? reply->str : "NULL");
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);

	if (rename(REDIS_SERVER_RUNNING_FILENAME, REDIS_SERVER_STARTUP_FILENAME)) {
		printf("ERROR: redis_mng_commit failed to rename, %s", strerror(errno));
		return SR_ERROR;
	}
	return SR_SUCCESS;
}

