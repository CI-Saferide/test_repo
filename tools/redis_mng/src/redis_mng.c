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

static int redis_changes;

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

SR_32 print_action(char *name, redis_mng_action_t *action)
{
	if (!action) return SR_ERROR;

	printf("%-10s %-6s %-6s %-6s %s \n",
		name,
		action->action_bm,
		action->action_log,
		action->rl_bm,
		action->rl_log);

	return SR_SUCCESS;
}

SR_32 redis_mng_exec_all_actions(redisContext *c, SR_32 (*cb)(char *name, redis_mng_action_t *action))
{
	int i, j;
	redisReply *reply;
	redisReply **replies;
	redis_mng_action_t action = {};

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

		// action has no number so all are printed
		// ACTION_BITMAP, action->action_bm, ACTION_LOG, action->action_log, RL_BITMAP, action->rl_bm, RL_LOG, action->rl_log
		action.action_bm = replies[i]->element[1]->str;
		action.action_log = replies[i]->element[3]->str;
		action.rl_bm = replies[i]->element[5]->str;
		action.rl_log = replies[i]->element[7]->str;
		if (cb(reply->element[i]->str + strlen(ACTION_PREFIX), &action) != SR_SUCCESS) {
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

SR_32 redis_mng_print_list(redisContext *c, list_type_e type, char *name)
{
	int j;
	redisReply *reply;

	if (name) {
		// get specific key
		reply = redisCommand(c,"LRANGE %d%s%s 0 -1", type, LIST_PREFIX, name);
		if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
			printf("ERROR: redis_mng_print_list failed, %d\n", reply ? reply->type : -1);
			freeReplyObject(reply);
			return SR_ERROR;
		}

		for (j = 0; j < reply->elements; j++)
			printf("%-64s ", reply->element[j]->str);
		printf("\n");

		freeReplyObject(reply);

	} else {
		printf("ERROR: redis_mng_print_list list name is NULL\n");
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

SR_32 redis_mng_print_all_list_names(redisContext *c, list_type_e type)
{
	int i;
	redisReply *reply;

	// get all keys
	reply = redisCommand(c,"KEYS %d%s*", type, LIST_PREFIX);
	if (reply == NULL || reply->type != REDIS_REPLY_ARRAY) {
		printf("ERROR: redis_mng_print_all_list_names failed, %d\n", reply ? reply->type : -1);
		freeReplyObject(reply);
		return SR_ERROR;
	}

	for (i = 0; i < reply->elements; i++)
		printf("%-64s ", reply->element[i]->str);
	printf("\n");

	freeReplyObject(reply);
	return SR_SUCCESS;
}

static char *get_field(char *field, int n, redisReply *reply)
{
	int i;

	for (i = 0; i < n - 1; i += 2) {
		if (!strcmp(reply->element[i]->str, field))
			return reply->element[i + 1]->str;
	}
	
	return NULL;
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

static SR_32 load_action(char *name, SR_32 n, redisReply *reply, handle_rule_f_t cb)
{
	sr_action_record_t action = {};
	SR_32 rc;
	char *field;

	strncpy(action.name, name, MAX_ACTION_NAME);
	field = get_field(ACTION_BITMAP, n, reply);
	action.actions_bitmap = field ? atoi(field) : 0;
	field = get_field(ACTION_LOG, n, reply);
	action.log_target = get_log_facility_enum(field);
	field = get_field(RL_BITMAP, n, reply);
	action.rl_actions_bitmap = field ? atoi(field) : 0;
	field = get_field(RL_LOG, n, reply);
	action.rl_log_target = get_log_facility_enum(field);
	
	cb(&action, ENTITY_TYPE_ACTION, &rc);

	return rc;
}

static SR_32 load_can(char *name, SR_32 n, redisReply *reply, handle_rule_f_t cb)
{
	SR_32 rc = SR_SUCCESS;
#if 0
				can_rule.rulenum = atoi(reply->element[i]->str + strlen(CAN_PREFIX));
				memcpy(can_rule.action_name, replies[i]->element[1]->str, strlen(replies[i]->element[1]->str));
				can_rule.tuple.id = 1; // todo remove
				can_rule.tuple.direction = atoi(replies[i]->element[5]->str);
				memcpy(can_rule.tuple.interface, replies[i]->element[7]->str, strlen(replies[i]->element[7]->str));
				can_rule.tuple.max_rate = 100; // todo add rl to can rule
				can_rule.tuple.msg_id = atoi(replies[i]->element[3]->str);
				memcpy(can_rule.tuple.program, replies[i]->element[9]->str, strlen(replies[i]->element[9]->str));
				memcpy(can_rule.tuple.user, replies[i]->element[11]->str, strlen(replies[i]->element[11]->str));

				cb_func(reply->element[i]->str + strlen(CAN_PREFIX), &can_rule, ENTITY_TYPE_CAN_RULE, &rc);

	cb(name, &can_rule, ENTITY_TYPE_CAN_RULE, &rc);
#endif

	return rc;
}

static SR_32 load_net(SR_32 rule_id, SR_32 n, redisReply *reply, handle_rule_f_t cb)
{
	SR_32 rc = SR_SUCCESS;
	sr_net_record_t net_rule = {};
	char *field;

	// XXXX Should handle groups 

	net_rule.rulenum = rule_id;

	field = get_field(ACTION, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_ACTION;
	strncpy(net_rule.net_item.u.action, field, MAX_ACTION_NAME);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);

	field = get_field(SRC_ADDR, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_SRC_ADDR;
	strncpy(net_rule.net_item.u.src_addr, field, MAX_ADDR_LEN);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);

	field = get_field(DST_ADDR, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_DST_ADDR;
	strncpy(net_rule.net_item.u.dst_addr, field, MAX_ADDR_LEN);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);

	field = get_field(PROTOCOL, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_PROTO;
	if (!strcmp(field, "tcp"))
		net_rule.net_item.u.proto = 8;
	else if (!strcmp(field, "udp"))
		net_rule.net_item.u.proto = 17;
	else
		net_rule.net_item.u.proto = 0;
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);

	field = get_field(SRC_PORT, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_SRC_PORT;
	net_rule.net_item.u.src_port = atoi(field);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);

	field = get_field(DST_PORT, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_DST_PORT;
	net_rule.net_item.u.dst_port = atoi(field);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);

	field = get_field(UP_RL, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_UP_RL;
	net_rule.net_item.u.up_rl = atoi(field);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);

	field = get_field(DOWN_RL, n, reply);
	net_rule.net_item.net_item_type = NET_ITEM_DOWN_RL;
	net_rule.net_item.u.down_rl = atoi(field);
	cb(&net_rule, ENTITY_TYPE_IP_RULE, &rc);

	return rc;
}

static SR_BOOL is_supported(char *name) {
	return (!memcmp(name, CAN_PREFIX, strlen(CAN_PREFIX)) ||
		!memcmp(name, NET_PREFIX, strlen(NET_PREFIX)) ||
		!memcmp(name, FILE_PREFIX, strlen(FILE_PREFIX)) ||
		!memcmp(name, ACTION_PREFIX, strlen(ACTION_PREFIX)));
}

SR_32 redis_mng_load_db(redisContext *c, int pipelined, handle_rule_f_t cb_func)
{
	int i, j;
	redisReply *reply, *reply2;
	redisReply **replies;
	can_rule_t can_rule;
	ip_rule_t net_rule;
	file_rule_t file_rule;
	action_t action;
	SR_32 rc;
	int a1, a2, a3, a4, len;

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

	if (pipelined) {
		replies = malloc(sizeof(redisReply*) * reply->elements);
		if (!replies) {
			printf("ERROR: redis_mng_load_db allocation failed\n");
			freeReplyObject(reply);
			return SR_ERROR;
		}

		for (i = 0; i < reply->elements; i++) {
#ifdef DEBUG
			printf("i>>>>>> i:%d str:%s: \n", i, reply->element[i]->str);
#endif
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
				return SR_ERROR;
			}
			if (replies[i]->type != REDIS_REPLY_ARRAY) {
				printf("e1 ERROR: redisGetReply %d type is wrong %d\n", i, replies[i]->type);
				for (j = 0; j < i; j++)
					freeReplyObject(replies[j]);
				free(replies);
				freeReplyObject(reply);
				return SR_ERROR;
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
					return SR_ERROR;
				}
				if (load_can(reply->element[i]->str + strlen(CAN_PREFIX), replies[i]->elements, replies[i], cb_func) != SR_SUCCESS) {
					printf("ERROR: handle CAN %s failed \n", reply->element[i]->str + strlen(ACTION_PREFIX));
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
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
					return SR_ERROR;
				}
				if (load_net(atoi(reply->element[i]->str + strlen(NET_PREFIX)), replies[i]->elements, replies[i], cb_func) != SR_SUCCESS) {
					printf("ERROR: handle CAN %s failed \n", reply->element[i]->str + strlen(ACTION_PREFIX));
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
			} else if (!memcmp(reply->element[i]->str, FILE_PREFIX, strlen(FILE_PREFIX))) { // file rule

				// ACTION, action, FILENAME, file_name, PERMISSION, perms, PROGRAM_ID, exec, USER_ID, user
				if (replies[i]->elements != FILE_RULE_FIELDS) {
					printf("ERROR: FILE redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, FILE_RULE_FIELDS);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
				memset(&file_rule, 0, sizeof(file_rule));
				file_rule.rulenum = atoi(reply->element[i]->str + strlen(FILE_PREFIX));
				memcpy(file_rule.action_name, replies[i]->element[1]->str, strlen(replies[i]->element[1]->str));
				file_rule.tuple.id = 1; // todo remove
				memcpy(file_rule.tuple.filename ,replies[i]->element[3]->str, strlen(replies[i]->element[3]->str));
				file_rule.tuple.max_rate = 100; // todo add rl to can rule
				memcpy(file_rule.tuple.permission, replies[i]->element[5]->str, strlen(replies[i]->element[5]->str));
				memcpy(file_rule.tuple.program, replies[i]->element[7]->str, strlen(replies[i]->element[7]->str));
				memcpy(file_rule.tuple.user, replies[i]->element[9]->str, strlen(replies[i]->element[9]->str));

				cb_func(&file_rule, ENTITY_TYPE_FILE_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add file rule %d, ret %d\n", i, rc);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}

			} else if (!memcmp(reply->element[i]->str, ACTION_PREFIX, strlen(ACTION_PREFIX))) { // action

				if (replies[i]->elements != ACTION_FIELDS) {
					printf("ERROR: ACTION redisGetReply %d length is wrong %d instead of %d\n", i, (int)replies[i]->elements, ACTION_FIELDS);
					for (j = 0; j < replies[i]->elements; j++) 
						printf("%s ", replies[i]->element[j]->str);
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
				if (load_action(reply->element[i]->str + strlen(ACTION_PREFIX), replies[i]->elements, replies[i], cb_func) != SR_SUCCESS) {
					printf("ERROR: handle ACTION %s failed \n", reply->element[i]->str + strlen(ACTION_PREFIX));
					for (j = 0; j < i; j++)
						freeReplyObject(replies[j]);
					free(replies);
					freeReplyObject(reply);
					return SR_ERROR;
				}
			} else {
				printf(">>>>>>>>>>>>>>>>>>>>>>>>>>>>> default !!!!\n");
			}
		}

		// free replies
		for (i = 0; i < reply->elements; i++)
			freeReplyObject(replies[i]);
		free(replies);

	} else {
		// same NOT pipelined

		for (i = 0; i < reply->elements; i++) {
			reply2 = redisCommand(c,"HGETALL %s", reply->element[i]->str);
			if (reply2 == NULL || reply2->type != REDIS_REPLY_ARRAY) {
				printf("ERROR: redis_mng_load_db failed, %d\n", reply2 ? reply2->type : -1);
				freeReplyObject(reply);
				if (reply2)
					freeReplyObject(reply2);
				return SR_ERROR;
			}

			// check type and call cb func
			// todo change to new struct without tuples
			if (strstr(reply->element[i]->str, CAN_PREFIX)) { // can rule

				// ACTION, action, MID, mid, DIRECTION, dir_str, INTERFACE, interface, PROGRAM_ID, exec, USER_ID, user
				if (reply2->elements != CAN_RULE_FIELDS) {
					printf("ERROR: CAN redisGetReply %d length is wrong %d instead of %d\n", i, (int)reply2->elements, CAN_RULE_FIELDS);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
				memset(&can_rule, 0, sizeof(can_rule));
				can_rule.rulenum = atoi(reply->element[i]->str + strlen(CAN_PREFIX));
				memcpy(can_rule.action_name, reply2->element[1]->str, strlen(reply2->element[1]->str));
				can_rule.tuple.id = 1; // todo remove
				can_rule.tuple.direction = atoi(reply2->element[5]->str);
				memcpy(can_rule.tuple.interface, reply2->element[7]->str, strlen(reply2->element[7]->str));
				can_rule.tuple.max_rate = 100; // todo add rl to can rule
				can_rule.tuple.msg_id = atoi(reply2->element[3]->str);
				memcpy(can_rule.tuple.program, reply2->element[9]->str, strlen(reply2->element[9]->str));
				memcpy(can_rule.tuple.user, reply2->element[11]->str, strlen(reply2->element[11]->str));

				cb_func(&can_rule, ENTITY_TYPE_CAN_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add CAN rule %d, ret %d\n", i, rc);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}

			} else if (strstr(reply->element[i]->str, NET_PREFIX)) { // net rule

				// ACTION, action, SRC_ADDR, src_addr_netmask, DST_ADDR, dst_addr_netmask, PROGRAM_ID, exec, USER_ID, user,
				// PROTOCOL, proto, SRC_PORT, src_port, DST_PORT, dst_port
				if (reply2->elements != NET_RULE_FIELDS) {
					printf("ERROR: NET redisGetReply %d length is wrong %d instead of %d\n", i, (int)reply2->elements, NET_RULE_FIELDS);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}

				memset(&net_rule, 0, sizeof(net_rule));
				net_rule.rulenum = atoi(reply->element[i]->str + strlen(NET_PREFIX));
				memcpy(net_rule.action_name, reply2->element[1]->str, strlen(reply2->element[1]->str));
				net_rule.tuple.id = 1; // todo remove
				sscanf(reply2->element[5]->str, "%d.%d.%d.%d/%d", &a1, &a2, &a3, &a4, &len);
				net_rule.tuple.dstaddr.s_addr = a1 << 24 | a2 << 16 | a3 << 8 | a4;
				net_rule.tuple.dstnetmasklen = len;
				sscanf(reply2->element[3]->str, "%d.%d.%d.%d/%d", &a1, &a2, &a3, &a4, &len);
				net_rule.tuple.srcaddr.s_addr = a1 << 24 | a2 << 16 | a3 << 8 | a4;
				net_rule.tuple.srcnetmasklen = len;
				net_rule.tuple.proto = atoi(reply2->element[11]->str);
				net_rule.tuple.srcport = atoi(reply2->element[13]->str);
				net_rule.tuple.dstport = atoi(reply2->element[15]->str);
				net_rule.tuple.max_rate = 100; // todo add rl to can rule
				memcpy(net_rule.tuple.program, reply2->element[7]->str, strlen(reply2->element[7]->str));
				memcpy(net_rule.tuple.user, reply2->element[9]->str, strlen(reply2->element[9]->str));

				cb_func(&net_rule, ENTITY_TYPE_IP_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add net rule %d, ret %d\n", i, rc);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}

			} else if (strstr(reply->element[i]->str, FILE_PREFIX)) { // file rule

				// ACTION, action, FILENAME, file_name, PERMISSION, perms, PROGRAM_ID, exec, USER_ID, user
				if (reply2->elements != FILE_RULE_FIELDS) {
					printf("ERROR: FILE redisGetReply %d length is wrong %d instead of %d\n", i, (int)reply2->elements, FILE_RULE_FIELDS);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
				memset(&file_rule, 0, sizeof(file_rule));
				file_rule.rulenum = atoi(reply->element[i]->str + strlen(FILE_PREFIX));
				memcpy(file_rule.action_name, reply2->element[1]->str, strlen(reply2->element[1]->str));
				file_rule.tuple.id = 1; // todo remove
				memcpy(file_rule.tuple.filename ,reply2->element[3]->str, strlen(reply2->element[3]->str));
				file_rule.tuple.max_rate = 100; // todo add rl to can rule
				memcpy(file_rule.tuple.permission, reply2->element[5]->str, strlen(reply2->element[5]->str));
				memcpy(file_rule.tuple.program, reply2->element[7]->str, strlen(reply2->element[7]->str));
				memcpy(file_rule.tuple.user, reply2->element[9]->str, strlen(reply2->element[9]->str));

				cb_func(&file_rule, ENTITY_TYPE_FILE_RULE, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add file rule %d, ret %d\n", i, rc);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
			} else { // action

				// BITMAP, bm, LOG, log, SMS, sms, EMAIL, mail
				if (reply2->elements != ACTION_FIELDS) {
					printf("ERROR: ACTION redisGetReply %d length is wrong %d instead of %d\n", i, (int)reply2->elements, ACTION_FIELDS);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
				action.black_list = 0; // fixme
				action.terminate = 0; // fixme
				memcpy(action.action_name, reply->element[i]->str + strlen(ACTION_PREFIX),
						strlen(reply->element[i]->str) - strlen(ACTION_PREFIX));

				if (strstr(reply2->element[1]->str, "drop"))
					action.action = ACTION_DROP;
				else if (strstr(reply2->element[1]->str, "none"))
					action.action = ACTION_NONE;
				else if (strstr(reply2->element[1]->str, "allow"))
					action.action = ACTION_ALLOW;
				else
					action.action = ACTION_INVALID;

				if (strstr(reply2->element[3]->str, "file"))
					action.log_facility = LOG_TO_FILE;
				else if (strstr(reply2->element[3]->str, "none"))
					action.log_facility = LOG_NONE;
				else if (strstr(reply2->element[3]->str, "sys"))
					action.log_facility = LOG_TO_SYSLOG;
				else
					action.log_facility = LOG_INVALID;

				if (strstr(reply2->element[3]->str, "crt"))
					action.log_severity = LOG_SEVERITY_CRT;
				else if (strstr(reply2->element[3]->str, "err"))
					action.log_severity = LOG_SEVERITY_ERR;
				else if (strstr(reply2->element[3]->str, "warn"))
					action.log_severity = LOG_SEVERITY_WARN;
				else if (strstr(reply2->element[3]->str, "info"))
					action.log_severity = LOG_SEVERITY_INFO;
				else if (strstr(reply2->element[3]->str, "debug"))
					action.log_severity = LOG_SEVERITY_DEBUG;
				else
					action.log_severity = LOG_SEVERITY_NONE;

				cb_func(&action, ENTITY_TYPE_ACTION, &rc);
				if (rc) {
					printf("ERROR: cb func failed to add action %d, ret %d\n", i, rc);
					freeReplyObject(reply);
					freeReplyObject(reply2);
					return SR_ERROR;
				}
			}

			freeReplyObject(reply2);
		}
	}

	freeReplyObject(reply);
	return SR_SUCCESS;
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
	free(cmd);
	if (reply == NULL || reply->type != REDIS_REPLY_INTEGER || reply->integer != 1) {
		printf("ERROR: redis_mng_add_list failed, type %d, i %d\n", reply ? reply->type : -1, reply ? (int)reply->integer : 0);
		freeReplyObject(reply);
		return SR_ERROR;
	}
	freeReplyObject(reply);
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
