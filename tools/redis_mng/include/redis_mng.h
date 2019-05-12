#ifndef __REDIS_MNG_H__
#define __REDIS_MNG_H__

#include <sr_types.h>
#include "hiredis.h"
#include "db_tools.h"

#define MAX_LIST_NAME_LEN	96
#define MAX_LIST_VAL_LEN	256

#define ACTION_FIELDS		8
#define FILE_RULE_FIELDS	10
#define CAN_RULE_FIELDS		14
#define NET_RULE_FIELDS		18
#define MAX_RULE_FIELDS		20

typedef enum redis_mng_list_type {
	LIST_NONE,
	LIST_FILES,
	LIST_PROGRAMS,
	LIST_USERS,
	LIST_MIDS,
	LIST_CAN_INTF,
	LIST_ADDRS,
	LIST_PORTS,
	LIST_PROTOCOLS,
	LIST_TYPE_MAX = LIST_PROTOCOLS,
	LIST_TYPE_MIN = LIST_FILES,
} list_type_e;

typedef enum {
	ENTITY_TYPE_CAN_RULE,
	ENTITY_TYPE_IP_RULE,
	ENTITY_TYPE_FILE_RULE,
	ENTITY_TYPE_ACTION,
} redis_entity_type_t;

typedef struct redis_mng_reply {
	SR_U8	num_fields;
    char	feilds[MAX_RULE_FIELDS][MAX_LIST_NAME_LEN];
} redis_mng_reply_t;

typedef struct redis_mng_file_rule {
	char 	*file_name;
	char 	*exec;
	char 	*user;
	char 	*action; 	// single value
	char 	*file_op; 	// single value
	SR_8	file_names_list;
	SR_8	execs_list;
	SR_8	users_list;
} redis_mng_file_rule_t;

typedef struct redis_mng_net_rule {
	char 	*src_addr_netmask;
	char 	*dst_addr_netmask;
	char 	*proto;		// protocol
	char 	*src_port;
	char 	*dst_port;
	char 	*exec;
	char 	*user;
	char 	*action; 	// single value
	char 	*up_rl; 	// upload rate limit - single value
	char 	*down_rl; 	// download rate limit - single value
	SR_8 	src_addr_netmasks_list;
	SR_8 	dst_addr_netmasks_list;
	SR_8 	protos_list;
	SR_8 	src_ports_list;
	SR_8 	dst_ports_list;
	SR_8	execs_list;
	SR_8	users_list;
} redis_mng_net_rule_t;

typedef struct redis_mng_can_rule {
	char 	*mid;
	char 	*interface;
	char 	*exec;
	char 	*user;
	char 	*dir;		// direction - single value
	char 	*action; 	// single value
	char 	*rl;
	SR_8	mids_list;
	SR_8	interfaces_list;
	SR_8	execs_list;
	SR_8	users_list;
} redis_mng_can_rule_t;

typedef struct redis_mng_action {
	char *action_bm;	// bitmap
	char *action_log;
//	char *log_facility;
//	char *log_severity;
	char *rl_bm;
	char *rl_log;
//	char *sms;
//	char *mail;
} redis_mng_action_t;

typedef struct redis_system_policer {
	SR_U64  time;
	SR_U32  bytes_read;
	SR_U32  bytes_write;
	SR_U32  vm_allocated;
	SR_U32  num_of_threads;
} redis_system_policer_t;

//SR_32 redis_mng_parse_json(redis_mng_handler_t *handler, char *buf, SR_U32 *version, SR_U32 old_version);

/* Callback function definition:
 * Called when a rule / action is ready
 * params:	rule - rule or action pointer
 * 			type - action / rule type
 * 			status - retval */
typedef void handle_rule_f_t(void *data, redis_entity_type_t type, SR_32 *status);

void file_op_convert(SR_U8 file_op, char *perms);

redisContext *redis_mng_session_start(void);
void redis_mng_session_end(redisContext *c);
SR_32 redis_mng_clean_db(redisContext *c); // for test only
/* get new configuration policy */
SR_32 redis_mng_load_db(redisContext *c, int pipelined, handle_rule_f_t cb_func, SR_32 (*action_cb)(void *data));

/* get all file-paths and executables from the current rules, pipelined */
SR_32 redis_mng_reconf(redisContext *c, handle_rule_f_t cb_func);

/* if rule_id_start = rule_id_end: 		a specific rule is printed
 * if rule_id_start = rule_id_end = -1: all rules (of that type) are printed
 * else:								a range of rules (from start to end) are printed */
SR_32 redis_mng_print_rules(redisContext *c, rule_type_t type, SR_32 rule_id_start, SR_32 rule_id_end);
SR_32 redis_mng_print_actions(redisContext *c);
SR_32 redis_mng_print_list(redisContext *c, list_type_e type, char *name);

SR_32 redis_mng_print_all_list_names(redisContext *c, list_type_e type);

/* update / delete rules and verify reply */
SR_32 redis_mng_update_file_rule(redisContext *c, SR_32 rule_id, redis_mng_file_rule_t *rule);
SR_32 redis_mng_del_file_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force);
//SR_32 redis_mng_get_file_rule(redisContext *c, SR_32 rule_id, redis_mng_reply_t *reply);

SR_32 redis_mng_update_net_rule(redisContext *c, SR_32 rule_id, redis_mng_net_rule_t *rule);
SR_32 redis_mng_del_net_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force);

SR_32 redis_mng_update_can_rule(redisContext *c, SR_32 rule_id, redis_mng_can_rule_t *rule);
SR_32 redis_mng_del_can_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force);

/* params:
 * 	bm (bitmap):	"drop" / "none" / "allow" (o/w invalid)
 * 	log_facility:	"file" / "none" / "sys" (syslog) (o/w invalid)
 * 	log_severity:	"crt" / "err" / "warn" / "info" / "debug" */
SR_32 redis_mng_add_action(redisContext *c, char *name, redis_mng_action_t *action);
SR_32 redis_mng_del_action(redisContext *c, char *name);

/* add values to existing list or create a new list */
SR_32 redis_mng_add_list(redisContext *c, list_type_e type, char *name, SR_U32 length, char **values);
/* delete values from existing list */
SR_32 redis_mng_del_list(redisContext *c, list_type_e type, char *name, SR_U32 length, char **values);
/* remove entire list */
SR_32 redis_mng_destroy_list(redisContext *c, list_type_e type, char *name);

/* return:	1 if the key exists
 * 			0 if the key does not exist
 * 			-1 if error */
SR_32 redis_mng_has_file_rule(redisContext *c, SR_32 rule_id);
SR_32 redis_mng_has_net_rule(redisContext *c, SR_32 rule_id);
SR_32 redis_mng_has_can_rule(redisContext *c, SR_32 rule_id);
SR_32 redis_mng_has_action(redisContext *c, char *name);
SR_32 redis_mng_has_list(redisContext *c, list_type_e type, char *name);

/* add rules pipelined
 * without waiting for replies
 * replies will be verified during commit */
#if 0
SR_32 redis_mng_create_file_rule(redisContext *c, SR_32 rule_id, char *file_name, char *exec, char *user, char *action, SR_U8 file_op);
SR_32 redis_mng_create_canbus_rule(redisContext *c, SR_32 rule_id, SR_U32 msg_id, char *interface, char *exec, char *user, char *action, SR_U8 dir);
SR_32 redis_mng_create_net_rule(redisContext *c, SR_32 rule_id, char *src_addr, char *src_netmask, char *dst_addr, char *dst_netmask, SR_U8 ip_proto, SR_U16 src_port, SR_U16 dst_port, char *exec, char *user, char *action);
SR_32 redis_mng_commit(redisContext *c);
SR_32 redis_mng_create_action(redisContext *c, char *action_name, SR_BOOL is_allow, SR_BOOL is_log);
#endif

#if 0
SR_32 redis_mng_delete_ip_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end);
SR_32 redis_mng_delete_file_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end);
SR_32 redis_mng_delete_can_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end);
SR_32 redis_mng_delete_all(redis_mng_handler_t *handler, SR_BOOL is_commit);
#endif

SR_32 redis_mng_update_engine_state(redisContext *c, SR_BOOL is_on);
SR_32 redis_mng_get_engine_state(redisContext *c, SR_BOOL *is_on);

SR_32 redis_mng_commit(redisContext *c);

//SR_U8 redis_mng_perm_get_code(char *perms);

SR_32 redis_mng_add_system_policer(redisContext *c, char *exec, redis_system_policer_t *system_policer_info);
SR_32 redis_mng_print_system_policer(redisContext *c);
SR_32 redis_mng_exec_all_system_policer(redisContext *c, SR_32 (*cb)(char *exec, redis_system_policer_t *sp));
SR_32 redis_mng_exec_all_rules(redisContext *c, rule_type_t type, SR_32 rule_id_start, SR_32 rule_id_end, SR_32 (*cb)(SR_32 rule_num, void *rule, void *param), void *param);
SR_32 redis_mng_exec_list(redisContext *c, list_type_e type, char *name, SR_32 (*cb)(char *val));
SR_32 redis_mng_exec_all_list_names(redisContext *c, list_type_e type, SR_32 (*cb)(list_type_e type, char *name));
SR_BOOL redis_mng_group_used(redisContext *c, rule_type_t type, SR_32 (*cb)(SR_32 rule_num, void *rule));

char *redis_mng_get_group_name(char *field);

#endif
