#ifndef __REDIS_MNG_H__
#define __REDIS_MNG_H__

#include <sr_types.h>
#include "hiredis.h"
#include "db_tools.h"

#define MAX_LIST_NAME_LEN	96
#define MAX_LIST_VAL_LEN	256

#define ACTION_FIELDS		8
#define FILE_RULE_FIELDS	10
#define CAN_RULE_FIELDS		12
#define NET_RULE_FIELDS		16
#define MAX_RULE_FIELDS		16

typedef enum redis_mng_list_type {
	LIST_FILES = 1,
	LIST_PROGRAMS,
	LIST_USERS,
	LIST_MIDS,
	LIST_CAN_INTF,
	LIST_ADDRS,
	LIST_PORTS,
	LIST_PROTOCOLS,
	LIST_TYPE_MAX,
} list_type_e;

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
	SR_8 	src_addr_netmasks_list;
	SR_8 	dst_addr_netmasks_list;
	SR_8 	protos_list;
	SR_8 	src_ports_list;
	SR_8 	dst_ports_list;
	SR_8	execs_list;
	SR_8	users_list;
} redis_mng_net_rule_t;

//SR_32 redis_mng_parse_json(redis_mng_handler_t *handler, char *buf, SR_U32 *version, SR_U32 old_version);

/* Callback function definition:
 * Called when a rule / action is ready
 * params:	rule - rule or action pointer
 * 			type - action / rule type
 * 			status - retval */
typedef void handle_rule_f_t(void *rule, SR_8 type, SR_32 *status);

void file_op_convert(SR_U8 file_op, char *perms);

redisContext *redis_mng_session_start(SR_BOOL is_tcp);
void redis_mng_session_end(redisContext *c);
SR_32 redis_mng_clean_db(redisContext *c); // for test only
/* get new configuration policy */
SR_32 redis_mng_load_db(redisContext *c, int pipelined, handle_rule_f_t cb_func);

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

SR_32 redis_mng_update_can_rule(redisContext *c, SR_32 rule_id, char *msg_id, char *interface, char *exec, char *user, char *action, char *dir);
SR_32 redis_mng_del_can_rule(redisContext *c, SR_32 rule_id_start, SR_32 rule_id_end, SR_8 force);

/* params:
 * 	bm (bitmap):	"drop" / "none" / "allow" (o/w invalid)
 * 	log_facility:	"file" / "none" / "sys" (syslog) (o/w invalid)
 * 	log_severity:	"crt" / "err" / "warn" / "info" / "debug"
 * 	rl (rate limit) */
SR_32 redis_mng_add_action(redisContext *c, char *name, char *bm, char *log_facility, char *log_severity, char *rl, char *sms, char *mail);
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

//SR_U8 redis_mng_perm_get_code(char *perms);

#endif
