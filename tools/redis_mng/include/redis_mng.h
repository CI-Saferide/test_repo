#ifndef __REDIS_MNG_H__
#define __REDIS_MNG_H__

#include <sr_types.h>
#include "hiredis.h"

#if 0
enum connection_type {
    CONN_TCP,
    CONN_UNIX
};

struct config {
    enum connection_type type;
    union {
    	struct {
    		const char *host;
    		int port;
    		struct timeval timeout;
    	} tcp;
    	struct {
    		const char *path;
    	} unix_sock;
    };
};

typedef struct redis_mng_hadler {
        sr_conn_ctx_t *conn;
        sr_session_ctx_t *sess;
} redis_mng_handler_t;
#endif

//SR_32 redis_mng_parse_json(redis_mng_handler_t *handler, char *buf, SR_U32 *version, SR_U32 old_version);

/* Callback function definition:
 * Called when a rule / action is ready
 * params:	rule - rule or action pointer
 * 			type - action / rule type
 * 			status - retval
 */
typedef void handle_rule_f_t(void *rule, SR_8 type, SR_32 *status);

void file_op_convert(SR_U8 file_op, char *perms);

redisContext *redis_mng_session_start(SR_BOOL is_tcp);
void redis_mng_session_end(redisContext *c);
SR_32 redis_mng_clean_db(redisContext *c); // for test only
SR_32 redis_mng_load_db(redisContext *c, int pipelined, handle_rule_f_t cb_func);
/* add / modify / delete rules and verify reply */
SR_32 redis_mng_add_file_rule(redisContext *c, SR_32 rule_id, char *file_name, char *exec, char *user, char *action, SR_U8 file_op);
SR_32 redis_mng_mod_file_rule(redisContext *c, SR_32 rule_id, char *file_name, char *exec, char *user, char *action, SR_U8 file_op);
SR_32 redis_mng_del_file_rule(redisContext *c, SR_32 rule_id);
SR_32 redis_mng_add_net_rule(redisContext *c, SR_32 rule_id, char *src_addr_netmask, char *dst_addr_netmask,
		char *proto, char *src_port, char *dst_port, char *exec, char *user, char *action);
SR_32 redis_mng_mod_net_rule(redisContext *c, SR_32 rule_id, char *src_addr_netmask, char *dst_addr_netmask,
		char *proto, char *src_port, char *dst_port, char *exec, char *user, char *action);
SR_32 redis_mng_del_net_rule(redisContext *c, SR_32 rule_id);
SR_32 redis_mng_add_can_rule(redisContext *c, SR_32 rule_id, char *msg_id, char *interface, char *exec, char *user,
		char *action, SR_U8 dir);
SR_32 redis_mng_mod_can_rule(redisContext *c, SR_32 rule_id, char *mid, char *interface, char *exec, char *user,
		char *action, SR_U8 dir);
SR_32 redis_mng_del_can_rule(redisContext *c, SR_32 rule_id);

/* add rules pipelined
 * without waiting for replies
 * replies will be verified during commit */
SR_32 redis_mng_create_file_rule(redisContext *c, SR_32 rule_id, char *file_name, char *exec, char *user, char *action, SR_U8 file_op);
SR_32 redis_mng_create_canbus_rule(redisContext *c, SR_32 rule_id, SR_U32 msg_id, char *interface, char *exec, char *user,
		char *action, SR_U8 dir);
SR_32 redis_mng_create_net_rule(redisContext *c, SR_32 rule_id, char *src_addr, char *src_netmask,
	char *dst_addr, char *dst_netmask, SR_U8 ip_proto, SR_U16 src_port, SR_U16 dst_port, char *exec, char *user, char *action);
SR_32 redis_mng_commit(redisContext *c);
SR_32 redis_mng_create_action(redisContext *c, char *action_name, SR_BOOL is_allow, SR_BOOL is_log);
#if 0
SR_32 redis_mng_delete_ip_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end);
SR_32 redis_mng_delete_file_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end);
SR_32 redis_mng_delete_can_rules(redis_mng_handler_t *handler, SR_32 start, SR_32 end);
SR_32 redis_mng_delete_all(redis_mng_handler_t *handler, SR_BOOL is_commit);
#endif
SR_32 redis_mng_update_engine_state(redisContext *c, SR_BOOL is_on);

SR_U8 redis_mng_perm_get_code(char *perms);

#endif
