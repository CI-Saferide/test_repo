#ifndef __SYSREPO_MNG_H__
#define __SYSREPO_MNG_H__

#include <sysrepo.h>
#include <sr_types.h>

typedef struct sysrepo_mng_hadler {
        sr_conn_ctx_t *conn;
        sr_session_ctx_t *sess;
} sysrepo_mng_handler_t;

SR_32 sysrepo_mng_parse_json(sysrepo_mng_handler_t *handler, char *buf, SR_U32 *version, SR_U32 old_version);
SR_32 sysrepo_mng_session_start(sysrepo_mng_handler_t *handler);
SR_32 sysrepo_mng_session_end(sysrepo_mng_handler_t *handler);
SR_32 sys_repo_mng_create_file_rule(sysrepo_mng_handler_t *handler, SR_32 rule_id, SR_32 tuple_id, char *file_name, char *exec, char *user, char *action, SR_U8 file_op);
SR_32 sys_repo_mng_create_canbus_rule(sysrepo_mng_handler_t *handler, SR_32 rule_id, SR_U32 msg_id, char *exec, char *user, char *action, SR_U8 dir);
SR_32 sys_repo_mng_create_net_rule(sysrepo_mng_handler_t *handler, SR_32 rule_id, SR_32 tuple, char *src_addr, char *src_netmask,
        char *dst_addr, char *dst_netmsk, SR_U8 ip_proto, SR_U16 src_port, SR_U16 dst_port, char *exec, char *user, char *action);
SR_32 sys_repo_mng_commit(sysrepo_mng_handler_t *handler);
SR_32 sys_repo_mng_create_action(sysrepo_mng_handler_t *handler, char *action_name, SR_BOOL is_allow, SR_BOOL is_log);

#endif
