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

#endif
