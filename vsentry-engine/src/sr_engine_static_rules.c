#include "sr_log.h"
#include "sr_types.h"
#include "sr_engine_static_rules_internal.h"
#include "file_rule.h"
#include "sr_actions_common.h"
#include "sr_cls_wl_common.h"
#include "sr_cls_file_control.h"
#include "sr_cls_rules_control.h"

static SR_BOOL is_valid_rules(static_file_rule_t rules[])
{
        SR_U32 i;

        for (i = 0; *rules[i].filename; i++) {
                if (rules[i].rule_id >= SR_FILE_START_STATIC_RULE_NO) {
                        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                                 "%s=Rule id is not in the range:%d ", REASON, rules[i].rule_id);
                        return SR_FALSE;
                }
        }

        return SR_TRUE;
}

SR_32 create_static_white_list(void)
{
        SR_U32 i;
        SR_32 rc;
        SR_U8 perm;
        SR_U16 actions_bitmap = SR_CLS_ACTION_ALLOW;

        if (!is_valid_rules(static_wl)) {
                return SR_ERROR;
        }

        for (i = 0; *static_wl[i].filename; i++) {
                perm = 0;
                if (strstr(static_wl[i].permission, "r"))
                        perm |= SR_FILEOPS_READ;
                if (strstr(static_wl[i].permission, "w"))
                        perm |= SR_FILEOPS_WRITE;
                if (strstr(static_wl[i].permission, "x"))
                        perm |= SR_FILEOPS_EXEC;

printf("XCXXXXX add rule %d filename:%s \n", static_wl[i].rule_id, static_wl[i].filename);
                rc = sr_cls_file_add_rule(static_wl[i].filename, static_wl[i].program, static_wl[i].user, static_wl[i].rule_id, (SR_U8)1);
                if (rc != SR_SUCCESS) {
                        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                "%s=irdeto static WL Failed add file rule:%d ", REASON, static_wl[i].rule_id);
                }
                sr_cls_rule_add(SR_FILE_RULES, static_wl[i].rule_id, actions_bitmap, perm, SR_RATE_TYPE_BYTES, 0, 0 ,0, 0, 0, 0);
        }

        return SR_SUCCESS;
}

