#ifndef SR_CLS_UID_H
#define SR_CLS_UID_H

#include "sr_sal_common.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_actions_common.h"
#include "sr_cls_uid_common.h"

#define UID_ANY -1

int sr_cls_uid_init(void);
void sr_cls_uid_ut(void);
void sr_cls_uid_uninit(void);
void sr_cls_uid_empty_table(SR_BOOL is_lock);
int sr_cls_uid_add_rule(enum sr_rule_type type, SR_32 uid, SR_U32 rulenum);
int sr_cls_uid_del_rule(enum sr_rule_type type, SR_32 uid, SR_U32 rulenum);
struct sr_hash_ent_t *sr_cls_uid_find(enum sr_rule_type type, SR_32 uid);
bit_array *sr_cls_match_uid(enum sr_rule_type type, SR_32 uid);
bit_array *sr_cls_uid_any(enum sr_rule_type type);
SR_8 sr_cls_uid_msg_dispatch(struct sr_cls_uid_msg *msg);

#endif
