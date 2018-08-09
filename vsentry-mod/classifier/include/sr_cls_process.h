#ifndef SR_CLS_PROCESS_H
#define SR_CLS_PROCESS_H

#include "sr_sal_common.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_actions_common.h"

struct sr_hash_ent_process_t{
        SR_U32 key;
        SR_U32 type;
        struct sr_hash_ent_t *next;
        enum policy_cls ent_type;
        SR_U32 exec_inode;
};

int sr_cls_process_init(void);
void sr_cls_process_uninit(void);
void sr_cls_process_ut(void);

int sr_cls_process_add(SR_32 pid, SR_BOOL is_atomic);
int sr_cls_process_del(SR_32 pid);
SR_U32 sr_cls_process_find_inode(SR_32 pid);
bit_array *sr_cls_process_match(enum sr_rule_type type, SR_32 pid);

#endif
