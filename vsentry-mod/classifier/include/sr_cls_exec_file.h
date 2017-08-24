#ifndef SR_CLS_EXEC_FILE_H
#define SR_CLS_EXEC_FILE_H

#include "sr_sal_common.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#include "sr_actions_common.h"

#define INODE_ANY 0

struct sr_hash_ent_multy_t{
        SR_U32 key;
        SR_U32 type;
        struct sr_hash_ent_t *next;
        enum policy_cls ent_type;
        bit_array rules[SR_RULES_TYPE_MAX];
};

int sr_cls_exec_file_init(void);
void sr_cls_exec_file_ut(void);
void sr_cls_exec_file_uninit(void);
void sr_cls_exec_file_empty_table(SR_BOOL is_lock);

int sr_cls_exec_inode_add_rule(enum sr_rule_type type, SR_U32 exec_inode, SR_U32 rulenum);
int sr_cls_exec_inode_del_rule(enum sr_rule_type type, SR_U32 exec_inode, SR_U32 rulenum);
struct sr_hash_ent_multy_t *sr_cls_exec_inode_find(enum sr_rule_type type, SR_U32 exec_inode);
bit_array *sr_cls_match_exec_inode(enum sr_rule_type type, SR_U32 exec_inode);
bit_array *sr_cls_exec_file_any(enum sr_rule_type type);
int sr_cls_exec_inode_inherit(enum sr_rule_type type, SR_U32 from, SR_U32 to);

#endif
