#ifndef SR_CLS_FILE_H
#define SR_CLS_FILE_H

#include "sr_types.h"
#include "sr_cls_file_common.h"
#include "sr_cls_filter_path_common.h"
#include "sal_bitops.h"

int sr_cls_fs_init(void);
void sr_cls_fs_uninit(void);
void sr_cls_fs_empty_table(SR_BOOL is_lock);
bit_array *sr_cls_file_any(void);
int sr_cls_inode_add_rule(SR_U32 inode, SR_U32 rulenum);
int sr_cls_inode_del_rule(SR_U32 inode, SR_U32 rulenum);
int sr_cls_inode_inherit(SR_U32 from, SR_U32 to);
void sr_cls_inode_remove(SR_U32 inode);
SR_8 sr_cls_file_msg_dispatch(struct sr_cls_file_msg *msg);
SR_32 sr_cls_file_filter_path_msg_dispatch(struct sr_cls_filter_path_msg *msg);
bit_array *sr_cls_file_find(SR_U32 inode);
SR_BOOL sr_cls_filter_path_is_match(char *path);
struct sr_hash_table_t * get_cls_file_table(void);

#endif /* SR_CLS_FILE_H */
