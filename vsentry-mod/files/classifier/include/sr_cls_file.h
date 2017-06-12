#ifndef SR_CLS_FILE_H
#define SR_CLS_FILE_H

#define SR_MAX_PATH 1024
int sr_cls_init(void);
int sr_cls_inode_add_rule(SR_U32 inode, SR_U32 rulenum);
int sr_cls_inode_del_rule(SR_U32 inode, SR_U32 rulenum);
int sr_cls_inode_inherit(SR_U32 from, SR_U32 to);
void sr_cls_inode_remove(SR_U32 inode);

#endif
