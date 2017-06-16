#ifndef SR_CLASSIFIER_H
#define SR_CLASSIFIER_H
int sr_classifier_init(void);
int sr_cls_inode_add_rule(SR_U32 inode, SR_U32 rulenum);
int sr_cls_inode_del_rule(SR_U32 inode, SR_U32 rulenum);
int sr_cls_inode_inherit(SR_U32 from, SR_U32 to);
void sr_cls_inode_remove(SR_U32 inode);
void sr_classifier_uninit(void);
#endif

