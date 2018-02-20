#ifndef SR_CLS_FILE_COMMON_H
#define SR_CLS_FILE_COMMON_H
#include "sr_types.h"

#define INODE_ANY 0

typedef enum {
	SR_CLS_INODE_INHERIT=0,
	SR_CLS_INODE_DEL_RULE,
	SR_CLS_INODE_ADD_RULE,
	SR_CLS_INODE_REMOVE,
	SR_CLS_INODE_MAX = SR_CLS_INODE_REMOVE,
	SR_CLS_INODE_TOTAL = (SR_CLS_INODE_MAX + 1),
} sr_file_verb_t;

struct sr_cls_file_msg {
	sr_file_verb_t msg_type;
	SR_U32	rulenum;
	SR_U32  inode1;
	SR_U32  inode2;
	SR_U32  exec_inode;
	SR_32   uid;
};

#endif /* SR_CLS_FILE_COMMON_H */
