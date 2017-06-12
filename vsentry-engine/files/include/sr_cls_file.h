#ifndef SR_CLS_FILE_H
#define SR_CLS_FILE_H
#include "sal_linux.h"

#define SR_MAX_PATH 1024
enum {
	SR_CLS_INODE_INHERIT=0,
	SR_CLS_INODE_DEL_RULE,
	SR_CLS_INODE_ADD_RULE
};
struct sr_cls_msg {
	SR_U8 msg_type;
	SR_U32	rulenum;
	SR_U32  inode1;
	SR_U32  inode2;
};

#endif
