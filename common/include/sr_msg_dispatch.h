#ifndef __SR_MSG_DISPATCH__
#define __SR_MSG_DISPATCH__

#include "sr_types.h"
#include "sr_shmem.h"
#include "sr_cls_file_common.h"

typedef enum {
	SR_MSG_TYPE_DEFAULT=0,
	SR_MSG_TYPE_CLS_FILE,
} sr_msg_dispatch_type;

#pragma pack(push, 1)
typedef struct {
	SR_8 msg_type;
	SR_8 msg_payload[1];
} sr_msg_dispatch_hdr_t;
#pragma pack(pop)
#pragma pack(push, 1)
typedef struct {
	SR_8 msg_type;
	struct sr_cls_msg file_msg;
} sr_msg_cls_file_t;
#pragma pack(pop)

SR_32 sr_msg_dispatch(char *msg, int size);

#endif /* __SR_MSG__ */

