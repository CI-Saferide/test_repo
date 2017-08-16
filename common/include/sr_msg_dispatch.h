#ifndef __SR_MSG_DISPATCH__
#define __SR_MSG_DISPATCH__

#include "sr_types.h"
#include "sr_shmem.h"
#include "sr_cls_file_common.h"
#include "sr_cls_canbus_common.h"
#include "sr_cls_uid_common.h"
#include "sr_cls_network_common.h"
#include "sr_cls_port_common.h"
#include "sr_control_common.h"
#include "sr_actions_common.h"

typedef enum {
	SR_MSG_TYPE_DEFAULT=0,
	SR_MSG_TYPE_CLS_RULES,
	SR_MSG_TYPE_CLS_FILE,
	SR_MSG_TYPE_CLS_NETWORK,
	SR_MSG_TYPE_CLS_PORT,
	SR_MSG_TYPE_CLS_CANBUS,	
	SR_MSG_TYPE_CLS_UID,
	SR_MSG_TYPE_CONTROL,
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
	struct sr_cls_rules_msg sub_msg;
} sr_rules_msg_cls_t;

typedef struct {
	SR_8 msg_type;
	struct sr_cls_file_msg sub_msg;
} sr_file_msg_cls_t;

typedef struct {
	SR_8 msg_type;
	struct sr_cls_uid_msg sub_msg;
} sr_uid_msg_cls_t;

typedef struct {
	SR_8 msg_type;
	struct sr_cls_canbus_msg sub_msg;
} sr_canbus_msg_cls_t;

typedef struct {
	SR_8 msg_type;
	struct sr_cls_network_msg sub_msg;
} sr_network_msg_cls_t;

typedef struct {
	SR_8 msg_type;
	struct sr_cls_port_msg sub_msg;
} sr_port_msg_cls_t;

typedef struct {
	SR_8 msg_type;
	struct sr_control_msg sub_msg;
} sr_control_msg_t;

#pragma pack(pop)

SR_32 sr_msg_dispatch(char *msg, int size);

#endif /* __SR_MSG__ */

