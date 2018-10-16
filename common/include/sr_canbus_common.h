#ifndef SR_CLS_CANBUS_COMMON_H
#define SR_CLS_CANBUS_COMMON_H
#include "sr_types.h"
#include "sr_sal_common.h"

#define MSGID_ANY -1
#define CAN_INTERFACES_MAX 10
#define CAN_INTERFACES_NAME_SIZE 16

#define SR_CAN_IN (SR_U8)0
#define SR_CAN_OUT (SR_U8)1
#define SR_CAN_BOTH (SR_U8)2

#define CAN_ML_START_PROTECT		0xffffffff
#define CAN_ML_STOP_PROTECT			0xfffffffe

#define CAN_DEV_BASE 100
#define PCAN_DEV CAN_DEV_BASE

#define  PCAN_DEV_NAME "pcan"

#ifdef CONFIG_CAN_ML
struct sr_ml_can_msg {
	SR_U32		msg_id;						/* can message id */
	SR_32		K;							/* drift blocker */
	SR_32		h;							/* alarm threshold */
	SR_U32		mean_delta;					/* mean value of delta from learning sequence */
};
#endif
typedef enum {
	SR_CLS_CANID_DEL_RULE = 0,
	SR_CLS_CANID_ADD_RULE,
} sr_canbus_verb_t;

struct sr_cls_canbus_msg {
	sr_canbus_verb_t  msg_type;
	SR_U32	rulenum;
	SR_U32  canid;
	SR_U8   dir; // SR_CAN_IN/ SR_CAN_OUT/ SR_CAN_BOTH
	SR_U32  exec_inode;
	SR_32   uid;
	SR_32   if_id;
};

typedef struct can_trsnalator {
        SR_8 devices_map_to_can_id[MAX_DEVICE_NUMBER];
        char interfaces_name[CAN_INTERFACES_MAX][CAN_INTERFACES_NAME_SIZE];
        SR_U8 curr_can_dev_ind;
} can_translator_t;

SR_32 sr_can_tran_init(can_translator_t *can_traslator);
SR_32 sr_can_tran_get_if_id(can_translator_t *can_traslator, SR_U8 dev_id, SR_U8 *can_id);
char *sr_can_tran_get_interface_name(can_translator_t *can_translator, SR_32 if_id);
SR_32 sr_can_get_special_dev_id(char *name, SR_U32 *dev_id);

#endif /* SR_CLS_CANBUS_COMMON_H */
