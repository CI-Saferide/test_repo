#ifndef __ML_CAN__
#define __ML_CAN__

#include "sr_types.h"
#include "dispatcher.h"
#include "sr_ml_can_common.h"

typedef struct ml_can_item {
	SR_U32		msg_id;						/* can message id */
	SR_U64		ts;							/* time stamp of last message, in usec */
	SR_U32		delta;						/* delta between last two messages, in usec */
	SR_U32		calc_sigma_plus;			/* max(0, sigma_plus + d_delta - K) */
	SR_U32		calc_sigma_minus;			/* max(0, sigma_plus - d_delta - K) */
	SR_32		K;							/* drift blocker (from learning sequence)*/
	SR_32		h;							/* alarm threshold (from learning sequence)*/
	SR_U32		mean_delta;					/* mean value of delta (from learning sequence) */
	SR_U8		payload[8];					/* payload of the message */
	SR_U32		index;						/* index of the message */
}ml_can_item_t;

SR_U8 test_can_msg(disp_info_t* info);
SR_32 sr_ml_can_handle_message(struct sr_ml_can_msg *msg);
void sr_ml_can_hash_deinit(void);
SR_32 sr_ml_can_hash_init(void);
SR_BOOL get_can_ml_state(void);

#endif /* __ML_CAN__ */
