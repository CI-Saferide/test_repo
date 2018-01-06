#ifndef SR_ML_CAN_COMMON_
#define SR_ML_CAN_COMMON_
#include "sr_types.h"

#define CAN_ML_START_PROTECT		0xffffffff
#define CAN_ML_STOP_PROTECT			0xfffffffe

struct sr_ml_can_msg {
	SR_U32		msg_id;						/* can message id */
	SR_32		K;							/* drift blocker */
	SR_32		h;							/* alarm threshold */
	SR_U32		mean_delta;					/* mean value of delta from learning sequence */
};

#endif /* SR_ML_CAN_COMMON_ */
