#ifndef __SR_ML_CAN__
#define __SR_ML_CAN__

#include "sr_types.h"

typedef enum {
	SR_ML_CAN_MODE_LEARN,
	SR_ML_CAN_MODE_PROTECT,
	SR_ML_CAN_MODE_HALT,
} sr_ml_can_mode_t;

typedef struct ml_can_ts {
   SR_U32		sec;						/* time stamp of last message in sec */
   SR_U32		usec;						/* time stamp of last message in usec */
} ml_can_ts_t;

typedef struct ml_can_item {
   SR_U32		msg_id;						/* can message id */
   SR_U64		ts;							/* time stamp of last message, in usec */
   SR_U32		delta;						/* delta between last two messages, in usec */
   SR_32		d_delta;					/* difference between last two deltas */
   SR_U32		calc_sigma_plus;			/* max(0, sigma_plus + d_delta - K) */
   SR_U32		calc_sigma_minus;			/* max(0, sigma_plus - d_delta - K) */
   SR_32		K;							/* drift blocker */
   SR_32		h;							/* alarm threshold */
   SR_U64		sum_delta;					/* sum of all the delta accumulated within learning time */
   SR_U32		samples;					/* number of samples taken to sum_delta */
   SR_U32		mean_delta;					/* mean value of delta from learning sequence */
} ml_can_item_t;

SR_32 sr_ml_can_hash_init(void);
void ml_can_get_raw_data(SR_U64 ts, SR_U32 msg_id);
void sr_ml_can_print_hash(void);
void sr_ml_can_hash_deinit(void);
void ml_can_set_state(sr_ml_can_mode_t state);

#endif /* __SR_ML_CAN__ */
