#ifndef __SR_ML_CAN__
#define __SR_ML_CAN__

#include "sr_types.h"

typedef struct ml_can_ts {
   SR_U32		sec;		/* time stamp of last message in sec */
   SR_U32		usec;		/* time stamp of last message in usec */
} ml_can_ts_t;

typedef struct ml_can_item {
   SR_U32		msg_id;		/* can message id */
   SR_U64		ts;			/* time stamp of last message, in usec */
   SR_U32		delta;		/* delta between last two messages, in usec */
   SR_U32		noise;		/* difference between last two deltas */
} ml_can_item_t;

SR_32 sr_ml_can_hash_init(void);
void ml_can_get_raw_data(SR_U64 ts, SR_U32 msg_id);
void sr_ml_can_print_hash(void);
void sr_ml_can_hash_deinit(void);

#endif /* __SR_ML_CAN__ */
