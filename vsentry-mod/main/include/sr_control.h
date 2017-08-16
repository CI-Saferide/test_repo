#ifndef __SR_CONTROL__
#define __SR_CONTROL__

#include "sr_types.h"
#include "sr_control_common.h"

void 	vsentry_set_state (SR_BOOL state);
SR_BOOL vsentry_get_state(void);
SR_8 	sr_control_msg_dispatch(struct sr_control_msg *msg);

#endif /* __SR_CONTROL__ */
