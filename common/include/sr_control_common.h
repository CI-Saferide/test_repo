#ifndef SR_CONTROL_COMMON_H
#define SR_CONTROL_COMMON_H
#include "sr_types.h"

enum {
	SR_CONTROL_SET_STATE = 0,
};

struct sr_control_msg {
	SR_U8 	msg_type;
	SR_BOOL	state;
};

#endif /* SR_CONTROL_COMMON_H */
