#ifndef SR_CONTROL_COMMON_H
#define SR_CONTROL_COMMON_H
#include "sr_types.h"

typedef enum {
	SR_CONTROL_SET_STATE = 0,
#ifdef CONFIG_STAT_ANALYSIS
	SR_CONTROL_PRINT_CONNECTIONS,
	SR_CONTROL_TRANSMIT_CONNECTIONS,
	SR_CONTROL_GARBAGE_COLLECTION,
	SR_CONTROL_PRINT,
#endif
	SR_CONTROL_SET_MEM_OPT,
} sr_control_verb_t;

struct sr_control_msg {
	sr_control_verb_t msg_type;
	SR_BOOL	state;
	SR_U8 mem_opt;
};

#endif /* SR_CONTROL_COMMON_H */
