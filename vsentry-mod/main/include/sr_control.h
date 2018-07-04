#ifndef __SR_CONTROL__
#define __SR_CONTROL__

#include "sr_types.h"
#include "sr_control_common.h"
#include "sr_config_common.h"

struct config_params_t {
	SR_U8	cef_max_rate;						/* max allowed cef message rate per second for classifier and ml algorithms */	
	SR_U16	def_file_action;					/* default action for file classifier */
	SR_U16	def_can_action;						/* default action for canbus classifier */
	SR_U16	def_net_action;						/* default action for network classifier */
	SR_U8	system_policer_interval;				/* system policer interval mesaured */
};

void 	vsentry_set_state (SR_BOOL state);
SR_BOOL vsentry_get_state(void);
SR_8 	sr_control_msg_dispatch(struct sr_control_msg *msg);
SR_32   sr_config_handle_message(struct sr_config_msg *msg);
struct config_params_t *sr_control_config_params(void);
void vsentry_set_pid(SR_32);
SR_32 vsentry_get_pid(void);

#endif /* __SR_CONTROL__ */
