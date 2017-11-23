#include "sr_control.h"
#include "sr_sal_common.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#endif

static SR_BOOL vsentry_state = SR_TRUE;

void vsentry_set_state (SR_BOOL state)
{
	vsentry_state = state;
}
SR_BOOL vsentry_get_state(void)
{
	return (vsentry_state);
}

SR_8 sr_control_msg_dispatch(struct sr_control_msg *msg)
{
	switch (msg->msg_type) {
		case SR_CONTROL_SET_STATE:
			if ((SR_TRUE == msg->state) && (SR_TRUE == vsentry_state))
				sal_kernel_print_info("vsentry state is already enabled\n");
			else if ((SR_FALSE == msg->state) && (SR_FALSE == vsentry_state))
				sal_kernel_print_info("vsentry state is already diabled\n");
			else {
				vsentry_state = msg->state;
				sal_kernel_print_warn("vsentry state changed to %s\n", (vsentry_state == SR_TRUE)? "enabled" : "disabled");
			}
			break;
#if CONFIG_STAT_ANALYSIS
		case SR_CONTROL_PRINT_CONNECTIONS:
			sr_stat_analisys_print_connections(SR_FALSE);
			break;
		case SR_CONTROL_TRANSMIT_CONNECTIONS:
			if (sr_stat_analysis_start_transmit() != SR_SUCCESS) {
				sal_kernel_print_err("TRansmission of connection failed \n");
				return SR_ERROR;
			}
			break;
		case SR_CONTROL_GARBAGE_COLLECTION:
			sr_stat_analysis_garbage_collector();			
			break;
#endif
		default:
			break;
	}
	return SR_SUCCESS;
}
