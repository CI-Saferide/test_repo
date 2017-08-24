#include "sr_control.h"
#include "sr_sal_common.h"

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
		default:
			break;
	}
	return SR_SUCCESS;
}
