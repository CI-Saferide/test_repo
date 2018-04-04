#include "sr_control.h"
#include "sr_sal_common.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#endif

static SR_BOOL vsentry_state = SR_TRUE;
static struct config_params_t config_params;
static SR_32 sr_vsentryd_pid;

struct config_params_t *sr_control_config_params(void)
{
	return &config_params;
}

void vsentry_set_state (SR_BOOL state)
{
	vsentry_state = state;
}
SR_BOOL vsentry_get_state(void)
{
	return (vsentry_state);
}

void vsentry_set_pid(SR_32 pid)
{
	sr_vsentryd_pid = pid;
}
	
SR_32 vsentry_get_pid()
{
	return sr_vsentryd_pid;
}

SR_8 sr_control_msg_dispatch(struct sr_control_msg *msg)
{
	switch (msg->msg_type) {
		case SR_CONTROL_SET_STATE:
			if ((SR_TRUE == msg->state) && (SR_TRUE == vsentry_state))
				CEF_log_event(SR_CEF_CID_SYSTEM, "warning", SEVERITY_MEDIUM,
							"msg=vsentry state is already enabled");
			else if ((SR_FALSE == msg->state) && (SR_FALSE == vsentry_state))
				CEF_log_event(SR_CEF_CID_SYSTEM, "warning", SEVERITY_MEDIUM,
							"msg=vsentry state is already disabled");
			else {
				vsentry_state = msg->state;
				CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
								"msg=vsentry state changed to %s", (vsentry_state == SR_TRUE)? "enabled" : "disabled");	
			}
			break;
#ifdef CONFIG_STAT_ANALYSIS
		case SR_CONTROL_PRINT_CONNECTIONS:
#ifdef SR_STATS_ANALYSIS_DEBUG
			sr_stat_analisys_print_connections(SR_FALSE);
#endif
			break;
		case SR_CONTROL_TRANSMIT_CONNECTIONS:
			if (sr_stat_analysis_start_transmit() != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"reason=Transmission of connection failed");
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

SR_32 sr_config_handle_message(struct sr_config_msg *msg)
{
	config_params.cef_max_rate = msg->cef_max_rate;
	return SR_SUCCESS;
}
