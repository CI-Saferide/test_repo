#include "sr_sal_common.h"
#include "sr_control_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_engine_utils.h"
	
SR_32 sr_control_set_state(SR_BOOL state)
{
	sr_control_msg_t *msg;

	set_engine_state(state);
	msg = (sr_control_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CONTROL;			
			msg->sub_msg.msg_type = SR_CONTROL_SET_STATE;			
			msg->sub_msg.state = state;
			sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
		}

	return SR_SUCCESS;
}
	
SR_32 sr_control_set_mem_opt(cls_file_mem_optimization_t mem_opt)
{
	sr_control_msg_t *msg;

	msg = (sr_control_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_CONTROL;			
		msg->sub_msg.msg_type = SR_CONTROL_SET_MEM_OPT,
		msg->sub_msg.mem_opt = mem_opt;
		sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
	}

	return SR_SUCCESS;
}
	
SR_32 sr_control_util(sr_control_verb_t control_type)
{
	sr_control_msg_t *msg;

	msg = (sr_control_msg_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_CONTROL;			
		msg->sub_msg.msg_type = control_type;			
		sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
	}

	return SR_SUCCESS;
}
