#include "sr_sal_common.h"
#include "sr_cls_canbus_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"

int sr_cls_canid_add_rule(SR_U32 canid, SR_U32 rulenum)
{
	sr_canbus_msg_cls_t *msg;
	
	msg = (sr_canbus_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_CANBUS;			
			msg->sub_msg.msg_type = SR_CLS_CANID_ADD_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.canid=canid;						
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}


	return SR_SUCCESS;
}


int sr_cls_canid_del_rule(SR_U32 canid, SR_U32 rulenum)
{
	sr_canbus_msg_cls_t *msg;

	msg = (sr_canbus_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_CANBUS;			
			msg->sub_msg.msg_type = SR_CLS_CANID_DEL_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.canid=canid;						
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}


	return SR_SUCCESS;
}
