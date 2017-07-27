#include "sr_sal_common.h"
#include "sr_cls_port_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
	
int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum, SR_8 dir, SR_8 proto)
{
	sr_port_msg_cls_t *msg;
	
	msg = (sr_port_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_PORT;			
			msg->sub_msg.msg_type = SR_CLS_PORT_ADD_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.port=port;
			msg->sub_msg.dir=dir;
			msg->sub_msg.proto=proto;								
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}

	return SR_SUCCESS;
}
int sr_cls_port_del_rule(SR_U32 port, SR_U32 rulenum, SR_8 dir, SR_8 proto)
{
	sr_port_msg_cls_t *msg;
	
	msg = (sr_port_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_PORT;			
			msg->sub_msg.msg_type = SR_CLS_PORT_ADD_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.port=port;
			msg->sub_msg.dir=dir;
			msg->sub_msg.proto=proto;								
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}

	return SR_SUCCESS;
}
