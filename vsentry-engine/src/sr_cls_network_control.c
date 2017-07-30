#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"

int sr_cls_add_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum, SR_8 dir)
{							
	sr_network_msg_cls_t *msg;
	msg = (sr_network_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_CLS_NETWORK;			
		msg->sub_msg.msg_type = SR_CLS_IPV4_ADD_RULE;			
		msg->sub_msg.rulenum = rulenum;
		msg->sub_msg.addr = addr;
		msg->sub_msg.netmask = netmask;		
		msg->sub_msg.dir = dir;							
		sr_send_msg(ENG2MOD_BUF, sizeof(msg));
	}
	

	return SR_SUCCESS;
}

int sr_cls_del_ipv4(SR_U32 addr, SR_U32 netmask, SR_U16 rulenum)
{
	sr_network_msg_cls_t *msg;
	
	msg = (sr_network_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_NETWORK;			
			msg->sub_msg.msg_type = SR_CLS_IPV4_DEL_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.addr = addr;
			msg->sub_msg.netmask = netmask;						
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}

	return SR_SUCCESS;
}



