#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_engine_utils.h"

int sr_cls_add_ipv4(SR_U32 addr, char *exec, char *user, SR_U32 netmask, int rulenum, SR_U8 dir)
{							
	sr_network_msg_cls_t *msg;
	SR_U32 inode;
	SR_32 uid, st;

	if ((st = sr_get_inode(exec, &inode)) != SR_SUCCESS) {
	    CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=%s failed getting inode",REASON,
			__FUNCTION__);
	    return st; 
	}
	uid = sr_get_uid(user);

	msg = (sr_network_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
	if (msg) {
		msg->msg_type = SR_MSG_TYPE_CLS_NETWORK;			
		msg->sub_msg.msg_type = SR_CLS_IPV4_ADD_RULE;			
		msg->sub_msg.rulenum = (SR_U16)rulenum;
		msg->sub_msg.addr = addr;
		msg->sub_msg.netmask = netmask;		
		msg->sub_msg.dir = dir;
		msg->sub_msg.exec_inode = inode;
		msg->sub_msg.uid = uid;
		sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
	}
	

	return SR_SUCCESS;
}

int sr_cls_del_ipv4(SR_U32 addr, char *exec, char *user, SR_U32 netmask, SR_U16 rulenum, SR_U8 dir)
{
	sr_network_msg_cls_t *msg;
	SR_U32 inode;
	SR_32 uid;
	int st;
	
	if ((st = sr_get_inode(exec, &inode)) != SR_SUCCESS)  {
	    CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"S5=%s failed getting inode",REASON,
			__FUNCTION__);
	    return st; 
	}
	uid = sr_get_uid(user);

	msg = (sr_network_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_NETWORK;			
			msg->sub_msg.msg_type = SR_CLS_IPV4_DEL_RULE;			
			msg->sub_msg.rulenum = (SR_U16)rulenum;
			msg->sub_msg.addr = addr;
			msg->sub_msg.netmask = netmask;						
			msg->sub_msg.dir = dir;
			msg->sub_msg.exec_inode = inode;
			msg->sub_msg.uid = uid;
			sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
		}

	return SR_SUCCESS;
}



