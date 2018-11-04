#include "sr_sal_common.h"
#include "sr_canbus_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_engine_utils.h"

static SR_32 get_can_interface_id(char *interface, SR_32 *if_id, SR_32 *dev_id)
{
	if (is_special_can_interface(interface)) {
		return (sr_can_get_special_dev_id(interface, if_id, dev_id));
	}
	*dev_id = 0;
	return sal_get_interface_id(interface, if_id);
}

int sr_cls_canid_add_rule(SR_U32 canid, char *exec, char *user, SR_U32 rulenum,SR_U8 dir, char *interface)
{
	sr_canbus_msg_cls_t *msg;
 	SR_U32 inode;
 	SR_32 uid, st;
 	SR_32 if_id, dev_id;

	if ((st = sr_get_inode(exec, &inode)) != SR_SUCCESS)  {
	    CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=can add:failed to get exec inode for can rule, exec %s, rule %d",REASON, exec, rulenum);
	    return st;
	}
	uid = sr_get_uid(user);
	if (get_can_interface_id(interface, &if_id, &dev_id) != SR_SUCCESS) {
		 CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=can add:failed to get id for interface %s, rule %d",REASON, interface, rulenum);
		 return SR_ERROR;
	}
	
	msg = (sr_canbus_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_CANBUS;			
			msg->sub_msg.msg_type = SR_CLS_CANID_ADD_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.canid=canid;	
			msg->sub_msg.dir=dir;					
			msg->sub_msg.exec_inode=inode;						
			msg->sub_msg.uid=uid;
			msg->sub_msg.if_id = if_id;
			msg->sub_msg.dev_id = dev_id;
			sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
		}


	return SR_SUCCESS;
}


int sr_cls_canid_del_rule(SR_U32 canid, char *exec, char *user, SR_U32 rulenum, SR_U8 dir, char *interface)
{
	sr_canbus_msg_cls_t *msg;
 	SR_U32 inode;
 	SR_32 uid, if_id, dev_id;

	int st;

        if ((st = sr_get_inode(exec, &inode)) != SR_SUCCESS)  {
            CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=can del:failed to get exec inode for can rule, exec %s, rule %d",REASON, exec, rulenum);
            return st;
        }
	uid = sr_get_uid(user);
	if (get_can_interface_id(interface, &if_id, &dev_id) != SR_SUCCESS) {
		 CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=can add:failed to get id for interface %s, rule %d",REASON, interface, rulenum);
		 return SR_ERROR;
	}

	msg = (sr_canbus_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_CANBUS;			
			msg->sub_msg.msg_type = SR_CLS_CANID_DEL_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.canid=canid;
			msg->sub_msg.dir=dir;						
			msg->sub_msg.exec_inode=inode;						
			msg->sub_msg.uid=uid;
			msg->sub_msg.if_id = if_id;
			msg->sub_msg.dev_id = dev_id;
			sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
		}


	return SR_SUCCESS;
}
