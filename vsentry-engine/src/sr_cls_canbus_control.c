#include "sr_sal_common.h"
#include "sr_cls_canbus_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_engine_utils.h"

int sr_cls_canid_add_rule(SR_U32 canid, char *exec, char *user, SR_U32 rulenum)
{
	sr_canbus_msg_cls_t *msg;
 	SR_U32 inode;
 	SR_32 uid;
	int st;

	if ((st = sr_get_inode(exec, 0, &inode)) != SR_SUCCESS)  {
	    sal_printf("Error: %s failed getting inode \n", __FUNCTION__);
	    return st;
	}
	uid = sr_get_uid(user);
	
	msg = (sr_canbus_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_CANBUS;			
			msg->sub_msg.msg_type = SR_CLS_CANID_ADD_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.canid=canid;						
			msg->sub_msg.exec_inode=inode;						
			msg->sub_msg.uid=uid;						
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}


	return SR_SUCCESS;
}


int sr_cls_canid_del_rule(SR_U32 canid, char *exec, char *user, SR_U32 rulenum)
{
	sr_canbus_msg_cls_t *msg;
 	SR_U32 inode;
 	SR_32 uid;
	int st;

        if ((st = sr_get_inode(exec, 0, &inode)) != SR_SUCCESS)  {
            sal_printf("Error: %s failed getting inode \n", __FUNCTION__);
            return st;
        }
	uid = sr_get_uid(user);

	msg = (sr_canbus_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_CANBUS;			
			msg->sub_msg.msg_type = SR_CLS_CANID_DEL_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.canid=canid;						
			msg->sub_msg.exec_inode=inode;						
			msg->sub_msg.uid=uid;						
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}


	return SR_SUCCESS;
}
