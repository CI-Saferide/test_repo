#include "sr_sal_common.h"
#include "sr_cls_uid_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"

int sr_cls_uid_add_rule(enum sr_rule_type rule_type, SR_U32 uid, SR_U32 rulenum)
{
	sr_uid_msg_cls_t *msg;
	
	msg = (sr_uid_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_UID;			
			msg->sub_msg.msg_type = SR_CLS_UID_ADD_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.rule_type = rule_type;
			msg->sub_msg.uid=uid;						
			sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
		}


	return SR_SUCCESS;
}


int sr_cls_uid_del_rule(enum sr_rule_type rule_type, SR_U32 uid, SR_U32 rulenum)
{
	sr_uid_msg_cls_t *msg;

	msg = (sr_uid_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_UID;			
			msg->sub_msg.msg_type = SR_CLS_UID_DEL_RULE;			
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.rule_type = rule_type;
			msg->sub_msg.uid=uid;						
			sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
		}


	return SR_SUCCESS;
}
