#include "sr_sal_common.h"
#include "sr_actions_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"

void sr_cls_rule_add(SR_32 rule_type,
						SR_U16 rulenum,
						SR_U16 actions,
						SR_8 file_ops,
						sr_rate_type_t rate_type,
						SR_U32 rl_max_rate,
						SR_U16 rl_exceed_action,
						SR_U16 log_target,
						SR_U16 email_id,
						SR_U16 phone_id,
						SR_U16 skip_rulenum)
{
	sr_rules_msg_cls_t *msg;
	
	msg = (sr_rules_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_RULES;			
			msg->sub_msg.msg_type = SR_CLS_RULES_ADD;			
			msg->sub_msg.rule_type = rule_type;
			msg->sub_msg.rulenum = rulenum;	
			msg->sub_msg.actions = actions;
			msg->sub_msg.file_ops = file_ops;
			msg->sub_msg.rate_type = rate_type;
			msg->sub_msg.rl_max_rate = rl_max_rate;
			msg->sub_msg.rl_exceed_action=rl_exceed_action;	
			msg->sub_msg.log_target = log_target;
			msg->sub_msg.email_id = email_id;
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.phone_id = phone_id;	
			msg->sub_msg.skip_rulenum = skip_rulenum;
			
			sr_send_msg(ENG2MOD_BUF, (SR_32)sizeof(msg));
		}
}


void sr_cls_rule_del(SR_32 rule_type, SR_U16 rulenum)
{
	sr_rules_msg_cls_t *msg;

	msg = (sr_rules_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_RULES;			
			msg->sub_msg.msg_type = SR_CLS_RULES_DEL;			
			msg->sub_msg.rule_type = rule_type;
			msg->sub_msg.rulenum = rulenum;						
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}


	//return SR_SUCCESS;
}
