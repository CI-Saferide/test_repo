#ifndef SR_CLS_RULES_CONTROL_H
#define SR_CLS_RULES_CONTROL_H

void sr_cls_rule_add(SR_32 rule_type, SR_U16 rulenum, SR_U16 actions, SR_8 file_ops, SR_U32 rl_max_rate, SR_U16 rl_exceed_action, SR_U16 log_target, SR_U16 email_id, SR_U16 phone_id, SR_U16 skip_rulenum);
void sr_cls_rule_del(SR_32 rule_type, SR_U16 rulenum);

#endif /* SR_CLS_RULES_CONTROL_H */
