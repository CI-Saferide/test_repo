#ifndef SR_CLS_CANBUS_CONTROL_H
#define SR_CLS_CANBUS_CONTROL_H

int sr_cls_canid_add_rule(SR_U32 canid, SR_U32 rulenum);
int sr_cls_canid_del_rule(SR_U32 canid, SR_U32 rulenum);

#endif /* SR_CLS_CANBUS_CONTROL_H */