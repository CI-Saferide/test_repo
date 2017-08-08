#ifndef SR_EVENT_RECEIVER_H
#define SR_EVENT_RECEIVER_H

void sr_event_receiver(SR_8 *msg_buff, SR_U32 msg_len);
int sr_cls_canid_add_rule(SR_U32 canid, SR_U32 rulenum);
int sr_cls_canid_del_rule(SR_U32 canid, SR_U32 rulenum);

#endif /* SR_CLS_CANBUS_CONTROL_H */
