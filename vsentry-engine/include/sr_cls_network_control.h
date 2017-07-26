#ifndef SR_CLS_NETWORK_CONTROL_H
#define SR_CLS_NETWORK_CONTROL_H

int sr_cls_ipv4_add_rule(SR_U32 addr, SR_U32 netmask, SR_U16 rulenum);
int sr_cls_ipv4_del_rule(SR_U32 addr, SR_U32 netmask, SR_U16 rulenum);

#endif /* SR_CLS_NETWORK_CONTROL_H */
