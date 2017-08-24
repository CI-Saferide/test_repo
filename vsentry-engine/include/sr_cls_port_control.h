#ifndef SR_CLS_PORT_CONTROL_H
#define SR_CLS_PORT_CONTROL_H

int sr_cls_port_add_rule(SR_U32 port, char *exec, SR_U32 rulenum, SR_8 dir, SR_8 proto);
int sr_cls_port_del_rule(SR_U32 port, char *exec, SR_U32 rulenum, SR_8 dir, SR_8 proto);

#endif /* SR_CLS_PORT_CONTROL_H */
