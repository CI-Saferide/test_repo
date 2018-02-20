#ifndef SR_CLS_PORT_CONTROL_H
#define SR_CLS_PORT_CONTROL_H

int sr_cls_port_add_rule(SR_U32 port, char *exec, char *user, SR_U32 rulenum, SR_U8 dir, SR_U8 proto);
int sr_cls_port_del_rule(SR_U32 port, char *exec, char *user, SR_U32 rulenum, SR_U8 dir, SR_U8 proto);

#endif /* SR_CLS_PORT_CONTROL_H */
