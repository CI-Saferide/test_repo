#ifndef SR_CLS_NETWORK_CONTROL_H
#define SR_CLS_NETWORK_CONTROL_H

int sr_cls_add_ipv4(SR_U32 addr, char *exec_proc, char *user, SR_U32 netmask, int rulenum, SR_U8 dir);
int sr_cls_del_ipv4(SR_U32 addr, char *exec_proc, char *user, SR_U32 netmask, int rulenum, SR_U8 dir);

#endif /* SR_CLS_NETWORK_CONTROL_H */
