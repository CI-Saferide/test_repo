#ifndef SR_CLS_NETWORK_H
#define SR_CLS_NETWORK_H

#include "sr_types.h"
#include "sr_cls_network_common.h"

SR_8 sr_cls_network_msg_dispatch(struct sr_cls_network_msg *msg);
void sr_cls_network_init(void);
void sr_cls_network_uninit(void);
bit_array *sr_cls_match_ip(SR_U32 addr, SR_8 dir);

int sr_cls_add_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum, SR_8 dir);

#endif /* SR_CLS_NETWORK_H */
