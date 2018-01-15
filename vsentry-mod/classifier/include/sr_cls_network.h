#ifndef SR_CLS_NETWORK_H
#define SR_CLS_NETWORK_H

#include "sr_types.h"
#include "sr_cls_network_common.h"
#include "sal_bitops.h"

extern bit_array sr_cls_network_src_any_rules;
extern bit_array sr_cls_network_dst_any_rules;

void sr_cls_network_ut(void) ;
SR_8 sr_cls_network_msg_dispatch(struct sr_cls_network_msg *msg);
void sr_cls_network_init(void);
void sr_cls_network_uninit(void);
bit_array *sr_cls_match_ip(SR_U32 addr, SR_8 dir);

int sr_cls_add_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum, SR_8 dir);
bit_array *src_cls_network_any_src(void);
bit_array *src_cls_network_any_dst(void);
bit_array *src_cls_network_local_src(void);
bit_array *src_cls_network_local_dst(void);
SR_BOOL cr_cls_is_ip_address_local(struct in_addr addr);

#endif /* SR_CLS_NETWORK_H */
