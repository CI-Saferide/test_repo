#ifndef SR_CLS_NETWORK_H
#define SR_CLS_NETWORK_H

#include "sr_types.h"
#include "sr_cls_network_common.h"
#include "sal_bitops.h"

extern bit_array sr_cls_network_src_any_rules;
extern bit_array sr_cls_network_dst_any_rules;
#ifdef UNIT_TEST
extern struct radix_head *sr_cls_src_ipv4;
extern struct radix_head *sr_cls_dst_ipv4;
#endif

SR_8 sr_cls_network_msg_dispatch(struct sr_cls_network_msg *msg);
void sr_cls_network_init(void);
void sr_cls_network_uninit(void);
bit_array *sr_cls_match_ip(SR_U32 addr, SR_8 dir);

int sr_cls_add_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum, SR_8 dir);
#ifdef UNIT_TEST
int sr_cls_del_ipv4(SR_U32 addr, SR_U32 netmask, int rulenum, SR_8 dir);
#endif
bit_array *src_cls_network_any_src(void);
bit_array *src_cls_network_any_dst(void);
bit_array *src_cls_network_local_src(void);
bit_array *src_cls_network_local_dst(void);
SR_BOOL cr_cls_is_ip_address_local(struct in_addr addr);
SR_32 local_ips_array_init(void);
struct radix_head* get_cls_src_ipv4_table(void);
struct radix_head* get_cls_dst_ipv4_table(void);

#endif /* SR_CLS_NETWORK_H */
