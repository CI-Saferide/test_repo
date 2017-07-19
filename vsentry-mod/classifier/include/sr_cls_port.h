#ifndef SR_CLS_PORT_H
#define SR_CLS_PORT_H

#include "sr_sal_common.h"
#include "sal_bitops.h"
#include "sr_hash.h"
#define SR_MAX_PORT 65535
#define SR_PROTO_SELECTOR(proto) (proto==IPPROTO_UDP)?1:0

struct port_ent_t {
	SR_U32 key; //the key is the PORT
	SR_U32 type;
	struct sr_hash_ent_t *next;
	//SR_U16 port_num; //using the SR_U32 key for the PORT ...for now..
	SR_U32 rule;
	enum policy_cls ent_type;
	struct bit_array *bit_arr;
};

int sr_cls_port_init(void);
void sr_cls_port_ut(void);
void sr_cls_port_uninit(void);
int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum, SR_8 dir, SR_8 proto);
int sr_cls_port_del_rule(SR_U32 port, SR_U32 rulenum, SR_8 dir, SR_8 proto);
struct sr_hash_ent_t *sr_cls_port_find(SR_U32 port, SR_8 dir, SR_8 proto);
void sr_cls_print_port_rules(SR_U32 port, SR_8 dir, SR_8 proto);
bit_array *sr_cls_match_port(SR_U32 port, SR_8 dir, SR_8 proto);
bit_array *src_cls_port_any_src(void);
bit_array *src_cls_port_any_dst(void);

#endif
