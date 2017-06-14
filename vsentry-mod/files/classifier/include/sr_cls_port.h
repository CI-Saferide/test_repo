#ifndef SR_CLS_PORT_H
#define SR_CLS_PORT_H

#include "sal_bitops.h"
#define SR_MAX_PORT 65535

struct port_ent_t {
	SR_U32 key; //the key is the PORT
	SR_U32 type;
	struct sr_hash_ent_t *next;
	//SR_U16 port_num; //using the SR_U32 key for the PORT ...for now..
	SR_U32 rule;
	struct bit_array *bit_arr;
};

int sr_cls_port_init(void);
int sr_cls_port_add_rule(SR_U32 port, SR_U32 rulenum);
int sr_cls_port_del_rule(SR_U32 port, SR_U32 rulenum);
int sr_cls_port_find(SR_U32 port);
void sr_cls_port_ut(void);


#endif
