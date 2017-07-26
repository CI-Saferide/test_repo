#ifndef SR_CLS_CANID_H
#define SR_CLS_CANID_H

#include "sr_sal_common.h"
#include "sal_bitops.h"
#include "sr_cls_canbus_common.h"
#include "sr_hash.h"

#define SR_MAX_CANID 4095 //FFF in hexa max CAN MSG ID

struct canid_ent_t {
	SR_U32 key; //the key is the canid
	SR_U32 type;
	struct sr_hash_ent_t *next;
	//SR_U16 canid_num; //using the SR_U32 key for the canid ...for now..
	SR_U32 rule;
	enum policy_cls ent_type;
	struct bit_array *bit_arr;
};

int sr_cls_canid_init(void);
void sr_cls_canid_ut(void);
void sr_cls_canid_uninit(void);
int sr_cls_canid_add_rule(SR_U32 canid, SR_U32 rulenum);
int sr_cls_canid_del_rule(SR_U32 canid, SR_U32 rulenum);
struct sr_hash_ent_t *sr_cls_canid_find(SR_U32 canid);
void sr_cls_print_canid_rules(SR_U32 canid);
bit_array *sr_cls_match_canid(SR_U32 canid);
bit_array *src_cls_canid(void);
SR_8 sr_cls_canid_msg_dispatch(struct sr_cls_canbus_msg *msg);

#endif
