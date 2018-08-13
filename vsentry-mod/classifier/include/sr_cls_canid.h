#ifndef SR_CLS_CANID_H
#define SR_CLS_CANID_H

#include "sr_sal_common.h"
#include "sal_bitops.h"
#include "sr_canbus_common.h"
#include "sr_hash.h"

#define SR_MAX_CANID 4095 //FFF in hexa max CAN MSG ID

struct canid_ent_t {
	SR_32 key; //the key is the canid
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
void sr_cls_canid_empty_table(SR_BOOL is_lock);

int sr_cls_canid_add_rule(SR_32 canid, SR_U32 rulenum, SR_8 dir, SR_32 if_id);
int sr_cls_canid_del_rule(SR_32 canid, SR_U32 rulenum, SR_8 dir, SR_32 if_id);
struct sr_hash_ent_t *sr_cls_canid_find(SR_32 canid, SR_8 dir, SR_32 if_id);

bit_array *sr_cls_match_canid(SR_32 canid,SR_8 dir, SR_32 if_id);
bit_array *src_cls_out_canid_any(SR_32 id_if);
bit_array *src_cls_in_canid_any(SR_32 id_if);

SR_8 sr_cls_canid_msg_dispatch(struct sr_cls_canbus_msg *msg);

#ifdef DEBUGFS_SUPPORT
struct sr_hash_table_t * get_cls_in_can_table(void);
struct sr_hash_table_t * get_cls_out_can_table(void);
#endif

char *sr_cls_get_interface_name(SR_32 if_id);

SR_32 sr_cls_get_can_id(SR_U8 dev_id, SR_U8 *can_if_id);

#endif
