#ifndef __WHITE_LIST_CAN_H__
#define __WHITE_LIST_CAN_H__

#include "sr_ec_common.h"
#include "sr_canbus_common.h"

typedef struct wl_can_item {
	SR_U32		msg_id;				/* can message id */
	SR_U8 	dir; //inbound/outbound msg
	SR_32 if_id;
	SR_32 dev_id;
	struct wl_can_item *next;		/* ptr for linked list of can MSGID */
}sr_wl_can_item_t;

/*
typedef struct wl_can_head {
	sr_wl_can_item_t *can_in;			//ptr to next inbound can 
	sr_wl_can_item_t *can_out;			//ptr to next outbound can
}sr_wl_can_head_t;
*/

SR_32 sr_white_list_canbus(struct sr_ec_can_t *can_info);
void sr_white_list_canbus_print(sr_wl_can_item_t *wl_canbus);
void sr_white_list_canbus_cleanup(sr_wl_can_item_t *wl_canbus);
SR_32 sr_white_list_canbus_apply(SR_BOOL is_protect);
SR_32 sr_white_list_canbus_init(void);

#endif
