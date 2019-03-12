#ifndef __CAN_CLS_H__
#define __CAN_CLS_H__

#include "classifier.h"
#include "bitops.h"

#define MSGID_ANY 		(unsigned int)(-1)
#define CAN_MAX_IF_INDEX 	16
#define MAX_CAN_MSG_ID 		0x1FFFFFFFU

int can_cls_init(cls_hash_params_t *hash_params);
int can_cls_add_rule(unsigned int rule, can_header_t *data, unsigned int dir);
int can_cls_del_rule(unsigned int rule, can_header_t *data, unsigned int dir);
int can_cls_search(vsentry_event_t *can_ev, bit_array_t *verdict);
void can_print_hash(void);

#endif /* __CAN_CLS_H__ */
