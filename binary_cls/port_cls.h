#ifndef __PORT_CLS_H__
#define __PORT_CLS_H__

#include "classifier.h"
#include "bitops.h"

#define PORT_ANY 	(unsigned int)(-1)
#define PORT_MAX 	(unsigned short)(-1)

int  port_cls_init(cls_hash_params_t *hash_params);
int  port_cls_add_rule(unsigned int rule, unsigned int port, unsigned int type, unsigned int dir);
int  port_cls_del_rule(unsigned int rule, unsigned int port, unsigned int type, unsigned int dir);
int  port_cls_search(ip_event_t *data, bit_array_t *verdict);
void port_cls_clear_rules(int start, int end);

#ifdef CLS_DEBUG
void port_print_hash(void);
#endif

#endif /* __PORT_CLS_H__ */
