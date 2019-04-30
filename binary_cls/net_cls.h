#ifndef __NET_CLS_H__
#define __NET_CLS_H__

#include "classifier.h"
#include "bitops.h"

int  net_cls_init(cls_hash_params_t *hash_params);
int  net_cls_add_rule(unsigned int rule, unsigned int ip, unsigned int mask, unsigned int dir);
int  net_cls_del_rule(unsigned int rule, unsigned int ip, unsigned int mask, unsigned int dir);
int  net_cls_search(ip_event_t *data, bit_array_t *verdict);
void net_cls_clear_rules(int start, int end);

#ifdef CLS_DEBUG
void net_print_tree(void);
#endif

#endif /* __NET_CLS_H__ */
