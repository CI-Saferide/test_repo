#ifndef __IP_PROTO_CLS_H__
#define __IP_PROTO_CLS_H__

#include "classifier.h"
#include "bitops.h"

#define IP_PROTO_ANY 		(unsigned int)(-1)
#define IP_PROTO_MAX 		0xFF

int  ip_proto_cls_init(cls_hash_params_t *hash_params);
int  ip_proto_cls_add_rule(unsigned int rule, unsigned int proto);
int  ip_proto_cls_del_rule(unsigned int rule, unsigned int proto);
int  ip_proto_cls_search(ip_event_t *data, bit_array_t *verdict);
void ip_proto_cls_clear_rules(int start, int end);

#ifdef CLS_DEBUG
void ip_proto_print_hash(void);
#endif

#endif /* __IP_PROTO_CLS_H__ */
