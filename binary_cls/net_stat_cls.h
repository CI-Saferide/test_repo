#ifndef __NET_STAT_CLS_H__
#define __NET_STAT_CLS_H__

#include "classifier.h"
#include "bitops.h"

int net_stat_cls_init(cls_hash_params_t *hash_params);
int net_stat_cls_update_connection(vsentry_event_t *data);
int net_stat_cls_del_connection(ip_event_t *data);
void net_stat_print_hash(void);

#endif /* __NET_STAT_CLS_H__ */
