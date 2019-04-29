#ifndef __UID_CLS_H__
#define __UID_CLS_H__

#include "classifier.h"
#include "bitops.h"

#define UID_ANY 		(unsigned int)(-1)

int  uid_cls_init(cls_hash_params_t *hash_params);
int  uid_cls_add_rule(cls_rule_type_e type, unsigned int rule, unsigned int uid);
int  uid_cls_del_rule(cls_rule_type_e type, unsigned int rule, unsigned int uid);
int  uid_cls_search(cls_rule_type_e type, id_event_t *data, bit_array_t *verdict);
void uid_cls_clear_rules(int start, int end);
int  uid_find_free_rule(cls_rule_type_e type, unsigned int uid);
void uid_print_hash(void);

#endif /* __UID_CLS_H__ */
