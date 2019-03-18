#ifndef __PROG_CLS_H__
#define __PROG_CLS_H__

#include "classifier.h"
#include "bitops.h"

#define PROG_ANY 		(unsigned int)(-1)

int  prog_cls_init(cls_hash_params_t *hash_params);
int  prog_cls_add_rule(cls_rule_type_e type, unsigned int rule, unsigned int exec_ino);
int  prog_cls_del_rule(cls_rule_type_e type, unsigned int rule, unsigned int exec_ino);
int  prog_cls_search(cls_rule_type_e type, id_event_t *data, bit_array_t *verdict);
int  prog_find_free_rule(cls_rule_type_e type, unsigned int prog);
void prog_print_hash(void);

#endif /* __PROG_CLS_H__ */
