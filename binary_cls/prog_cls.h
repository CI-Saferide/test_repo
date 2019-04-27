#ifndef __PROG_CLS_H__
#define __PROG_CLS_H__

#include "classifier.h"
#include "bitops.h"

#define PROG_ANY 		(unsigned long)(-1)

typedef unsigned long (*get_file_inode_cb)(char *filename);

int  prog_cls_init(cls_hash_params_t *hash_params);
int  prog_cls_add_rule(cls_rule_type_e type, unsigned int rule, char* prog_name, unsigned long exec_ino, int len);
int  prog_cls_del_rule(cls_rule_type_e type, unsigned int rule, char* prog_name);
int  prog_cls_search(cls_rule_type_e type, id_event_t *data, bit_array_t *verdict);
void prog_cls_clear_rules(int start, int end);
void prog_cls_update_tree_inodes(get_file_inode_cb cb);
int  prog_find_free_rule(cls_rule_type_e type, unsigned int prog);

#ifdef CLS_DEBUG
void prog_print_hash(void);
#endif

#endif /* __PROG_CLS_H__ */
