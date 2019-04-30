#ifndef __FILE_CLS_H__
#define __FILE_CLS_H__

#include "classifier.h"
#include "bitops.h"

typedef unsigned long (*get_file_inode_cb)(char *filename);

int 	file_cls_init(cls_hash_params_t *hash_params);
int 	file_cls_add_rule(unsigned int rule, file_event_t *file_ev);
int 	file_cls_del_rule(unsigned int rule, file_event_t *file_ev);
int 	file_cls_search(vsentry_event_t *file_ev, bit_array_t *verdict);
void 	file_cls_remove_inode(unsigned long *inode);
void 	file_cls_trim(int depth, int max_siblings);
void 	file_cls_trim_by_name(char *filename, int len);
void 	file_cls_update_tree_inodes(get_file_inode_cb cb);
void 	file_cls_clear_rules(int start, int end);

#ifdef CLS_DEBUG
char 	*get_file_name(file_event_t *ev);
void 	file_cls_print_tree(void);
#endif
#endif /* __FILE_CLS_H__ */
