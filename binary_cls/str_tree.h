#ifndef __STR_TREE_H__
#define __STR_TREE_H__

#include "stdbool.h"

typedef struct tree_node {
	unsigned int 	sibling_offset;
	unsigned int 	child_offset;
	unsigned int 	parent_offset;
	unsigned int	priv_offset;
	unsigned int	name_len;
	unsigned int	node_str_offset;
	unsigned int 	depth;
	unsigned int 	num_of_siblings;
	bool 		locked;
} tree_node_t;

typedef void (*cb_func)(tree_node_t *node, void *param);

tree_node_t 	*str_tree_init(void);
tree_node_t 	*str_tree_search(tree_node_t *root, char *str, unsigned int len, int *res);
tree_node_t	*str_tree_add(tree_node_t *root, char *new_str, int len);
int 		str_tree_reattach_node(tree_node_t *parent, tree_node_t *node);
int 		str_tree_detach_node(tree_node_t *node);
int 		str_tree_remove_by_name(tree_node_t *root, char *del_str, cb_func delete);
void 		str_tree_walk(tree_node_t *root, cb_func print, void *param);

#endif /* __STR_TREE_H__ */
