#include "classifier.h"
#include "str_tree.h"
#include "heap.h"
#include "aux.h"

#ifdef STR_TREE_DEBUG
#define str_tree_dbg cls_dbg
#define str_tree_err cls_err
#else
#define str_tree_dbg(...)
#define str_tree_err(...)
#endif

/* initialize the string tree root */
tree_node_t *str_tree_init(void)
{
	tree_node_t *root = heap_calloc(sizeof(tree_node_t));
	if(!root) {
		str_tree_dbg("failed to allocate string tree\n");
		return NULL;
	}

	root->parent_offset = get_offset(root);

	return root;
}

/* search a string in the string tree. the function will return
 * the closest node.
 * str - the string to search for in the form of /a/b/c.
 * len - str length.
 * res - number of chars that were not matched */
tree_node_t *str_tree_search(tree_node_t *root, char *str, unsigned int len, int *res)
{
	tree_node_t *tmp, *match = root;
	char *ptr = str;
	int residue = len; /* the number of chars we have not matched */

	/* validity check */
	if (!root || !str || !len || *str != '/')
		return NULL;

	/* if str is '/' --> return root */
	if (len == 1 && *str == '/') {
		residue--;
		goto search_exit;
	}

	/* if root have no child or is '/' --> return root */
	if (!root->child_offset)
		goto search_exit;

	/* start searching from 1st root child */
	tmp = get_pointer(root->child_offset);

	while (residue && tmp) {
		char *delimiter = ptr;

		if (*ptr != '/') {
			str_tree_err("malformed string %s at %s\n", str, ptr);
			return NULL;
		}

		/* skip '/' */
		ptr++;
		residue--;

		/* find the delimiter '/' or '\0' */
		delimiter = ptr;
		while (*delimiter != '/' && *delimiter != 0)
			delimiter++;

		/* search for string in node */
		if (((delimiter - ptr) == tmp->name_len) &&
				(vs_memcmp(get_pointer(tmp->node_str_offset), ptr, tmp->name_len) == 0)) {
			/* update the amount of chars not checked */
			residue -= tmp->name_len;
			/* move ptr to the next comparison point */
			ptr = delimiter;
			/* set match node */
			match = tmp;
			/* do we need to go further down the tree ??*/
			if (*ptr == '/') {
				tmp = get_pointer(tmp->child_offset);
				continue;
			}
		}

		/* move to the next sibling */
		tmp = get_pointer(tmp->sibling_offset);

		if (residue) {
			/* move back to '/' */
			ptr--;
			residue++;
		}
	}

search_exit:
//	str_tree_dbg("found match name %s res %d\n", get_pointer(match->node_str_offset), residue);

	/* update the number of unmatched chars */
	if (res)
		*res = residue;

	return match;
}

/* add new string to the string tree */
tree_node_t *str_tree_add(tree_node_t *root, char *new_str, int len)
{
	tree_node_t *matched, *tmp = NULL;
	int res = 0;
	char *ptr = new_str;

	if (!new_str || !root || !len)
		return NULL;

	/* search if already exist */
	matched = str_tree_search(root, new_str, len, &res);
	if (!res)
		/* full match, i.e. already exists */
		return matched;

	/* start adding from the closest node and skip the first '/'*/
	ptr += (len - res);

	while (res > 0) {
		char *delimiter, *str;

		if (*ptr == '/')
			/* skip '/' */
			ptr++;

		/* find the delimiter '/' or '\0' */
		delimiter = ptr;
		while (*delimiter != '/' && *delimiter != 0)
			delimiter++;

		/* allocate a new node */
		tmp = heap_calloc(sizeof(tree_node_t));
		if(!tmp) {
			str_tree_err("failed to allocate new tree node\n");
			return NULL;
		}

		/* fill info */
		tmp->name_len = (delimiter - ptr);
		str = heap_calloc(tmp->name_len + 1);
		vs_memcpy(str, ptr, tmp->name_len);
		tmp->node_str_offset = get_offset(str);
		tmp->parent_offset = get_offset(matched);
		tmp->depth = matched->depth + 1;

		/* update parent number of siblings */
		matched->num_of_siblings++;

		if (matched->child_offset) {
			/* parent have child, go to the last one in the list */
			matched = get_pointer(matched->child_offset);
			while (matched->sibling_offset)
				matched = get_pointer(matched->sibling_offset);

			/* set the new node as the last node sibling  */
			matched->sibling_offset = get_offset(tmp);
		} else {
			/* no child, set the new node as 1st child */
			matched->child_offset = get_offset(tmp);
		}

		/* update the number of unmatched chars */
		res -= (tmp->name_len + 1);
		ptr = delimiter;

		matched = tmp;
	}

	if (res != 0)
		str_tree_dbg("something is wrong, res %u\n", res);

	return tmp;
}

int str_tree_reattach_node(tree_node_t *parent, tree_node_t *node)
{
	if (!node || !parent || parent == node)
		return VSENTRY_ERROR;

	if (parent->child_offset)
		node->sibling_offset = parent->child_offset;

	/* set as parent 1st child */
	parent->child_offset = get_offset(node);

	node->parent_offset = get_offset(parent);
	node->depth = parent->depth + 1;

	/* update parent number of siblings */
	parent->num_of_siblings++;

	return VSENTRY_SUCCESS;
}

int str_tree_detach_node(tree_node_t *node)
{
	tree_node_t *sibling = NULL, *parent = NULL;

	/* 1. find the parent */
	parent = get_pointer(node->parent_offset);
	if (!parent || parent == node)
		return VSENTRY_ERROR;

	/* 2. detach the node from the parent/sibling */
	if (parent->child_offset == get_offset(node)) {
		/* matched is the 1st element in list so update parent
		 * to point to the next sibling */
		parent->child_offset = node->sibling_offset;
	} else {
		/* travel the list and find the node with the removed node as sibling */
		sibling = get_pointer(parent->child_offset);
		while (get_pointer(sibling->sibling_offset) != node)
			sibling = get_pointer(sibling->sibling_offset);

		/* update the node to point to matched sibling */
		sibling->sibling_offset = node->sibling_offset;
		if (!sibling->sibling_offset)
			/* if matched is the last in the list, update
			 * the previous node parent */
			sibling->parent_offset = node->parent_offset;
	}

	parent->num_of_siblings--;

	node->parent_offset = get_offset(node);
	node->sibling_offset = 0;
	node->depth = 0;

	return VSENTRY_SUCCESS;
}

/* delete a string (and the sub-tree) from the tree */
int str_tree_remove_by_name(tree_node_t *root, char *del_str, cb_func delete)
{
	tree_node_t *matched = NULL;
	int len, res = 0;

	/* validity check */
	if (!del_str || *del_str != '/')
		return VSENTRY_ERROR;

	/* skip any consecutive '/' */
	while (*(del_str+1) == '/')
		del_str++;

	len = vs_strlen(del_str);
	if (!len)
		return VSENTRY_ERROR;

	/* search string */
	matched = str_tree_search(root, del_str, len, &res);
	if (res || !matched) {
		/* not full match, i.e. does not exist */
		str_tree_dbg("%s not found\n", del_str);
		return VSENTRY_ERROR;
	}

	str_tree_detach_node(matched);

	/* delete the sub-tree */
	if (matched->child_offset)
		/* pass NULL as param since we want this node to deleted as well. */
		str_tree_walk(matched, delete, NULL);

	return VSENTRY_SUCCESS;
}

/* walk the tree starting from root first child and invoke cb function*/
void str_tree_walk(tree_node_t *root, cb_func cb, void *param)
{
	tree_node_t *tmp;
//	char *filename;

	if (!root)
		return;

	if (!root->child_offset) {
		cb(root, param);
		return;
	}

	tmp = root;

	do {
		tree_node_t *next = NULL;

//		filename = get_pointer(tmp->node_str_offset);

		if (tmp->locked) {
			/* we already visited this node */
			if (tmp != root && tmp->sibling_offset)
				/* visit sibling but not root siblings */
				next = get_pointer(tmp->sibling_offset);
			else
				/* go back to parent */
				next = get_pointer(tmp->parent_offset);

			tmp->locked = false;

			/* we call the cb again to inform (if needed) that we completed
			 * the walk in this sub tree and move to parent/sibling.
			 * in case cb is for delete this is the place to delete.
			 * in case cb is for print, this is the place to remove
			 * this node name from buffer */
//			cls_dbg("revisit unlocked %s\n", filename);
			cb(tmp, param);

			tmp = next;

		} else {
			/* we have not visited this node yet */
			tmp->locked = true;

			/* if this node have siblings .. visit them */
			if (tmp->child_offset) {
				/* we call cb with locked node to inform we
				 * start the walk in a sub tree */
//				cls_dbg("visit locked %s\n", filename);
				cb(tmp, param);
				/* visit child */
				tmp = get_pointer(tmp->child_offset);
				continue;
			}

			tmp->locked = false;

			if (tmp != root && tmp->sibling_offset)
				/* visit sibling */
				next = get_pointer(tmp->sibling_offset);
			else
				/* go back to parent */
				next = get_pointer(tmp->parent_offset);

			/* this node have no siblings,
			 * in case cb is for delete this is the place to delete.
			 * in case cb is for print, this is the place to remove
			 * this node name from buffer */
//			cls_dbg("visit unlocked %s\n", filename);
			cb(tmp, param);

			tmp = next;
		}
	} while (tmp != root);

	tmp->locked = false;
	cb(tmp, param);
}
