#include <stddef.h>
#include <linux/vsentry/vsentry.h>
#include "hash.h"
#include "prog_cls.h"
#include "bitops.h"
#include "aux.h"
#include "heap.h"
#include "str_tree.h"

#ifdef PROG_DEBUG
#define prog_dbg cls_dbg
#define prog_err cls_err
#else
#define prog_dbg(...)
#define prog_err(...)
#endif

/* this struct holds the memory offset of the prog trees,
 * hashes and any rules. either previously initialized or
 * will be initialized by init */
typedef struct __attribute__ ((aligned(8))) {
	bit_array_t	any_rules;
	unsigned int 	str_tree_offset;
	unsigned int	hash_offset;
} prog_offset_t;

static prog_offset_t *prog_info = NULL;

/* this array will hold the string tree pointer (executables names)
 * per type */
static tree_node_t *prog_str_trees[CLS_TOTAL_RULE_TYPE];

/* prog hash item */
typedef struct __attribute__ ((aligned(8))) {
	unsigned long 	exec_ino;
	bit_array_t 	rules;
	unsigned int 	tree_node_offset;
} prog_hash_item_t;

#define PROG_HASH_NUM_OF_BITS 	10

/* hash key generate function for prog */
static unsigned int prog_hash_genkey(void *data, unsigned int number_of_bits)
{
	prog_hash_item_t *prog_item = (prog_hash_item_t*)data;

	return hash32(prog_item->exec_ino, PROG_HASH_NUM_OF_BITS);
}

/* compare the hash item vs prog */
static bool prog_hash_compare(void *candidat, void *searched)
{
	prog_hash_item_t *prog_item;
	unsigned long *prog_ino_searched;

	prog_item = (prog_hash_item_t*)candidat;
	prog_ino_searched = (unsigned long*)searched;

	if (*prog_ino_searched == prog_item->exec_ino)
		return true;

	return false;
}

#ifdef CLS_DEBUG
/* print prog item content */
static void prog_print_item(void *data)
{
	prog_hash_item_t *prog_item = (prog_hash_item_t*)data;

	cls_printf("    exec_ino %lu rules: ", prog_item->exec_ino);
	ba_print_set_bits(&prog_item->rules);
}
#endif

/*  global array of 3 prog hashs (can, ip, file) */
static hash_t prog_hash_array[CLS_TOTAL_RULE_TYPE] = {
	{
		.name = "prog_ip_hash",
		.bits = PROG_HASH_NUM_OF_BITS,
	},
	{
		.name = "prog_can_hash",
		.bits = PROG_HASH_NUM_OF_BITS,
	},
	{
		.name = "prog_file_hash",
		.bits = PROG_HASH_NUM_OF_BITS,
	},
};

/* global hash ops struct for prog hash */
static hash_ops_t prog_hash_ops;

/* prog hash init function */
int prog_cls_init(cls_hash_params_t *hash_params)
{
	int i;

	/* init the hash ops */
	prog_hash_ops.comp = prog_hash_compare;
	prog_hash_ops.create_key = prog_hash_genkey;
#ifdef CLS_DEBUG
	prog_hash_ops.print = prog_print_item;
#endif

	/* init the 3 prog hash array ops */
	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++)
		prog_hash_array[i].hash_ops = &prog_hash_ops;

	/* initialize the executables trees, hashes and any rules*/
	if (hash_params->hash_offset == 0) {
		/* not previously allocated. lets allocate */
		prog_info = heap_calloc(CLS_TOTAL_RULE_TYPE * sizeof(prog_offset_t));

		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
			/* initialize the ANY rule */
			ba_clear(&prog_info[i].any_rules);

			/* initialize the executables string tree */
			prog_str_trees[i] = str_tree_init();
			if (!prog_str_trees[i]) {
				prog_err("failed to initialize prog string tree\n");
				return VSENTRY_ERROR;
			}

			prog_info[i].str_tree_offset = get_offset(prog_str_trees[i]);

			/* initialize the executables inode hash */
			if (hash_create(&prog_hash_array[i]) != VSENTRY_SUCCESS) {
				prog_err("failed to allocate prog inode hash\n");
				return VSENTRY_ERROR;
			}

			prog_info[i].hash_offset = get_offset(prog_hash_array[i].buckets);
		}

		/* update the global database, will be used in the next boot */
		hash_params->hash_offset = get_offset(prog_info);
	} else {
		/* restore previously allocated hashes and trees */
		prog_info = get_pointer(hash_params->hash_offset);

		for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
			/* initialize the executables string tree */
			prog_str_trees[i] = get_pointer(prog_info[i].str_tree_offset);
			/* initialize the executables inode hash */
			prog_hash_array[i].buckets = get_pointer(prog_info[i].hash_offset);
			hash_set_ops(&prog_hash_array[i]);
		}

		/* ANY rules should already be set (no need to do it)*/
	}

	return VSENTRY_SUCCESS;
}

/* add new prog rule */
int prog_cls_add_rule(cls_rule_type_e type, unsigned int rule, char* prog_name, unsigned long exec_ino, int len)
{
	bit_array_t *arr = NULL;

	if (type >= CLS_TOTAL_RULE_TYPE || !prog_name || rule >= MAX_RULES)
		return VSENTRY_ERROR;

	/* set the rule bit in bit array */
	if (len == 1 && *prog_name == '*') {
		/* this is any rule */
		arr = &prog_info[type].any_rules;
	} else {
		/* add prog to tree */
		prog_hash_item_t *prog_item = NULL;
		tree_node_t *prog = str_tree_add(prog_str_trees[type], prog_name, len);

		if (!prog) {
			prog_err("failed to add prog %s to %s prog str tree\n",
					prog_name, get_type_str(type));
			return VSENTRY_ERROR;
		}

		if (!prog->priv_offset) {
			/* allocate priv and hash this node (if not 0)*/
			if (exec_ino) {
				/* check if this inode already hashed */
				prog_item = hash_get_data(&prog_hash_array[type], &exec_ino);
				if (prog_item) {
					prog_dbg("over-writing existing inode %lu\n", exec_ino);
					hash_remove_data(&prog_hash_array[type], &exec_ino);
				}
			}

			if (!prog_item) {
				prog_item = heap_calloc(sizeof(prog_hash_item_t));
				if (!prog_item) {
					prog_err("failed to allocate prog_item for file %s\n", prog_name);
					return VSENTRY_ERROR;
				}

				prog_item->tree_node_offset = get_offset(prog);
				prog_item->rules.empty = true;
			}

			prog_item->exec_ino = exec_ino;

			/* only hash actual inodes */
			if (prog_item->exec_ino)
				hash_insert_data(&prog_hash_array[type], prog_item);

			prog->priv_offset = get_offset(prog_item);
			prog_dbg("created new file rule for file %s inode %lu\n", prog_name, exec_ino);
		} else {
			prog_item = get_pointer(prog->priv_offset);
			prog_dbg("updating file rule for file %s inode %lu\n", prog_name, exec_ino);

			/* check if we need to update the inode and hash */
			if (prog_item->exec_ino != exec_ino) {
				if (prog_item->exec_ino)
					hash_remove_data(&prog_hash_array[type], (void*)&prog_item->exec_ino);

				prog_item->exec_ino = exec_ino;
				if (prog_item->exec_ino)
					hash_insert_data(&prog_hash_array[type], prog_item);
			}
		}

		arr = &prog_item->rules;
	}

	if (!ba_is_set(rule, arr)) {
		ba_set_bit(rule, arr);
		prog_dbg("set bit %u on %s prog rule %s inode %lu\n",
				rule, get_type_str(type), prog_name, exec_ino);
	}

	return VSENTRY_SUCCESS;
}

static void prog_cls_delete_node(tree_node_t *node, void *param)
{
	unsigned int i;

	if (node->locked)
		return;

	/* param in this function represent the root of the tree/sub-tree
	 * we are working on. dont delete it */
	if (!param || param == node)
		return;

	if (node->child_offset) {
		prog_err("can't delete node %s with child\n", get_pointer(node->node_str_offset));
		return;
	}

	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
		if (param == &prog_str_trees[i])
			break;
	}

	if (i == CLS_TOTAL_RULE_TYPE)
		return;

	prog_dbg("deleting %s prog %s\n", get_type_str(i), get_pointer(node->node_str_offset));

	if (node->priv_offset) {
		prog_hash_item_t *prog_item = get_pointer(node->priv_offset);

		if (prog_item->exec_ino)
			/* if this prog_item have inode, we assume it is hashed.
			 * the hash will delete the prog_item */
			hash_delete_data(&prog_hash_array[i], (void*)&prog_item->exec_ino);
		else
			heap_free(get_pointer(node->priv_offset));

		node->priv_offset = 0;
	}

	str_tree_detach_node(node);

	heap_free(get_pointer(node->node_str_offset));
	heap_free(node);
}

int prog_cls_del_rule(cls_rule_type_e type, unsigned int rule, char* prog_name)
{
	if (type >= CLS_TOTAL_RULE_TYPE || !prog_name || rule >= MAX_RULES)
		return VSENTRY_ERROR;

	prog_dbg("del %s prog rule %u prog %s\n", get_type_str(type), rule, prog_name);

	/* set the rule bit in bit array */
	if (*prog_name == '*') {
		/* clear the bit in the any rule bit array */
		ba_clear_bit(rule, &prog_info[type].any_rules);
	} else {
		tree_node_t *prog = NULL;
		prog_hash_item_t *prog_item = NULL;
		int len = vs_strlen(prog_name);
		int res = 0;

		/* search if prog exist */
		prog = str_tree_search(prog_str_trees[type], prog_name, len, &res);
		if (!prog || res) {
			prog_err("could not find prog %s in %s prog str tree\n",
					prog_name, get_type_str(type));
			return VSENTRY_NONE_EXISTS;
		}

		/* check if the rule was set for this file */
		if (!prog->priv_offset) {
			prog_err("no rules are set on this prog\n", prog_name);
			return VSENTRY_NONE_EXISTS;
		}

		prog_item = get_pointer(prog->priv_offset);
		if (!ba_is_set(rule, &prog_item->rules)) {
			prog_err("rule %u was not set on prog %s\n", rule, prog_name);
			return VSENTRY_NONE_EXISTS;
		}

		/* clear the bit in the bit array */
		ba_clear_bit(rule, &prog_item->rules);

		prog_dbg("clear bit %u on file %s\n", rule, prog_name);

		/* if bit array is empty we can free the bit array */
		if (ba_is_empty(&prog_item->rules)) {
			tree_node_t *parent = get_pointer(prog->parent_offset);

			/* if this node have no child, remove from tree */
			if (!prog->child_offset)
				prog_cls_delete_node(prog, &prog_str_trees[type]);

			/* check if we can remove unneeded parent as well
			 * (i.e. node without rules) */
			while (!parent->child_offset && !parent->priv_offset) {
				tree_node_t *grandparent = get_pointer(parent->parent_offset);
				prog_cls_delete_node(parent, &prog_str_trees[type]);
				parent = grandparent;
			}
		}
	}

	return VSENTRY_SUCCESS;
}

/* classification function. find the matched bit array (if any)
 * and AND it with verdict */
int prog_cls_search(cls_rule_type_e type, id_event_t *data, bit_array_t *verdict)
{
	bit_array_t *arr_any = NULL;
	tree_node_t *prog = NULL;
	prog_hash_item_t *prog_item = NULL;

	int res = 0;

	/* in case kernel is the exec code we cannot classify.
	 * let other classifiers to decide. */
	if (data->kernel)
		return VSENTRY_SUCCESS;

	if (type >= CLS_TOTAL_RULE_TYPE) {
		prog_err("invalid prog type\n");
		return VSENTRY_INVALID;
	}

	arr_any = &prog_info[type].any_rules;

	/* try search by name */
	if (data->exec_name) {
		prog = str_tree_search(prog_str_trees[type], data->exec_name, data->exec_name_len, &res);
		if (!res && prog && prog->priv_offset) {
			prog_item = get_pointer(prog->priv_offset);
			if (prog_item)
				goto prog_cls;
		}
	}

	/* try search by inode */
	if (data->exec_ino)
		prog_item = hash_get_data(&prog_hash_array[type], &data->exec_ino);

prog_cls:
	if (prog_item) {
		if (!ba_is_empty(arr_any))
			/* if we have non-empty ANY rule , verdict calculation:
			 * verdict = verdict & (ANY | RULE)*/
			ba_and_or(verdict, verdict, &prog_item->rules, arr_any);
		else
			/* no ANY rule, just AND verdict with specific rule */
			ba_and(verdict, verdict, &prog_item->rules);

		return VSENTRY_SUCCESS;
	}

#ifdef ENABLE_LEARN
	if (cls_get_mode() == VSENTRY_MODE_LEARN) {
		/* in learn mode we dont want to get the any rule
		 * since we want to learn this event, so we clear the
		 * verdict bitmap to signal no match */
		ba_clear(verdict);
		return VSENTRY_SUCCESS;
	}
#endif

	/* no specific rule, just AND verdict with ANY rule */
	ba_and(verdict, verdict, arr_any);

	return VSENTRY_SUCCESS;
}

static char buffer[4096];
static int current_buf_len;

typedef struct {
	int start;
	int end;
	int type;
} prog_rules_limit_t;

static void check_prog_rule(tree_node_t *node, void *param)
{
	char *filename = NULL;

	if (node->locked) {
		/* this node is have a siblings/child. copy name to buffer */
		filename = get_pointer(node->node_str_offset);

		if (node->name_len) {
			vs_memcpy(&buffer[current_buf_len], filename, node->name_len);
			current_buf_len += node->name_len;
			buffer[current_buf_len] = 0;
		}

		if (node->name_len && node->child_offset) {
			buffer[current_buf_len] = '/';
			current_buf_len++;
		}
	} else {
		if (!node->child_offset && node->priv_offset) {
			prog_hash_item_t *prog_item= get_pointer(node->priv_offset);
			prog_rules_limit_t* limit = param;
			int i;

			/* this is a leaf in the tree. print. */
			filename = get_pointer(node->node_str_offset);

			vs_memcpy(&buffer[current_buf_len], filename, node->name_len);
			current_buf_len += node->name_len;
			buffer[current_buf_len] = 0;

			/* delete rules */
			for (i=limit->start; i<limit->end; i++) {
				if (ba_is_set(i, &prog_item->rules))
					prog_cls_del_rule(limit->type, i, buffer);
			}

			current_buf_len -= node->name_len;
		} else {
			if (node->name_len)
				current_buf_len -= (node->name_len + 1);
		}
	}
}

void prog_cls_clear_rules(int start, int end)
{
	int i;
	prog_rules_limit_t limit = {
		.start = start,
		.end = end,
	};

	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
		vs_memset(buffer, 0, 4096);
		buffer[0] = '/';
		current_buf_len = 1;
		limit.type = i;

		str_tree_walk(prog_str_trees[i], check_prog_rule, &limit);
	}
}

typedef struct {
	get_file_inode_cb cb;
	hash_t *hash;
} prog_update_inode_param_t;

static void update_node_inode(tree_node_t *node, void *param)
{
	prog_update_inode_param_t *update_param = (prog_update_inode_param_t*)param;
	char *filename = NULL;

	if (node->locked) {
		/* this node is have a siblings/child. copy name to buffer */
		filename = get_pointer(node->node_str_offset);

		if (node->name_len) {
			vs_memcpy(&buffer[current_buf_len], filename, node->name_len);
			current_buf_len += node->name_len;
			buffer[current_buf_len] = 0;
		}

		if (node->priv_offset) {
			prog_hash_item_t *prog_item = get_pointer(node->priv_offset);

			prog_item->exec_ino = update_param->cb(buffer);
//			prog_dbg("setting prog %s inode %lu\n", buffer, prog_item->exec_ino);
			if (prog_item->exec_ino)
				hash_insert_data(update_param->hash, prog_item);
		}

		if (node->name_len && node->child_offset) {
			buffer[current_buf_len] = '/';
			current_buf_len++;
		}
	} else {
		if (!node->child_offset && node->priv_offset) {
			/* this is a leaf in the tree. print. */
			filename = get_pointer(node->node_str_offset);

			vs_memcpy(&buffer[current_buf_len], filename, node->name_len);
			current_buf_len += node->name_len;
			buffer[current_buf_len] = 0;

			if (node->priv_offset) {
				prog_hash_item_t *prog_item = get_pointer(node->priv_offset);

				prog_item->exec_ino = update_param->cb(buffer);
//				prog_dbg("setting prog %s inode %lu\n", buffer, prog_item->exec_ino);
				if (prog_item->exec_ino)
					hash_insert_data(update_param->hash, prog_item);
			}

			current_buf_len -= node->name_len;
		} else {
			if (node->name_len)
				current_buf_len -= (node->name_len + 1);
		}
	}
}

static int prog_hash_clear_inode(void *data)
{
	prog_hash_item_t *prog_item = (prog_hash_item_t*)data;

	/* just mark the inode zero */
	prog_item->exec_ino = 0;

	return VSENTRY_SUCCESS;
}

void prog_cls_update_tree_inodes(get_file_inode_cb cb)
{
	void *tmp = NULL;
	int i;
	prog_update_inode_param_t update_param;

	/* when updating inodes we would like to delete the hash private content but
	 * dont want to delete the hash items as it contain the rules bit array.
	 * so well temporarily replace the hash delete callback (which delete the hash data)
	 * with stub and restore it when done
	 */

	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
		vs_memset(buffer, 0, 4096);
		buffer[0] = '/';
		current_buf_len = 1;

		tmp = prog_hash_array[i].hash_ops->del_data;
		prog_hash_array[i].hash_ops->del_data = prog_hash_clear_inode;

		hash_empty_data(&prog_hash_array[i]);

		update_param.cb = cb;
		update_param.hash = &prog_hash_array[i];
		str_tree_walk(prog_str_trees[i], update_node_inode, &update_param);

		prog_hash_array[i].hash_ops->del_data = tmp;
	}
}

#ifdef CLS_DEBUG

/* callback function that prints the file tree elements */

static void prog_cls_print_node(tree_node_t *node, void *param)
{
	char *filename = NULL;
	prog_hash_item_t *prog_item= get_pointer(node->priv_offset);

	if (node->locked) {
		/* this node is have a siblings/child. copy name to buffer */
		filename = get_pointer(node->node_str_offset);

		if (node->name_len) {
			vs_memcpy(&buffer[current_buf_len], filename, node->name_len);
			current_buf_len += node->name_len;
			buffer[current_buf_len] = 0;
		}

		/* print only file with rules */
		if (node->priv_offset) {
			cls_printf("    %s (inode %lu) : ", buffer, prog_item->exec_ino);
			ba_print_set_bits(&prog_item->rules);
		}

		if (node->name_len && node->child_offset) {
			buffer[current_buf_len] = '/';
			current_buf_len++;
		}
	} else {
		if (!node->child_offset && node->priv_offset) {
			/* this is a leaf in the tree. print. */
			filename = get_pointer(node->node_str_offset);

			vs_memcpy(&buffer[current_buf_len], filename, node->name_len);
			current_buf_len += node->name_len;
			buffer[current_buf_len] = 0;

			cls_printf("    %s (inode %lu) : ", buffer, prog_item->exec_ino);
			ba_print_set_bits(&prog_item->rules);

			current_buf_len -= node->name_len;
		} else {
			if (node->name_len)
				current_buf_len -= (node->name_len + 1);
		}
	}
}

/* print all prog hash array */
void prog_print_hash(void)
{
	unsigned int i;

	cls_printf("executable db:\n");

	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
		vs_memset(buffer, 0, 4096);
		buffer[0] = '/';
		current_buf_len = 1;

		cls_printf("  %s tree\n", get_type_str(i));

		str_tree_walk(prog_str_trees[i], prog_cls_print_node, NULL);
	}

	cls_printf("  any ip : ");
	ba_print_set_bits(&prog_info[CLS_IP_RULE_TYPE].any_rules);

	cls_printf("  any can : ");
	ba_print_set_bits(&prog_info[CLS_CAN_RULE_TYPE].any_rules);

	cls_printf("  any file : ");
	ba_print_set_bits(&prog_info[CLS_FILE_RULE_TYPE].any_rules);

	for (i=0; i<CLS_TOTAL_RULE_TYPE; i++) {
		cls_printf("  hash %s\n", prog_hash_array[i].name);
		hash_print(&prog_hash_array[i]);
	}

	cls_printf("\n");
}
#endif
