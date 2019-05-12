#include <stddef.h>
#include "can_cls.h"
#include "bitops.h"
#include "hash.h"
#include "aux.h"
#include "heap.h"
#include "str_tree.h"
#include "file_cls.h"
#include "lru_cache.h"

#ifdef FILE_DEBUG
#define file_dbg cls_dbg
#define file_err cls_err
#else
#define file_dbg(...)
#define file_err(...)
#endif

#ifdef CLS_DEBUG
char *get_file_name(file_event_t *ev)
{
	switch (ev->type) {
	case FILE_TYPE_SYSFS:
		return "sys";
	case FILE_TYPE_PROCFS:
		return "proc";
	case FILE_TYPE_REG:
		if (ev->filename)
			return ev->filename;
		return "n/a";
	default:
		return "n/a";
	}
}
#endif

static volatile int during_hash_update = 0;
static volatile int file_cls_usage = 0;

typedef struct {
	unsigned int root_offset;
	unsigned int hash_offset;
	unsigned int rules_modes_offset;
	unsigned int procfs_rules_offset;
	unsigned int sysfs_rules_offset;
} file_hash_t;

static tree_node_t *root = NULL;
static file_hash_t *file_hash = NULL;
/* each rule is assigned with file mode (rd/wr/ex). this is the pointer to this array of modes */
static unsigned char *rules_modes = NULL;
/* for procfs we allow each executable to access its own proc (this is decided
 * by the kernel patch). if an executable access other proc but its own it will
 * be granted with access to all procfs. this was decided as we assume that if an executable
 * access other's procfs, it will require accessing to all processes proc (like ps, top, etc) */
static bit_array_t *procfs_rules = NULL;
/* same rational as procfs but for sysfs the kernel patch does not take any decision.
 * either an executable can access sysfs or not */
static bit_array_t *sysfs_rules = NULL;

/* file hash item */
typedef struct __attribute__ ((aligned(8))) {
	unsigned long 	file_ino;
	bit_array_t 	rules;
	unsigned int 	tree_node_offset;
} file_hash_item_t;

#define FILE_HASH_NUM_OF_BITS 	10

/***********************************************************************
 * function:    file_hash_genkey
 * description:
 * in param:    n/a.
 * out param:   n/a.
 * return:      n/a.
 **********************************************************************/
static unsigned int file_hash_genkey(void *data, unsigned int number_of_bits)
{
	file_hash_item_t *file_item = (file_hash_item_t*)data;

	return hash32(file_item->file_ino, FILE_HASH_NUM_OF_BITS);
}

/* compare the hash item vs file */
static bool file_hash_compare(void *candidat, void *searched)
{
	file_hash_item_t *file_item;
	unsigned long *file_ino_searched;

	file_item = (file_hash_item_t*)candidat;
	file_ino_searched = (unsigned long*)searched;

	if (*file_ino_searched == file_item->file_ino)
		return true;

	return false;
}

#ifdef CLS_DEBUG
/* print file item content */
static void file_print_item(void *data)
{
	file_hash_item_t *file_item = (file_hash_item_t*)data;

	cls_printf("    file_ino %lu rules: ", file_item->file_ino);
	ba_print_set_bits(&file_item->rules);
}
#endif

static hash_t file_inode_hash = {
	.name = "file_hash",
	.bits = FILE_HASH_NUM_OF_BITS,
};

/* global hash ops struct for file hash */
static hash_ops_t file_hash_ops;

int file_cls_init(cls_hash_params_t *hash_params)
{
	/* init the hash ops */
	file_hash_ops.comp = file_hash_compare;
	file_hash_ops.create_key = file_hash_genkey;
#ifdef CLS_DEBUG
	file_hash_ops.print = file_print_item;
#endif

	file_inode_hash.hash_ops = &file_hash_ops;

	/* initialize the file string tree */
	if (hash_params->hash_offset == 0) {
		/* tree was not previously allocated. lets allocate.
		 * first we allocate memory to preserve the tree offset */
		file_hash = heap_calloc(sizeof(file_hash_t));
		if (!file_hash) {
			file_err("failed to allocate file_hash\n");
			return VSENTRY_ERROR;
		}

		root = str_tree_init();
		if (!root) {
			file_err("failed to allocate files string tree root\n");
			return VSENTRY_ERROR;
		}

		file_hash->root_offset = get_offset(root);

		rules_modes = heap_calloc(MAX_RULES);
		if (!rules_modes) {
			file_err("failed to allocate files rules_modes\n");
			return VSENTRY_ERROR;
		}

		file_hash->rules_modes_offset = get_offset(rules_modes);

		procfs_rules = heap_calloc(sizeof(bit_array_t));
		if (!procfs_rules) {
			file_err("failed to allocate files procfs_rules\n");
			return VSENTRY_ERROR;
		}
		procfs_rules->empty = true;

		file_hash->procfs_rules_offset = get_offset(procfs_rules);

		sysfs_rules = heap_calloc(sizeof(bit_array_t));
		if (!sysfs_rules) {
			file_err("failed to allocate files rules_modes\n");
			return VSENTRY_ERROR;
		}
		sysfs_rules->empty = true;

		file_hash->sysfs_rules_offset = get_offset(sysfs_rules);

		if (hash_create(&file_inode_hash) != VSENTRY_SUCCESS)
			return VSENTRY_ERROR;

		file_hash->hash_offset = get_offset(file_inode_hash.buckets);

		/* update the global database, will be used in the next boot */
		hash_params->hash_offset = get_offset(file_hash);
	} else {
		/* restore previously allocated tree */
		file_hash = get_pointer(hash_params->hash_offset);
		root = get_pointer(file_hash->root_offset);
		rules_modes = get_pointer(file_hash->rules_modes_offset);
		procfs_rules = get_pointer(file_hash->procfs_rules_offset);
		sysfs_rules = get_pointer(file_hash->sysfs_rules_offset);
		file_inode_hash.buckets = get_pointer(file_hash->hash_offset);
		hash_set_ops(&file_inode_hash);
	}

	return VSENTRY_SUCCESS;
}

/* callback function that do ba_or on file bitmap with parent_arr */
static void file_cls_inherit_rules(tree_node_t *node, void *parent_arr)
{
	if (node->priv_offset) {
		file_hash_item_t *file_item = get_pointer(node->priv_offset);
		ba_or(&file_item->rules, &file_item->rules, parent_arr);
	}
}

int file_cls_add_rule(unsigned int rule, file_event_t *file_ev)
{
	tree_node_t *file = NULL, *parent = NULL;
	file_hash_item_t *file_item = NULL;

	if (!file_ev || !file_ev->mode || file_ev->type >= FILE_TYPE_TOTAL || rule >= MAX_RULES)
		return VSENTRY_INVALID;

	switch(file_ev->type) {
	case FILE_TYPE_SYSFS:
		if (!ba_is_set(rule, sysfs_rules)) {
			file_dbg("set bit %u on sysfs\n", rule);
			ba_set_bit(rule, sysfs_rules);
		}
		goto set_mode;
	case FILE_TYPE_PROCFS:
		if (!ba_is_set(rule, procfs_rules)) {
			file_dbg("set bit %u on procfs\n", rule);
			ba_set_bit(rule, procfs_rules);
		}
		goto set_mode;
	case FILE_TYPE_REG:
		break;
	default:
		file_err("invalid file type %u\n", file_ev->type);
		return VSENTRY_INVALID;
	}

	if (!file_ev->filename_len || !file_ev->filename)
		return VSENTRY_INVALID;

	if (file_ev->filename_len == 1 && *file_ev->filename == '*') {
		/* in files, ANY is root directory '/' */
		file = root;
	} else {
		/* add path to string tree */
		file = str_tree_add(root, file_ev->filename, file_ev->filename_len);
		if (!file) {
			file_err("failed to add file %s to file str tree\n", file_ev->filename);
			return VSENTRY_ERROR;
		}
	}

	if (!file->priv_offset) {
		/* allocate priv and hash this node (if not 0)*/
		if (file_ev->file_ino) {
			/* check if this inode already hashed */
			file_item = hash_get_data(&file_inode_hash, &file_ev->file_ino);
			if (file_item) {
				file_dbg("over-writing existing inode %lu\n", file_ev->file_ino);
				hash_remove_data(&file_inode_hash, (void*)&file_ev->file_ino);
			}
		}

		if (!file_item) {
			file_item = heap_calloc(sizeof(file_hash_item_t));
			if (!file_item) {
				file_err("failed to allocate file_item for file %s\n", file_ev->filename);
				return VSENTRY_ERROR;
			}

			file_item->tree_node_offset = get_offset(file);
			file_item->rules.empty = true;
		}

		file_item->file_ino = file_ev->file_ino;

		/* only hash actual inodes */
		if (file_item->file_ino)
			hash_insert_data(&file_inode_hash, file_item);

		file->priv_offset = get_offset(file_item);
		file_dbg("created new file rule for file %s inode %lu\n", file_ev->filename, file_item->file_ino);
	} else {
		file_item = get_pointer(file->priv_offset);
		file_dbg("updating file rule for file %s inode %lu\n", file_ev->filename, file_item->file_ino);

		/* check if we need to update the inode and hash */
		if (file_item->file_ino != file_ev->file_ino) {
			if (file_item->file_ino)
				hash_remove_data(&file_inode_hash, (void*)&file_item->file_ino);

			file_item->file_ino = file_ev->file_ino;
			if (file_item->file_ino)
				hash_insert_data(&file_inode_hash, file_item);
		}
	}

	/* set the rule bit in bit array */
	if (!ba_is_set(rule, &file_item->rules)) {
		file_dbg("set bit %u on file %s\n", rule, file_ev->filename);
		ba_set_bit(rule, &file_item->rules);
	}

	if (file != root) {
		/* inherit rules from parent */
		parent = get_pointer(file->parent_offset);
		while (parent) {
			if (parent->priv_offset) {
				file_hash_item_t *parent_file_item = get_pointer(parent->priv_offset);
				ba_or(&file_item->rules, &file_item->rules, &parent_file_item->rules);
				break;
			}

			if (parent == root)
				break;

			parent = get_pointer(parent->parent_offset);
		}
	}

	/* inherit this rule to all sub tree if exist */
	str_tree_walk(file, file_cls_inherit_rules, &file_item->rules);

set_mode:
	/* set the rule mode */
	if (rules_modes[rule] != (unsigned char)file_ev->mode) {
		rules_modes[rule] |= (unsigned char)file_ev->mode;
		file_dbg("set rule %u mode 0x%x\n", rule, rules_modes[rule]);
	}

	return VSENTRY_SUCCESS;
}

/* callback function that is called for each deleted node */
static void file_cls_delete_node(tree_node_t *node, void *param)
{
	if (node->locked) {
//		file_err("can't delete locked node %s\n", get_pointer(node->node_str_offset));
		return;
	}

	if (node->child_offset) {
//		file_err("can't delete node %s with child\n", get_pointer(node->node_str_offset));
		return;
	}

	file_dbg("deleting %s\n", get_pointer(node->node_str_offset));

	if (node->priv_offset) {
		file_hash_item_t *file_item = get_pointer(node->priv_offset);

		if (file_item->file_ino)
			/* if this file_item have inode, we assume it is hashed.
			 * the hash will delete the file_item */
			hash_delete_data(&file_inode_hash, (void*)&file_item->file_ino);
		else
			heap_free(get_pointer(node->priv_offset));

		node->priv_offset = 0;
	}

	/* param in this function represent the root of the tree/sub-tree
	 * we are working on. dont delete it */
	if (param == node)
		return;

	str_tree_detach_node(node);

	heap_free(get_pointer(node->node_str_offset));
	heap_free(node);
}

typedef struct {
	unsigned int count;
	unsigned int rule;
} rule_count_t;

/* callback function that checks if a rule is set in a file node */
static void file_cls_count_rule_refs(tree_node_t *node, void *param)
{
	rule_count_t *rule_counter = (rule_count_t*)param;

	if (node->priv_offset) {
		file_hash_item_t *file_item = get_pointer(node->priv_offset);

		if (ba_is_set(rule_counter->rule, &file_item->rules))
			rule_counter->count++;
	}
}

/* this function unset a rule in a file node bit array. if the array
 * is empty it will delete the node */
static int file_cls_del_rule_from_node(unsigned int rule, tree_node_t *file)
{
	file_hash_item_t *file_item = get_pointer(file->priv_offset);

	if (!file->priv_offset) {
		file_err("no rules are set on file %s\n", get_pointer(file->node_str_offset));
		return VSENTRY_NONE_EXISTS;
	}

	if (!ba_is_set(rule, &file_item->rules)) {
		file_err("rule %u was not set on file %s\n", rule, get_pointer(file->node_str_offset));
		return VSENTRY_NONE_EXISTS;
	}

	/* clear the bit in the bit array */
	ba_clear_bit(rule, &file_item->rules);
	file_dbg("cleared bit %u in file %s\n", rule, get_pointer(file->node_str_offset));

	/* if bit array is empty we can free the bit array */
	if (ba_is_empty(&file_item->rules)) {
		/* if this node have no child, remove from tree */
		if (!file->child_offset && file != root) {
			/* delete node from tree */
			file_cls_delete_node(file, root);
		} else {
			/* only clear its rules */
			heap_free(get_pointer(file->priv_offset));
			file->priv_offset = 0;
		}
	}

	return VSENTRY_SUCCESS;
}

/* unset a rule in a node file by name string */
int file_cls_del_rule(unsigned int rule, file_event_t *file_ev)
{
	tree_node_t *file = NULL;

	if (!file_ev || rule >= MAX_RULES)
		return VSENTRY_INVALID;

	switch(file_ev->type) {
	case FILE_TYPE_SYSFS:
		if (!ba_is_set(rule, sysfs_rules)) {
			file_err("rule %u was not set on sysfs\n", rule);
			return VSENTRY_NONE_EXISTS;
		}
		file_dbg("clear sysfs bit %u\n", rule);
		ba_clear_bit(rule, sysfs_rules);
		return VSENTRY_SUCCESS;
	case FILE_TYPE_PROCFS:
		if (!ba_is_set(rule, procfs_rules)) {
			file_err("rule %u was not set on procfs\n", rule);
			return VSENTRY_NONE_EXISTS;
		}
		file_dbg("clear procfs bit %u\n", rule);
		ba_clear_bit(rule, procfs_rules);
		return VSENTRY_SUCCESS;
	case FILE_TYPE_REG:
		break;
	default:
		file_err("invalid file type %u\n", file_ev->type);
		return VSENTRY_INVALID;
	}

	if (!file_ev->filename || !file_ev->filename_len)
		return VSENTRY_INVALID;

	file_dbg("delete file %s rule %u\n", file_ev->filename, rule);

	if (file_ev->filename_len == 1 && *file_ev->filename == '*') {
		/* in files, ANY is root directory '/' */
		file = root;
	} else {
		int res;
		/* search path in string tree */
		file = str_tree_search(root, file_ev->filename, file_ev->filename_len, &res);
		if (!file || res) {
			file_err("failed to find file %s in file str tree\n", file_ev->filename);
			return VSENTRY_ERROR;
		}
	}

	if (file_cls_del_rule_from_node(rule, file) != VSENTRY_SUCCESS)
		return VSENTRY_NONE_EXISTS;

	return VSENTRY_SUCCESS;
}

int file_cls_search(vsentry_event_t *file_ev, bit_array_t *verdict)
{
	tree_node_t *file = NULL;
	file_hash_item_t *file_item = NULL;
	int res = 0;

	if (!file_ev || file_ev->file_event.type >= FILE_TYPE_TOTAL)
		return VSENTRY_INVALID;

	/* update usage counter */
	__sync_add_and_fetch(&file_cls_usage, 1);

	/* wait until update finish */
	if (during_hash_update) {
		__sync_sub_and_fetch(&file_cls_usage, 1);
		return VSENTRY_BUSY;
	}

	/* handle procfs/sysfs */
	if (file_ev->file_event.type == FILE_TYPE_SYSFS || file_ev->file_event.type == FILE_TYPE_PROCFS) {
		if (file_ev->file_event.type == FILE_TYPE_SYSFS)
			ba_and(verdict, verdict, sysfs_rules);
		else
			ba_and(verdict, verdict, procfs_rules);
		goto check_mode;
	}

	/* try search by name */
	if (file_ev->file_event.filename && file_ev->file_event.filename_len) {
		/* file classifier is special in the sense that its ANY rule is actually
		 * the rule of the root directory. if root have no rule that means we dont
		 * have ANY rule. */

		/* search for the closest match in the tree */
		file = str_tree_search(root, file_ev->file_event.filename,
			file_ev->file_event.filename_len, &res);
#ifdef ENABLE_LEARN
		if (cls_get_mode() == VSENTRY_MODE_LEARN) {
			if (!file || res) {
				file_dbg("failed to find file %s len %u\n",
					file_ev->file_event.filename, file_ev->file_event.filename_len);
				/* in learn mode we dont want to get the any rule
				 * since we want to learn this event, so we clear the
				 * verdict bitmap to signal no match */
				ba_clear(verdict);

				/* update usage counter */
				__sync_sub_and_fetch(&file_cls_usage, 1);

				return VSENTRY_SUCCESS;
			}
		}
#endif
		if (!file) {
			/* we could not find and file match */
			file_err("could not find file match\n");

			/* update usage counter */
			__sync_sub_and_fetch(&file_cls_usage, 1);

			return VSENTRY_NONE_EXISTS;
		}

		/* go up the tree until we find bit array */
		while (!file->priv_offset) {
			file = get_pointer(file->parent_offset);
			if (!file) {
				/* we could not find and file match, clear bit array and return */
				file_err("could not find parent\n");

				/* update usage counter */
				__sync_sub_and_fetch(&file_cls_usage, 1);

				return VSENTRY_NONE_EXISTS;
			}

			if (file == root) {
				__sync_sub_and_fetch(&file_cls_usage, 1);

				return VSENTRY_NONE_EXISTS;
			}
		}

		file_item = get_pointer(file->priv_offset);
		goto and_ba;
	}

	/* try search by file inode */
	if (file_ev->file_event.file_ino) {
		unsigned int file_item_offset;
		/* look for the inode in cache */
		file_item_offset = cache_lookup(file_ev->file_event.file_ino);
		if (file_item_offset) {
			/* found in cache */
			file_dbg("found inode %lu in cache\n", file_ev->file_event.file_ino);
			file_item = get_pointer(file_item_offset);
			goto and_ba;
		}

		file_item = hash_get_data(&file_inode_hash, &file_ev->file_event.file_ino);
		if (!file_item) {
			/* try search by ancestor inode */
			file_item = hash_get_data(&file_inode_hash, &file_ev->file_event.ancestor_ino);
			if (!file_item) {
				/* update usage counter */
				__sync_sub_and_fetch(&file_cls_usage, 1);

				return VSENTRY_NONE_EXISTS;
			}
		}

		/* update the cache */
		file_dbg("adding inode %lu to cache\n", file_ev->file_event.file_ino);
		cache_update(file_ev->file_event.file_ino, get_offset(file_item));
	}

and_ba:
	ba_and(verdict, verdict, &file_item->rules);

check_mode:
	/* update usage counter */
	__sync_sub_and_fetch(&file_cls_usage, 1);

	if (!ba_is_empty(verdict)) {
		unsigned int rule = ba_ffs(verdict);
		if (rule == MAX_RULES) {
			file_err("file %s bitmap is not empty but failed to find action bit\n",
					get_file_name(&file_ev->file_event));
			return VSENTRY_NONE_EXISTS;
		}

		if ((rules_modes[rule] & (unsigned char)file_ev->file_event.mode) != (unsigned char)file_ev->file_event.mode) {
			/* mode is not allowed */
			file_err("file %s rule %u mode (%x) is not allowed (%x)\n",
					file_ev->file_event.filename?file_ev->file_event.filename:"",
					rule,
					(unsigned char)file_ev->file_event.mode, rules_modes[rule]);
			ba_clear(verdict);

			return VSENTRY_SUCCESS;
		}
	}

	return VSENTRY_SUCCESS;
}

static char buffer[4096];
static int current_buf_len;

/* the below struct help to determine which node should be trimmed */
typedef struct {
	int depth;
	int max_siblings;
} file_trim_limits_t;

/* callback function that do ba_or on file bitmap with parent_arr */
static void gather_node_rules(tree_node_t *node, void *parent_arr)
{
	if (!node->locked && node->priv_offset) {
		file_hash_item_t *file_item = get_pointer(node->priv_offset);
		ba_or(parent_arr, parent_arr, &file_item->rules);
	}
}

/* this function consolidate a node's sub-tree rules in to it's
 * own rule bit array. consolidation is based on limits in param */
static void trim_node(tree_node_t *node, void *param)
{
	file_trim_limits_t *l = (file_trim_limits_t*)param;
	file_hash_item_t *file_item = NULL;

	if (node->locked)
		return;

	if (node->depth >= l->depth && node->num_of_siblings >= l->max_siblings) {
		file_dbg("trimming node %s\n", get_pointer(node->node_str_offset));

		if (node->priv_offset) {
			file_item = get_pointer(node->priv_offset);
		} else {
			/* if this node have no prov, create one */
			file_item = heap_calloc(sizeof(file_hash_item_t));
			if (!file_item) {
				file_err("failed to allocate file_item\n");
				return;
			}

			node->priv_offset = get_offset(file_item);
		}

		/* delete the sub tree */
		while (node->child_offset) {
			/* go down the tree and gather all set bits to this node rules */
			str_tree_walk(get_pointer(node->child_offset), gather_node_rules, &file_item->rules);

			str_tree_walk(get_pointer(node->child_offset), file_cls_delete_node, NULL);
		}
	}
}

void file_cls_trim(int depth, int max_siblings)
{
	int i;
	file_trim_limits_t l = {
		.depth = depth,
		.max_siblings = max_siblings,
	};

	str_tree_walk(root, trim_node, &l);

	/* go over the rest of the tree */
	for (i=0; i<MAX_RULES; i++) {
		rule_count_t rule_counter = {
			.count = 0,
			.rule = i,
		};

		if (rules_modes[i]) {
			str_tree_walk(root, file_cls_count_rule_refs, &rule_counter);
			if (!rule_counter.count) {
				/* no other file uses this rule, delete its mode */
				file_dbg("clearing mode for rule %u\n", i);
				rules_modes[i] = 0;
			}
		}
	}
}

void file_cls_trim_by_name(char *filename, int len)
{
	tree_node_t *node = NULL;
	int res = 0;
	file_trim_limits_t l = {
		.depth = 0,
		.max_siblings = 0,
	};

	/* search if file exist */
	node = str_tree_search(root, filename, len, &res);
	if (!node || res) {
		file_err("could not find file %s in file str tree\n", filename);
		return;
	}

	trim_node(node, &l);
}

static void update_node_inode(tree_node_t *node, void *param)
{
	get_file_inode_cb cb = (get_file_inode_cb)param;
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
			file_hash_item_t *file_item = get_pointer(node->priv_offset);

			file_item->file_ino = cb(buffer);
//			file_dbg("setting file %s inode %lu\n", buffer, file_item->file_ino);
			if (file_item->file_ino)
				hash_insert_data(&file_inode_hash, file_item);
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
				file_hash_item_t *file_item = get_pointer(node->priv_offset);

				file_item->file_ino = cb(buffer);
//				file_dbg("setting file %s inode %lu\n", buffer, file_item->file_ino);
				if (file_item->file_ino)
					hash_insert_data(&file_inode_hash, file_item);
			}

			current_buf_len -= node->name_len;
		} else {
			if (node->name_len)
				current_buf_len -= (node->name_len + 1);
		}
	}
}

static int file_hash_clear_inode(void *data)
{
	file_hash_item_t *file_item = (file_hash_item_t*)data;

	/* just mark the inode zero */
	file_item->file_ino = 0;

	return VSENTRY_SUCCESS;
}

void file_cls_update_tree_inodes(get_file_inode_cb cb)
{
	void *tmp = NULL;

	vs_memset(buffer, 0, 4096);
	buffer[0] = '/';
	current_buf_len = 1;

	/* when updating inodes we would like to delete the hash private content but
	 * dont want to delete the hash items as it contain the rules bit array.
	 * so well temporarily replace the hash delete callback (which delete the hash data)
	 * with stub and restore it when done
	 */
	tmp = file_inode_hash.hash_ops->del_data;
	file_inode_hash.hash_ops->del_data = file_hash_clear_inode;

	hash_empty_data(&file_inode_hash);
	str_tree_walk(root, update_node_inode, cb);

	file_inode_hash.hash_ops->del_data = tmp;
}

static void clear_node_inode(tree_node_t *node, void *param)
{
	if (node->locked) {
		/* node need to be cleared. */
		if (node->priv_offset) {
			file_hash_item_t *file_item = get_pointer(node->priv_offset);

			/* remove the inode from hash */
			if (file_item->file_ino) {
				file_dbg("removing and clearing inode %lu from hash\n", file_item->file_ino);
				hash_remove_data(&file_inode_hash, file_item);
				file_item->file_ino = 0;
			}
		}
	}
}

void file_cls_remove_inode(unsigned long *inode)
{
	file_hash_item_t *file_item = NULL;

	if (!inode || !*inode)
		return;

	/* check if this inode hashed i.e. have rule */
	file_item = hash_get_data(&file_inode_hash, inode);
	if (file_item) {
		tree_node_t *node = NULL;

		/* signal update is on the way */
		during_hash_update = true;

		file_dbg("removing inode %lu from hash\n", *inode);

		/* wait until all ongoing checks will complete */
		while (file_cls_usage)
			;


		/* get the tree node */
		node = get_pointer(file_item->tree_node_offset);

		/* go over the sub-tree and remove from hash all sub-tree inodes */
		str_tree_walk(node, clear_node_inode, NULL);

		/* remove and clear the file itself */
		hash_remove_data(&file_inode_hash, file_item);
		file_item->file_ino = 0;

		/* clear all cache */
		file_dbg("clearing cache\n", *inode);
		cache_clear();

		/* signal update done */
		during_hash_update = false;
	} else {
		/* this inode use ancestor rule. we only need to remove it
		 * from cache */
		file_dbg("removing inode %lu from cache\n", *inode);
		cache_delete(*inode);
	}
}

typedef struct {
	int start;
	int end;
} file_rules_limit_t;

static void check_file_rule(tree_node_t *node, void *param)
{
	file_rules_limit_t* limit = param;
	int i;

	if (!node->locked && node->priv_offset) {
		file_hash_item_t *file_item= get_pointer(node->priv_offset);

		for (i=limit->start; i<limit->end; i++) {
			if (ba_is_set(i, &file_item->rules))
				file_cls_del_rule_from_node(i, node);

		}
	}
}

void file_cls_clear_rules(int start, int end)
{
	int i;
	file_rules_limit_t limit = {
		.start = start,
		.end = end,
	};

	vs_memset(buffer, 0, 4096);
	buffer[0] = '/';
	current_buf_len = 1;

	str_tree_walk(root, check_file_rule, &limit);

	if (!ba_is_empty(procfs_rules)) {
		for (i=start; i<end; i++)
			ba_clear_bit(i, procfs_rules);
	}

	if (!ba_is_empty(sysfs_rules)) {
		for (i=start; i<end; i++)
			ba_clear_bit(i, sysfs_rules);
	}

	/* go over the rest of the tree */
	for (i=0; i<MAX_RULES; i++) {
		rule_count_t rule_counter = {
			.count = 0,
			.rule = i,
		};

		if (rules_modes[i]) {
			str_tree_walk(root, file_cls_count_rule_refs, &rule_counter);
			if (!rule_counter.count) {
				/* no other file uses this rule, delete its mode */
				file_dbg("clearing mode for rule %u\n", i);
				rules_modes[i] = 0;
			}
		}
	}
}

#ifdef CLS_DEBUG

/* callback function that prints the file tree elements */

static void file_cls_print_node(tree_node_t *node, void *param)
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

		/* print only file with rules */
		if (node->priv_offset) {
			file_hash_item_t *file_item= get_pointer(node->priv_offset);
			cls_printf("    %s (inode %lu) : ", buffer, file_item->file_ino);
			ba_print_set_bits(&file_item->rules);
		}

		if (node->name_len && node->child_offset) {
			buffer[current_buf_len] = '/';
			current_buf_len++;
		}
	} else {
		if (!node->child_offset && node->priv_offset) {
			file_hash_item_t *file_item= get_pointer(node->priv_offset);
			/* this is a leaf in the tree. print. */
			filename = get_pointer(node->node_str_offset);

			vs_memcpy(&buffer[current_buf_len], filename, node->name_len);
			current_buf_len += node->name_len;
			buffer[current_buf_len] = 0;

			cls_printf("    %s (inode %lu) : ", buffer, file_item->file_ino);
			ba_print_set_bits(&file_item->rules);

			current_buf_len -= node->name_len;
		} else {
			if (node->name_len)
				current_buf_len -= (node->name_len + 1);
		}
	}
}

void file_cls_print_tree(void)
{
	int i;

	vs_memset(buffer, 0, 4096);
	buffer[0] = '/';
	current_buf_len = 1;

	cls_printf("file db:\n");

	if (!ba_is_empty(procfs_rules)) {
		cls_printf("  procfs: ");
		ba_print_set_bits(procfs_rules);
	}

	if (!ba_is_empty(sysfs_rules)) {
		cls_printf("  sysfs: ");
		ba_print_set_bits(sysfs_rules);
	}

	str_tree_walk(root, file_cls_print_node, NULL);
	cls_printf("\n");

	cls_printf("  file rules modes :\n");
	for (i=0; i<MAX_RULES; i++) {
		if (rules_modes[i]) {
			cls_printf("    rule[%d]: mode %s%s%s\n", i,
					(rules_modes[i] & FILE_MODE_READ)?"r":"",
					(rules_modes[i] & FILE_MODE_WRITE)?"w":"",
					(rules_modes[i] & FILE_MODE_EXEC)?"x":"");
		}
	}
	cls_printf("\n");

	cls_printf("  hash %s\n", file_inode_hash.name);
	hash_print(&file_inode_hash);

	cls_printf("\n");
}

#endif /* CLS_DEBUG */
