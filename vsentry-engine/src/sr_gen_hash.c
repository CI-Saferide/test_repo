#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sr_sal_common.h>
#include <sr_gen_hash.h>
#include <sr_mem.h>

typedef struct hash_item {
	struct hash_item *next;
	void *data; 
} hash_item_t;

struct sr_gen_hash { 
	int size;
	hash_ops_t hash_ops;
	hash_item_t **table;
};

#define GET_HASH_IND(hash, ind, key, err_retval) if (!hash || !hash->hash_ops.create_key) \
		return err_retval;\
		ind = hash->hash_ops.create_key(key) % hash->size;

struct sr_gen_hash *sr_gen_hash_new(int size, hash_ops_t hash_ops)
{
	struct sr_gen_hash *new_item;

	SR_Zalloc(new_item, struct sr_gen_hash *, sizeof(struct sr_gen_hash));
	if (!(new_item))
		return NULL;
	new_item->hash_ops.create_key = hash_ops.create_key;
	new_item->hash_ops.comp = hash_ops.comp;
	new_item->hash_ops.free = hash_ops.free;
	new_item->hash_ops.print = hash_ops.print;
	new_item->size = size;
	SR_Zalloc((new_item->table), hash_item_t **, (size * sizeof(hash_item_t *)));
	if (!(new_item->table))
		return NULL;
	
	return new_item;
}

SR_32 sr_gen_hash_insert(struct sr_gen_hash *hash, void *key, void *data)
{
	int ind;
	hash_item_t **iter;

	GET_HASH_IND(hash, ind, key, SR_ERROR);

	for (iter = &(hash->table[ind]); *iter; iter = &((*iter)->next)) {
		if (hash->hash_ops.comp && hash->hash_ops.comp((*iter)->data, key) == 0)
			break;
	}
	if (*iter) {
		sal_printf("hash_inserti Error, key exists \n");
		return SR_ERROR;
	}
	/* Add new key */
	SR_Zalloc((*iter), hash_item_t *, sizeof(hash_item_t));
	if (!*iter)
		return SR_ERROR;
	(*iter)->next = NULL;
	(*iter)->data = data;

	return SR_SUCCESS;
}

SR_32 sr_gen_hash_delete(struct sr_gen_hash *hash, void *key)
{
	int ind;
	hash_item_t **iter, *help;

	GET_HASH_IND(hash, ind, key, SR_ERROR);

	for (iter = &(hash->table[ind]); *iter; iter = &((*iter)->next)) {
		if (hash->hash_ops.comp && hash->hash_ops.comp((*iter)->data, key) == 0)
			break;
	}

	if (!*iter) {
		sal_printf("has_delete error, key does not exist\n");
		return SR_ERROR;
	}
	if (hash->hash_ops.free)
		hash->hash_ops.free((*iter)->data);
	help = *iter;
	*iter = (*iter)->next;
	SR_Free(help);

	return SR_SUCCESS;
}

SR_32 sr_gen_hash_delete_all(struct sr_gen_hash *hash)
{
	int i;
	hash_item_t *iter, *help;

	if (!hash)
		return SR_ERROR;

	for (i = 0; i < hash->size; i++) {
		if (!hash->table[i])
			continue;
		for (iter = hash->table[i]; iter; ) {
			if (hash->hash_ops.free)
				hash->hash_ops.free(iter->data);
			help = iter->next;
			SR_Free(iter);
			iter = help;
		}
		hash->table[i] = NULL;
	}

	return SR_SUCCESS;
}

void sr_gen_hash_print(struct sr_gen_hash *hash)
{
	int i;
	hash_item_t *iter;

	if (!hash)
		return;

	for (i = 0; i < hash->size; i++) {
		for (iter = hash->table[i]; iter; iter = iter->next) {
			if (hash->hash_ops.print)
				hash->hash_ops.print(iter->data);
		}
	}
}

void *sr_gen_hash_get(struct sr_gen_hash *hash, void *key)
{
	int ind;
	hash_item_t *iter;

	GET_HASH_IND(hash, ind, key, NULL);

	for (iter = hash->table[ind]; iter; iter = iter->next) {
		if (hash->hash_ops.comp && hash->hash_ops.comp(iter->data, key) == 0)
			break;
	}

	return iter ? iter->data : NULL;
}

void sr_gen_hash_destroy(struct sr_gen_hash *hash)
{
	if (!hash)
		return;

	sr_gen_hash_delete_all(hash);
	SR_Free(hash->table);
	SR_Free(hash);
}

