#include <sr_sal_common.h>
#include <sr_gen_hash.h>
#include <sal_mem.h>
#include <sal_linux.h>
#include <sr_cyclic_array.h>

typedef struct hash_item {
	struct hash_item *next;
	void *data; 
} hash_item_t;

typedef struct hash_bucket {
	SR_MUTEX lock;
	hash_item_t *items;
} hash_bucket_t;

struct sr_gen_hash { 
	SR_U32 size;
	SR_U8 attrs;
	hash_ops_t hash_ops;
	hash_bucket_t *table;
	hash_item_t **slow_delete_items;
	sr_cyclic_array_t carr;
};

#define GET_HASH_IND(hash, ind, key, err_retval) if (!hash || !hash->hash_ops.create_key) \
		return err_retval;\
		ind = hash->hash_ops.create_key(key) % hash->size;

struct sr_gen_hash *sr_gen_hash_new(int size, hash_ops_t hash_ops, SR_U8 attrs)
{
	struct sr_gen_hash *new_item;
	SR_U32 i;

	SR_Zalloc(new_item, struct sr_gen_hash *, sizeof(struct sr_gen_hash));
	if (!(new_item))
		return NULL;
	new_item->hash_ops.create_key = hash_ops.create_key;
	new_item->hash_ops.comp = hash_ops.comp;
	new_item->hash_ops.free = hash_ops.free;
	new_item->hash_ops.print = hash_ops.print;
	new_item->size = size;
	new_item->attrs = attrs;
	SR_Zalloc((new_item->table), hash_bucket_t *, (size * sizeof(hash_bucket_t)));
	if (!(new_item->table)) {
		SR_Free(new_item);
		return NULL;
	}

	/* Locking is required */
	if ((attrs & SR_GEN_HASH_WRITE_LOCK) || (attrs & SR_GEN_HASH_READ_LOCK)) {
		for (i = 0; i < size; i++) 
			SR_MUTEX_INIT(&((new_item->table)[i].lock)); 
	}

	/* Slow delete is required */
	if (attrs & SR_GEN_HASH_SLOW_DELETE) {
		SR_Zalloc(new_item->slow_delete_items, hash_item_t **, ((size / 10) * sizeof(struct hash_item_t *)));
		if (!(new_item->slow_delete_items)) {
			SR_Free(new_item->table);
			SR_Free(new_item);
			return NULL;
		}
	 	sr_cyclic_array_init(&(new_item->carr), (void **)new_item->slow_delete_items, size / 10);
	}
	
	return new_item;
}

SR_32 sr_gen_hash_insert(struct sr_gen_hash *hash, void *key, void *data)
{
	SR_U32 ind;
	SR_32 rc = SR_SUCCESS;
	hash_item_t **iter, *new_item;

	/* Add new key */
	SR_Zalloc(new_item, hash_item_t *, sizeof(hash_item_t));
	if (!new_item)
		return SR_ERROR;

	GET_HASH_IND(hash, ind, key, SR_ERROR);

	if (hash->attrs & SR_GEN_HASH_WRITE_LOCK)
		SR_MUTEX_LOCK(&(hash->table[ind].lock));
		
	for (iter = &(hash->table[ind].items); *iter; iter = &((*iter)->next)) {
		if (hash->hash_ops.comp && hash->hash_ops.comp((*iter)->data, key) == 0)
			break;
	}
	if (*iter) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=hash_insert error, key exists",REASON);
		rc = SR_ERROR;
		goto out;
	}
	*iter = new_item;
	(*iter)->next = NULL;
	(*iter)->data = data;

out:
	if (hash->attrs & SR_GEN_HASH_WRITE_LOCK)
		SR_MUTEX_UNLOCK(&(hash->table[ind].lock));
	return rc;
}

SR_32 sr_gen_hash_delete(struct sr_gen_hash *hash, void *key)
{
	SR_U32 ind;
	SR_32 rc = SR_SUCCESS;
	hash_item_t **iter, *help;

	GET_HASH_IND(hash, ind, key, SR_ERROR);

	if (hash->attrs & SR_GEN_HASH_WRITE_LOCK)
		SR_MUTEX_LOCK(&(hash->table[ind].lock));

	for (iter = &(hash->table[ind].items); *iter; iter = &((*iter)->next)) {
		if (hash->hash_ops.comp && hash->hash_ops.comp((*iter)->data, key) == 0)
			break;
	}

	if (!*iter) {
		rc = SR_NOT_FOUND;
		goto out;
	}
	if (hash->hash_ops.free)
		hash->hash_ops.free((*iter)->data);
	help = *iter;
	*iter = (*iter)->next;
	SR_Free(help);

out:
	if (hash->attrs & SR_GEN_HASH_WRITE_LOCK)
		SR_MUTEX_UNLOCK(&(hash->table[ind].lock));
	return rc;
}

SR_32 sr_gen_hash_delete_all(struct sr_gen_hash *hash)
{
	int i;
	hash_item_t *iter, *help;

	if (!hash)
		return SR_ERROR;

	for (i = 0; i < hash->size; i++) {
		for (iter = hash->table[i].items; iter; ) {
			if (hash->hash_ops.free)
				hash->hash_ops.free(iter->data);
			else if (iter->data)
				SR_Free(iter->data);
			help = iter->next;
			SR_Free(iter);
			iter = help;
		}
		hash->table[i].items = NULL;
	}

	return SR_SUCCESS;
}

static void add_object_to_free_repos(struct sr_gen_hash *hash, void *object)
{
        hash_item_t *object_to_free;

        if (!sr_cyclic_array_is_full(&(hash->carr))) {
                sr_cyclic_array_write(&(hash->carr), object);
                return;
        }
        // Clear one object to create space and free it.
        sr_cyclic_array_read(&(hash->carr), (void *)&object_to_free);
        sr_cyclic_array_write(&(hash->carr), object);
        if (hash->hash_ops.free)
                hash->hash_ops.free(object_to_free->data);
        else if (object_to_free->data)
                SR_Free(object_to_free->data);
        SR_Free(object_to_free);
}

static void clean_free_repos(struct sr_gen_hash *hash)
{
        hash_item_t *object_to_free;

        while (sr_cyclic_array_read(&(hash->carr), (void *)&object_to_free) == SR_SUCCESS) {
        	if (hash->hash_ops.free)
                	hash->hash_ops.free(object_to_free->data);
        	else
                	SR_Free(object_to_free->data);
        	SR_Free(object_to_free);
	}
}

SR_32 sr_gen_hash_slow_delete_all(struct sr_gen_hash *hash, SR_BOOL (*cond_cb)(void *hash_data))
{
	int i;
	hash_item_t **iter, *help;

	if (!hash)
		return SR_ERROR;

	if ((hash->attrs & SR_GEN_HASH_SLOW_DELETE) == 0) 
		return SR_ERROR; 

	if (!cond_cb)
		return SR_ERROR; 

	for (i = 0; i < hash->size; i++) {
		if (hash->attrs & SR_GEN_HASH_WRITE_LOCK)
			SR_MUTEX_LOCK(&(hash->table[i].lock));
		for (iter = &(hash->table[i].items); *iter; ) {
			if (!cond_cb((*iter)->data)) {
				/* Do NOT deletet */
				iter = &((*iter)->next);
				continue;
			}
			/* Delete */
			help = *iter;
			*iter = (*iter)->next;
			add_object_to_free_repos(hash, help);
		}
		if (hash->attrs & SR_GEN_HASH_WRITE_LOCK)
			SR_MUTEX_UNLOCK(&(hash->table[i].lock));
	}

	return SR_SUCCESS;
}

void sr_gen_hash_print(struct sr_gen_hash *hash)
{
	SR_U32 i, count = 0;
	hash_item_t *iter;

	if (!hash)
		return;

	for (i = 0; i < hash->size; i++) {
		for (iter = hash->table[i].items; iter; iter = iter->next) {
			if (hash->hash_ops.print)
				hash->hash_ops.print(iter->data);
			count++;
		}
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"%s=GEN HASH table print count:%d",MESSAGE,
		count);
}

void *sr_gen_hash_get(struct sr_gen_hash *hash, void *key)
{
	SR_U32 ind;
	hash_item_t *iter;

	GET_HASH_IND(hash, ind, key, NULL);

	for (iter = hash->table[ind].items; iter; iter = iter->next) {
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
	if (hash->attrs & SR_GEN_HASH_SLOW_DELETE)
		clean_free_repos(hash);
	SR_Free(hash->table);
	SR_Free(hash);
}

SR_32 sr_gen_hash_exec_for_each(struct sr_gen_hash *hash, SR_32 (*cb)(void *hash_data, void *data), void *data)
{
	hash_item_t *iter;
	SR_U32 i;

	for (i = 0 ; i < hash->size; i++) {
		for (iter = hash->table[i].items; iter; iter = iter->next)
			cb(iter->data, data);
	}

	return SR_SUCCESS;
}

SR_32 sr_gen_hash_delete_all_cb(struct sr_gen_hash *hash, SR_BOOL (*cb)(void *hash_data))
{
	hash_item_t **iter, *help;
	SR_U32 i;

	for (i = 0 ; i < hash->size; i++) {
		for (iter = &(hash->table[i].items); *iter; ) {
			if (cb && cb((*iter)->data)) {
				help = *iter;
				*iter = (*iter)->next;
				SR_Free(help);
			} else 
				iter = &((*iter)->next);
		}
	}

	return SR_SUCCESS;
}

