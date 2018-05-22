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
	SR_SLEEPLES_LOCK_DEF(s_lock)
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
	if ((attrs & SR_GEN_HASH_SLEEPLES_LOCK)){
		for (i = 0; i < size; i++) 
			SR_SLEEPLES_LOCK_INIT(&((new_item->table)[i].s_lock)); 
	} else {
		if ((attrs & SR_GEN_HASH_WRITE_LOCK) || (attrs & SR_GEN_HASH_READ_LOCK)) {
			for (i = 0; i < size; i++) 
				SR_MUTEX_INIT(&((new_item->table)[i].lock)); 
		}
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

static SR_32 gen_hash_lock(hash_bucket_t *bucket, SR_U8 hash_attrs, SR_U8 hash_flags, SR_SLEEPLES_LOCK_FLAGS *flags, SR_BOOL is_update)
{
	if ((is_update && !(hash_attrs & SR_GEN_HASH_WRITE_LOCK)) ||
	    (!is_update && !(hash_attrs & SR_GEN_HASH_READ_LOCK))) {
		return SR_SUCCESS;
	}

	if (!(hash_attrs & SR_GEN_HASH_SLEEPLES_LOCK)) {
		SR_MUTEX_LOCK(&(bucket->lock));
		return SR_SUCCESS;
	}

	if (hash_flags & SR_GEN_HASH_TRY_LOCK) {
		if (!SR_SLEEPLES_TRYLOCK(&(bucket->s_lock), *flags)) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=try lock failed to accuire lock", REASON);
			return SR_ERROR;
		}
	} else
		SR_SLEEPLES_LOCK(&(bucket->s_lock), *flags);

	return SR_SUCCESS;
}

static SR_32 gen_hash_unlock(hash_bucket_t *bucket, SR_U8 hash_attrs, SR_U8 hash_flags, SR_SLEEPLES_LOCK_FLAGS flags, SR_BOOL is_update)
{
	if ((is_update && !(hash_attrs & SR_GEN_HASH_WRITE_LOCK)) ||
	    (!is_update && !(hash_attrs & SR_GEN_HASH_READ_LOCK))) {
		return SR_SUCCESS;
	}

	if (!(hash_attrs & SR_GEN_HASH_SLEEPLES_LOCK)) {
		SR_MUTEX_UNLOCK(&(bucket->lock));
		return SR_SUCCESS;
	}
	SR_SLEEPLES_UNLOCK(&(bucket->s_lock), flags);

	return SR_SUCCESS;
}

SR_32 sr_gen_hash_insert(struct sr_gen_hash *hash, void *key, void *data, SR_U8 hash_flags)
{
	SR_U32 ind;
	SR_32 rc = SR_SUCCESS;
	hash_item_t **iter, *new_item;
	SR_SLEEPLES_LOCK_FLAGS flags;

	/* Add new key */
	SR_Zalloc(new_item, hash_item_t *, sizeof(hash_item_t));
	if (!new_item)
		return SR_ERROR;

	GET_HASH_IND(hash, ind, key, SR_ERROR);

	if (gen_hash_lock(&(hash->table[ind]), hash->attrs, hash_flags, &flags, SR_TRUE) != SR_SUCCESS) {
		return SR_ERROR;
	}

	for (iter = &(hash->table[ind].items); *iter; iter = &((*iter)->next)) {
		if (hash->hash_ops.comp && hash->hash_ops.comp((*iter)->data, key) == 0)
			break;
	}
	if (*iter) {
		rc = SR_ERROR;
		goto out;
	}
	*iter = new_item;
	(*iter)->next = NULL;
	(*iter)->data = data;

out:
	if (gen_hash_unlock(&(hash->table[ind]), hash->attrs, hash_flags, flags, SR_TRUE) != SR_SUCCESS) {
		return SR_ERROR;
	}
	return rc;
}

SR_32 sr_gen_hash_delete(struct sr_gen_hash *hash, void *key, SR_U8 hash_flags)
{
	SR_U32 ind;
	SR_32 rc = SR_SUCCESS;
	hash_item_t **iter, *help;
	SR_SLEEPLES_LOCK_FLAGS flags;

	GET_HASH_IND(hash, ind, key, SR_ERROR);

	if (gen_hash_lock(&(hash->table[ind]), hash->attrs, hash_flags, &flags, SR_TRUE) != SR_SUCCESS) {
		return SR_ERROR;
	}

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
	if (gen_hash_unlock(&(hash->table[ind]), hash->attrs, hash_flags, flags, SR_TRUE) != SR_SUCCESS) {
		return SR_ERROR;
	}
	return rc;
}

SR_32 sr_gen_hash_delete_all(struct sr_gen_hash *hash, SR_U8 hash_flags)
{
	int i;
	hash_item_t *iter, *help;
	SR_SLEEPLES_LOCK_FLAGS flags;

	if (!hash)
		return SR_ERROR;

	for (i = 0; i < hash->size; i++) {
		if (gen_hash_lock(&(hash->table[i]), hash->attrs, hash_flags, &flags, SR_TRUE) != SR_SUCCESS) {
			return SR_ERROR;
		}
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
		if (gen_hash_unlock(&(hash->table[i]), hash->attrs, hash_flags, flags, SR_TRUE) != SR_SUCCESS) {
			return SR_ERROR;
		}
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

SR_32 sr_gen_hash_cond_delete_all(struct sr_gen_hash *hash, SR_BOOL (*cond_cb)(void *hash_data))
{
	int i;
	hash_item_t **iter, *help;
	SR_SLEEPLES_LOCK_FLAGS flags;

	if (!hash)
		return SR_ERROR;

	if (!cond_cb)
		return SR_ERROR; 

	for (i = 0; i < hash->size; i++) {
		if (gen_hash_lock(&(hash->table[i]), hash->attrs, 0, &flags, SR_TRUE) != SR_SUCCESS) {
			return SR_ERROR;
		}
		for (iter = &(hash->table[i].items); *iter; ) {
			if (!cond_cb((*iter)->data)) {
				/* Do NOT deletet */
				iter = &((*iter)->next);
				continue;
			}
			/* Delete */
			help = *iter;
			*iter = (*iter)->next;
			if (hash->attrs & SR_GEN_HASH_SLOW_DELETE)
				add_object_to_free_repos(hash, help);
			else 
				SR_Free(help);
		}
		if (gen_hash_unlock(&(hash->table[i]), hash->attrs, 0, flags, SR_TRUE) != SR_SUCCESS) {
			return SR_ERROR;
		}
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
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=GEN HASH table print count:%d",MESSAGE,
		count);
}

void *sr_gen_hash_get(struct sr_gen_hash *hash, void *key, SR_U8 hash_flags)
{
	SR_U32 ind;
	hash_item_t *iter;
	SR_SLEEPLES_LOCK_FLAGS flags;

	GET_HASH_IND(hash, ind, key, NULL);

	if (gen_hash_lock(&(hash->table[ind]), hash->attrs, hash_flags, &flags, SR_FALSE) != SR_SUCCESS) {
		return NULL;
	}
	for (iter = hash->table[ind].items; iter; iter = iter->next) {
		if (hash->hash_ops.comp && hash->hash_ops.comp(iter->data, key) == 0)
			break;
	}
	if (gen_hash_unlock(&(hash->table[ind]), hash->attrs, hash_flags, flags, SR_FALSE) != SR_SUCCESS) {
		return NULL;
	}

	return iter ? iter->data : NULL;
}

void sr_gen_hash_destroy(struct sr_gen_hash *hash)
{
	if (!hash)
		return;

	sr_gen_hash_delete_all(hash, 0);
	if (hash->attrs & SR_GEN_HASH_SLOW_DELETE)
		clean_free_repos(hash);
	SR_Free(hash->table);
	SR_Free(hash);
}

SR_32 sr_gen_hash_exec_for_each(struct sr_gen_hash *hash, SR_32 (*cb)(void *hash_data, void *data), void *data, SR_U8 hash_flags)
{
	hash_item_t *iter;
	SR_U32 i;
	SR_SLEEPLES_LOCK_FLAGS flags;

	for (i = 0 ; i < hash->size; i++) {
		if (gen_hash_lock(&(hash->table[i]), hash->attrs, hash_flags, &flags, SR_FALSE) != SR_SUCCESS) {
			return SR_ERROR;
		}
		for (iter = hash->table[i].items; iter; iter = iter->next)
			cb(iter->data, data);
		if (gen_hash_unlock(&(hash->table[i]), hash->attrs, hash_flags, flags, SR_FALSE) != SR_SUCCESS) {
			return SR_ERROR;
		}
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

