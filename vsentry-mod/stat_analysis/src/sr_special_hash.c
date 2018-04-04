#include "sr_special_hash.h"
#include "sr_cyclic_array.h"

static inline int is_power_of_two(SR_U32 num)
{
	return !(num & (num - 1));
}

sr_special_hash_table_t *sr_special_hash_new_table(int count, sr_special_hash_ops_t *ops)
{
	SR_U32 i;
        sr_special_hash_table_t *table;

        if (!is_power_of_two(count)) {
                sal_kernel_print_alert("Error: Please initialize hash table to a power of two size\n");
                return NULL;
        }
        table = SR_ZALLOC(sizeof(*table));
        if (!table)
                return NULL;
        table->size = count;
	table->ops.create_key = ops->create_key;
	table->ops.comp = ops->comp;
	table->ops.print = ops->print;
	table->ops.free = ops->free;
        table->buckets = SR_ZALLOC(count * sizeof(sr_special_hash_bucket_t));
        if (!table->buckets) {
                SR_FREE(table);
                return NULL;
        }
	for (i = 0; i < count; i++) { 
        	SR_MUTEX_INIT(&table->buckets[i].bucket_lock);
	}
	sr_cyclic_array_init(&(table->gc_buffer), (void **)table->hash_ents_to_free, SR_SPECIAL_HASH_ENT_REPOS_SIZE);

        return table;
}

// TODO: create a better distribution by replacing function
static inline SR_U32 sr_special_hash_get_index(sr_special_hash_table_t *table, void *key, SR_U32 size)
{
	if (table->ops.create_key(key))
		return table->ops.create_key(key) % size;
	
	return (long int)key % size; 
}

SR_32 sr_special_hash_insert(sr_special_hash_table_t *table, void *key, void *data, SR_BOOL is_blocking, SR_BOOL is_atomic)
{ 
	SR_U32 index;
	sr_special_hash_ent_t *ent;
	
	ent = SR_KZALLOC_ATOMIC_SUPPORT(is_atomic, sr_special_hash_ent_t);
        if (!ent) {
            CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=Failed to allocate memory",REASON);
            return SR_ERROR;
	}

	index = sr_special_hash_get_index(table, key, table->size);
	ent->data = data;
	if (is_blocking) 
		SR_MUTEX_LOCK(&table->buckets[index].bucket_lock);
	else {
		if (SR_MUTEX_TRYLOCK(&table->buckets[index].bucket_lock) == 0) {
			/* Try lock failed we lose the stats and continue */
			SR_KFREE(ent);
			return SR_SUCCESS;	
		}
	}
	ent->next = table->buckets[index].head;
	table->buckets[index].head = ent;
	SR_MUTEX_UNLOCK(&table->buckets[index].bucket_lock);

	return SR_SUCCESS;
}

void sr_special_hash_soft_delete(sr_special_hash_table_t *table, void *key)
{
	sr_special_hash_ent_t *ptr;
	SR_U32 index = sr_special_hash_get_index(table, key, table->size);

	if (!table->ops.comp)
		return;
	
	for (ptr = table->buckets[index].head; ptr; ptr = ptr->next) {
		if (table->ops.comp(ptr->data, key) == 0) {
			ptr->should_delete = SR_TRUE;
			table->buckets[index].should_delete = SR_TRUE;
			break;
		}
	}
}

void *sr_special_hash_lookup(sr_special_hash_table_t *table, void *key)
{
	sr_special_hash_ent_t *ptr;
	SR_U32 index = sr_special_hash_get_index(table, key, table->size);

	if (!table->ops.comp)
		return NULL;
	
	for (ptr = table->buckets[index].head; ptr && table->ops.comp(ptr->data, key) != 0; ptr = ptr->next);

	return ptr ? ptr->data : NULL;
}

static void sr_special_hash_empty_table(sr_special_hash_table_t *table, SR_BOOL is_lock)
{
        sr_special_hash_ent_t *curr, *next;
        SR_32 i;

        if (!table)
                return;

        for (i = 0; i < table->size; i++) {
                if (table->buckets[i].head != NULL){
			if (is_lock)
                        	SR_LOCK(&table->buckets[i].bucket_lock);
                        curr = table->buckets[i].head;
                        while (curr != NULL){
                                next = curr->next;
				if (table->ops.free)
					table->ops.free(curr->data);
				else
                                	SR_KFREE(curr->data);
                                SR_KFREE(curr);
                                curr= next;
                        }
                        table->buckets[i].head = NULL;
			if (is_lock)
                        	SR_UNLOCK(&table->buckets[i].bucket_lock);
                }
        }
}

void sr_special_hash_free_table(sr_special_hash_table_t *table)
{
	sr_special_hash_empty_table(table, SR_FALSE);

	sal_kernel_print_info("Cleaned entire connection table\n");
	SR_FREE(table->buckets);
	SR_FREE(table);
}

SR_32 sr_special_hash_print_table(sr_special_hash_table_t *table)
{
	SR_U32 i, count = 0;
	sr_special_hash_ent_t *ptr;
	
	sal_kernel_print_info("sr_special_hash_print_table: Entry, size is %u\n", table->size);

	for (i = 0; i < table->size ; i++) {
		if (table->buckets[i].head && table->buckets[i].should_delete)
			sal_kernel_print_info("bucket shoulde DELETE:\n");
		for (ptr = table->buckets[i].head; ptr; ptr = ptr->next) {
			if (ptr->should_delete)
				sal_kernel_print_info("DELETED: ");
			if (table->ops.print)
				table->ops.print(ptr->data);
			count++;
		}
	}
	sal_kernel_print_info("sr_special_hash_print_table count:%d Exit\n", count);

	return count;
}

static void add_object_to_free_repos(sr_special_hash_table_t *table, sr_special_hash_ent_t *object)
{
	sr_special_hash_ent_t *object_to_free;

	if (!sr_cyclic_array_is_full(&(table->gc_buffer))) {
		sr_cyclic_array_write(&(table->gc_buffer), object);
		return;
	}
	// Clear one object to create space and free it.
	sr_cyclic_array_read(&(table->gc_buffer), (void *)&object_to_free);
	sr_cyclic_array_write(&(table->gc_buffer), object);
	if (table->ops.free)
		table->ops.free(object_to_free->data);
	else
		SR_KFREE(object_to_free->data);
	SR_KFREE(object_to_free);
}

SR_32 sr_special_hash_garbage_collection(sr_special_hash_table_t *table)
{
	SR_U32 i;
	sr_special_hash_ent_t **ptr, *tmp;
	
	for (i = 0; i < table->size ; i++) {
		if (!table->buckets[i].head || !table->buckets[i].should_delete)
			continue;
		SR_MUTEX_LOCK(&table->buckets[i].bucket_lock);
		for (ptr = &(table->buckets[i].head); *ptr; ) {
			if (!(*ptr)->should_delete) {
				ptr = &((*ptr)->next);
				continue;
			}
			tmp = *ptr;
			*ptr = (*ptr)->next;
			add_object_to_free_repos(table, tmp);
		}
		table->buckets[i].should_delete = SR_FALSE;
		SR_MUTEX_UNLOCK(&table->buckets[i].bucket_lock);
	}

	return SR_SUCCESS;
}

SR_32 sr_special_hash_soft_cleanup(sr_special_hash_table_t *table, SR_BOOL (*cb)(void *data))
{
	SR_U32 i;
	sr_special_hash_ent_t *iter;
	SR_U32 count = 0;

        for (i = 0; i < table->size; i++) {
                for (iter = table->buckets[i].head; iter; iter = iter->next) {
			/* Runs a cb to determine if to soft delete */
			count++;
			if (cb(iter->data) == SR_TRUE) {
				iter->should_delete = SR_TRUE;
				table->buckets[i].should_delete = SR_TRUE;
			}
		}
	}

	return SR_SUCCESS;
}
