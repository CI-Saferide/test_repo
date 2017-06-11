#include "sal_linux.h"
#include "sr_hash.h"

static inline int IsPowerOfTwo(SR_U32 num)
{
	SR_U32 power;

	if (num<=1) {
		return 0;
	}
	for (power = 2; power <= num; power=(power <<1)) {
		if (power == num)
			return TRUE;
	}
	return FALSE;
}
struct sr_hash_table_t *sr_hash_new_table(int count)
{	
	struct sr_hash_table_t *table;
	if (!IsPowerOfTwo(count)) {
		sal_kernel_print_alert("Error: Please initialize hash table to a power of two size\n");
		return NULL;
	}
	table = SR_ALLOC(sizeof(sizeof(table)));
	if (!table)
		return NULL;
	table->size = count;
	table->buckets = SR_ZALLOC(count * sizeof(struct sr_hash_bucket_t));
	if (!table->buckets) {
		SR_FREE(table);
		return NULL;
	}
	return table;
}
static inline SR_U32 sr_hash_get_index(SR_U32 key, SR_U32 size)
{
	return key % size; // TODO: create a better distribution by replacing function
}

int sr_hash_insert(struct sr_hash_table_t *table, struct sr_hash_ent_t *ent)
{ 
	SR_U32 index;
	
	index = sr_hash_get_index(ent->key, table->size);
	table->count++;
	
	if (!table->buckets[index].head) { // First entry
		table->buckets[index].head = ent;
		ent->next = NULL;
		return SR_SUCCESS;
	}
	SR_LOCK(&table->buckets[index].bucket_lock);
	ent->next = table->buckets[index].head;
	table->buckets[index].head = ent;
	SR_UNLOCK(&table->buckets[index].bucket_lock);
	return SR_SUCCESS;
}
void sr_hash_delete(struct sr_hash_table_t *table, SR_U32 key)
{
	SR_U32 index;
	
	index = sr_hash_get_index(key, table->size);
	table->count--;
	
	if (!table->buckets[index].head) {
		return ;
	}
	SR_LOCK(&table->buckets[index].bucket_lock);
	if (table->buckets[index].head->key == key) {// remove head
		table->buckets[index].head = table->buckets[index].head->next;
	} else {
		struct sr_hash_ent_t *ptr = table->buckets[index].head;
		while (ptr && ptr->next) {
			if (ptr->next->key == key) {
				struct sr_hash_ent_t *ptr2 = ptr->next;
				ptr->next = ptr->next->next;
				SR_FREE(ptr2);
				break;
			}
			ptr = ptr->next;
		}
	}
	SR_UNLOCK(&table->buckets[index].bucket_lock);
}
struct sr_hash_ent_t *sr_hash_lookup(struct sr_hash_table_t *table, SR_U32 key)
{
	SR_U32 index;
	struct sr_hash_ent_t *ptr;
	
	index = sr_hash_get_index(key, table->size);
	table->count--;
	
	if (!table->buckets[index].head) {
		return NULL;
	}
	SR_LOCK(&table->buckets[index].bucket_lock);

	ptr = table->buckets[index].head;
	while (ptr) {
		if (ptr->key == key) {
			break;
		}
		ptr = ptr->next;
	}
	SR_UNLOCK(&table->buckets[index].bucket_lock);
	return (ptr);
}
