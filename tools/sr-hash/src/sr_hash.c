#include "sr_hash.h"

static inline int IsPowerOfTwo(SR_U32 num)
{
	SR_U32 power;

	if (num<=1) {
		return 0;
	}
	for (power = 2; power <= num; power=(power <<1)) {
		if (power == num)
			return SR_TRUE;
	}
	return SR_FALSE;
}
struct sr_hash_table_t *sr_hash_new_table(int count)
{	
	struct sr_hash_table_t *table;
	if (!IsPowerOfTwo(count)) {
		sal_kernel_print_alert("Error: Please initialize hash table to a power of two size\n");
		return NULL;
	}
	table = SR_ZALLOC(sizeof(*table));
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
	struct sr_hash_ent_t *ptr;
	
	index = sr_hash_get_index(key, table->size);
	
	if (!table->buckets[index].head) {
		return ;
	}

	SR_LOCK(&table->buckets[index].bucket_lock);
	if (table->buckets[index].head->key == key) {// remove head
		ptr = table->buckets[index].head;
		table->buckets[index].head = table->buckets[index].head->next;
		SR_FREE(ptr);
		table->count--;
	} else {
		ptr = table->buckets[index].head;
		while (ptr && ptr->next) {
			if (ptr->next->key == key) {
				struct sr_hash_ent_t *ptr2 = ptr->next;
				ptr->next = ptr->next->next;
				SR_FREE(ptr2);
				table->count--;
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

void sr_hash_free_table(struct sr_hash_table_t *table)
{
	SR_U32 i;
	struct sr_hash_ent_t *ptr,*ptr1;
	
	for (i=0; (i < table->size) && table->count; i++) {
		if (table->buckets[i].head) {
			sal_kernel_print_alert("sr_hash_free_table: Table still has member in location %u\n", i);
			SR_LOCK(&table->buckets[index].bucket_lock);
			ptr = table->buckets[i].head->next;
			while (ptr) {
				ptr1 = ptr->next;
				SR_FREE(ptr);
				table->count--;
				ptr = ptr1;
			}
			SR_FREE(table->buckets[i].head);
			table->buckets[i].head = NULL;
			table->count--;
			SR_UNLOCK(&table->buckets[index].bucket_lock);
		}
	}
	sal_kernel_print_alert("Cleaned entire table, count is %u\n", table->count);
	SR_FREE(table->buckets);
	SR_FREE(table);
}
void sr_hash_print_table(struct sr_hash_table_t *table)
{
	SR_U32 i;
	struct sr_hash_ent_t *ptr;
	
	sal_kernel_print_alert("sr_hash_print_table: Entry, size is %u\n", table->size);

	for (i=0; i < table->size ; i++) {
		if (table->buckets[i].head) {
			sal_kernel_print_alert("Table has member in location %u\n", i);
			SR_LOCK(&table->buckets[index].bucket_lock);
			ptr = table->buckets[i].head->next;
			while (ptr) {
				sal_kernel_print_alert("Element address is %lu\n", (unsigned long)ptr);
				ptr = ptr->next;
			}
			SR_UNLOCK(&table->buckets[index].bucket_lock);
		}
	}
	sal_kernel_print_alert("sr_hash_print_table: Exit\n");
}
