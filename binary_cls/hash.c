#include <stddef.h>
#include <linux/vsentry/vsentry.h>
#include "hash.h"
#include "heap.h"
#include "classifier.h"

#ifdef HASH_DEBUG
#define hash_dbg cls_dbg
#define hash_err cls_err
#else
#define hash_dbg(...)
#define hash_err(...)
#endif

static unsigned int hash_default_create_key(void *data, unsigned int bits)
{
	unsigned int key;

	if (!data) {
		hash_err("no data was provided\n");
		return (unsigned int)(-1);
	}

	if (bits > MAX_NUM_OF_BITS) {
		hash_err("only upto 32 bit supported (%u)\n", bits);
		return (unsigned int)(-1);
	}

	key = hash32(*(unsigned int*)data, bits);

	hash_dbg("generated key %u for value %u \n", key, *(unsigned int*)data);

	return key;
}

static bool hash_default_compare(void *hash_data, void *data)
{
	if (!data || !hash_data) {
		hash_err("no data/hash_data was provided\n");
		return false;
	}

	if (*(unsigned int*)hash_data == *(unsigned int*)data) {
		hash_dbg("found match: data (0x%lx, %u) value %u\n",
			hash_data, *(unsigned int*)hash_data, *(unsigned int*)data);
		return true;
	}

	hash_dbg("no match: data (0x%lx, %u) value %u\n",
		hash_data, *(unsigned int*)hash_data, *(unsigned int*)data);

	return false;
}

static int hash_default_del_data(void *data)
{
	if (!data) {
		hash_err("no data was provided\n");
		return VSENTRY_ERROR;
	}

	hash_dbg("deleting data (0x%lx,%u)\n", data, *(unsigned int*)data);

	heap_free(data);

	return false;
}

static void hash_default_print_data(void *data)
{
	if (!data) {
		hash_err("no data was provided\n");
		return;
	}

	cls_printf("data 0x%lx value %u\n", data, *(unsigned int*)data);
}

int hash_create(hash_t *new_hash)
{
	if (!new_hash) {
		hash_err("invalid argument\n");
		return VSENTRY_INVALID;
	}

	if (new_hash->bits > MAX_NUM_OF_BITS) {
		hash_err("invalid bits %u. (upto %d bits)\n",
			bits, MAX_NUM_OF_BITS);
		return VSENTRY_INVALID;
	}

	hash_set_ops(new_hash);

	/* allocate buckets */
	new_hash->buckets = heap_calloc((1<<new_hash->bits) * sizeof(hash_bucket_t));
	if (!new_hash->buckets) {
		hash_err("failed to allocate table\n");
		return VSENTRY_ERROR;
	}

	hash_dbg("hash %s cretaed 0x%lx with %u buckets\n", new_hash->name,
		new_hash, (1<<new_hash->bits));

	return VSENTRY_SUCCESS;
}

void hash_set_ops(hash_t *hash)
{
	/* fill missing ops callback */
	if (!hash->hash_ops->del_data)
		hash->hash_ops->del_data = hash_default_del_data;

	if (!hash->hash_ops->comp)
		hash->hash_ops->comp = hash_default_compare;

	if (!hash->hash_ops->create_key)
		hash->hash_ops->create_key = hash_default_create_key;

	if (!hash->hash_ops->print)
		hash->hash_ops->print = hash_default_print_data;
}

/* hash_delete: delete the hash */
int hash_delete(hash_t *hash)
{
	if (!hash) {
		hash_err("no hash was provided\n");
		return VSENTRY_ERROR;
	}

	hash_dbg("deleting hash %s\n", hash->name);

	hash_empty_data(hash);
	heap_free(hash->buckets);

	return VSENTRY_SUCCESS;
}

/* hash_empty_data: delete all hash items and their content */
int hash_empty_data(hash_t *hash)
{
	int i;
	hash_item_t *del_item = NULL;
	hash_bucket_t *bucket = NULL;

	if (!hash) {
		hash_err("no hash was provided\n");
		return VSENTRY_ERROR;
	}

	hash_dbg("deleting all data in hash %s\n", hash->name);

	for(i=0; i<(1<<hash->bits); i++) {
		bucket = hash->buckets + (i*sizeof(hash_bucket_t));
		if (bucket->head_offset) {
			del_item = get_pointer(bucket->head_offset);

			while(del_item) {
				hash_dbg("hash %s: deleting bucket %u item 0x%lx data 0x%lx\n",
					hash->name, i, del_item, del_item->data);
				if (del_item->next_offset)
					bucket->head_offset = del_item->next_offset;
				else
					bucket->head_offset = 0;

				hash->hash_ops->del_data(get_pointer(del_item->data_offset));
				heap_free(del_item);
				del_item = get_pointer(bucket->head_offset);
			}
		}
	}

	hash_dbg("all data in hash %s deleted\n", hash->name);

	return VSENTRY_SUCCESS;
}

/* hash_insert: add new data to specific bucket in the hash table */
static int hash_insert_data_to_bucket(hash_t *hash, void *data, unsigned int bucket)
{
	hash_item_t *new_item = NULL;
	hash_bucket_t *bucket_p = NULL;

	if (!hash || !data) {
		hash_dbg("no hash/data was provided\n");
		return VSENTRY_ERROR;
	}

	if (bucket >= (1<<hash->bits)) {
		hash_err("invalid bucket %u. max %u\n", bucket, (1<<hash->bits)-1);
		return VSENTRY_ERROR;
	}

	/* allocate the new hash item */
	new_item = heap_calloc(sizeof(hash_item_t));
	if (!new_item) {
		hash_err("failed to allocate new item\n");
		return VSENTRY_ERROR;
	}

	/*set the data */
	new_item->data_offset = get_offset(data);
	new_item->next_offset = 0;

	/* place the new item in hash */
	bucket_p = hash->buckets + bucket;

	if (bucket_p->head_offset)
		new_item->next_offset = bucket_p->head_offset;

	bucket_p->head_offset = get_offset(new_item);

	hash_dbg("added new data 0x%lx item 0x%lx to hash %s\n", data, new_item, hash->name);

	return VSENTRY_SUCCESS;
}

/* hash_insert: add new data to the hash table */
int hash_insert_data(hash_t *hash, void *data)
{
	unsigned int bucket;

	if (!hash || !data) {
		hash_dbg("no hash/data was provided\n");
		return VSENTRY_ERROR;
	}

	/* generate the bucket key */
	bucket = hash->hash_ops->create_key(data, hash->bits);

	return hash_insert_data_to_bucket(hash, data, bucket);
}

/* hash_get_data: find an hash item in a specific bucket based on data and
 * return its content. the item content will be compared to data, if compare
 * function will decalre them as equals, the item's data will be returned */
static void *hash_get_data_from_bucket(hash_t *hash, void *data, unsigned int bucket)
{
	hash_item_t *get_item = NULL;
	void *get_data = NULL;
	hash_bucket_t *bucket_p = NULL;

	if (!hash || !data) {
		hash_err("no hash/data was provided\n");
		return NULL;
	}

	if (bucket >= (1<<hash->bits)) {
		hash_err("invalid bucket %u. max %u\n", bucket, (1<<hash->bits)-1);
		return NULL;
	}

	bucket_p = hash->buckets + bucket;

	get_item = get_pointer(bucket_p->head_offset);

	while (get_item) {
		hash_dbg("comparing 0x%lx to 0x%lx\n", get_item->data, data);

		if (hash->hash_ops->comp(get_pointer(get_item->data_offset), data)) {
			get_data = get_pointer(get_item->data_offset);
			hash_dbg("hash %s: found item 0x%lx in bucket %u\n",
				hash->name, get_item, bucket);
			break;
		}
		get_item = get_pointer(get_item->next_offset);
	}

	return get_data;
}

/* hash_get_data: find an hash item based on data and return its content.
 * the item content will be compared to data, if compare function will decalre
 * them as equals, the item's data will be returned */
void *hash_get_data(hash_t *hash, void *data)
{
	unsigned int bucket;

	if (!hash || !data) {
		hash_dbg("no hash/data was provided\n");
		return NULL;
	}

	bucket = hash->hash_ops->create_key(data, hash->bits);

	return hash_get_data_from_bucket(hash, data, bucket);
}

/* hash_delete_data: find an hash item in a bucket based on data and delete its content
 * and the item. the item content will be compared to data, if compare function
 * will decalre them as equals, the item's data and the item will be deleted */
int hash_delete_data_from_bucket(hash_t *hash, void *data, unsigned int bucket)
{
	hash_item_t *del_item = NULL, *prev_item = NULL;
	hash_bucket_t *bucket_p = NULL;

	if (!hash || !data) {
		hash_err("no hash/data was provided\n");
		return VSENTRY_ERROR;
	}

	if (bucket >= (1<<hash->bits)) {
		hash_err("invalid bucket %u. max %u\n", bucket, (1<<hash->bits)-1);
		return VSENTRY_ERROR;
	}

	hash_dbg("try to delete 0x%lx from %s\n", data, hash->name);

	bucket_p = hash->buckets + bucket;

	del_item = get_pointer(bucket_p->head_offset);

	while (del_item) {
		if (hash->hash_ops->comp(get_pointer(del_item->data_offset), data)) {
			hash_dbg("hash %s: deleting item 0x%lx data 0x%lx\n",
				hash->name, del_item, del_item->data);

			if (del_item == get_pointer(bucket_p->head_offset))
				bucket_p->head_offset = del_item->next_offset;
			else if (prev_item)
				prev_item->next_offset = del_item->next_offset;

			hash->hash_ops->del_data(get_pointer(del_item->data_offset));
			heap_free(del_item);

			return VSENTRY_SUCCESS;
		}

		hash_dbg("searching next ...\n");
		prev_item = del_item;
		del_item = get_pointer(del_item->next_offset);
	}

	hash_dbg("could not find a matched item to delete\n");

	return VSENTRY_ERROR;
}

/* hash_delete_data: find an hash item based on data and delete its content
 * and the item. the item content will be compared to data, if compare function
 * will decalre them as equals, the item's data and the item will be deleted */
int hash_delete_data(hash_t *hash, void *data)
{
	unsigned int bucket;

	if (!hash || !data) {
		hash_err("no hash/data was provided\n");
		return VSENTRY_ERROR;
	}

	bucket = hash->hash_ops->create_key(data, hash->bits);

	return hash_delete_data_from_bucket(hash, data, bucket);
}

void hash_print(hash_t *hash)
{
	int i;
	hash_item_t *print_item;
	hash_bucket_t *bucket = NULL;

	if (!hash || !hash->hash_ops->print) {
		hash_err("no hash/print_func was provided\n");
		return;
	}

	bucket = hash->buckets;

	for(i=0; i<(1<<hash->bits); i++) {
		if (bucket->head_offset) {
			print_item = get_pointer(bucket->head_offset);

//			cls_printf("bucket %u\n", i);
			while(print_item) {
				hash->hash_ops->print(get_pointer(print_item->data_offset));
				print_item = get_pointer(print_item->next_offset);
			}
		}
		bucket++;
	}
}
