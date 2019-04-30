#include <stddef.h>
#include <linux/vsentry/vsentry.h>
#include "lru_cache.h"
#include "bitops.h"
#include "heap.h"
#include "hash.h"
#include "aux.h"

#ifdef CACHE_UNIT_TEST
#define LRU_CACHE_MAX_ENTRIES		10
#else
#define LRU_CACHE_MAX_ENTRIES		10240
#endif
#define LRU_CACHE_HASH_NUM_OF_BITS	10
#define LRU_CACHE_HASH_SIZE		(1 << LRU_CACHE_HASH_NUM_OF_BITS)
#define LRU_CACHE_TOTAL_SIZE		((LRU_CACHE_MAX_ENTRIES * sizeof(node_t)) + sizeof(cls_lru_cache_t))

//#define CACHE_DEBUG
#ifdef CACHE_DEBUG
#include "classifier.h"
#define cache_dbg cls_dbg
#define cache_err cls_err
#else
#define cache_dbg(...)
#define cache_err(...)
#endif

// Free list Node (single linked list)
typedef struct free_node
{
	unsigned int next_free_offset;
} free_node_t;

/* a queue node (and a hash_offset bucket node):
 * 		queue is implemented as a double linked list - used to find LRU
 * 		hash_offset is implemented as an array of buckets (single linked list) - used for quick search
 */
typedef struct node
{
	unsigned long key; 				// the key stored in this node
	unsigned int  q_prev_offset;	// prev node in the queue
	unsigned int  q_next_offset;	// next node in the queue
	unsigned int  hash_next_offset;	// next node in the same hash_offset index (in case of collision)
	unsigned int  val_offset; 		// the value stored in this node
} node_t;

typedef struct {
	unsigned int free_head_offset;					// Free list for internal memory management
	unsigned int free_last_offset;					// Last free offset (used in case free list is empty)
	unsigned int head_offset;						// head_offset of the queue to maintain LRU
	unsigned int tail_offset;						// tail_offset of the queue to maintain LRU
	unsigned int hash_offset[LRU_CACHE_HASH_SIZE];	// A hash offset (array) of nodes for search
	unsigned int count; 							// Number of values currently in cache
} cls_lru_cache_t;


static cls_lru_cache_t *cache = NULL;

static volatile int cache_lock = 0;


static unsigned int cache_get_offset(void *ptr)
{
	if (ptr == NULL)
		return 0;
	return ((unsigned char*)ptr - (unsigned char*)cache) + 1;
}

static void *cache_get_pointer(unsigned int offset)
{
	if (!offset)
		return NULL;
	return (((unsigned char*)cache) + offset - 1);
}

/* Avoid the big up-front work of going one-by-one and initializing the free list:
 * Store the offset of the last free node.
 * To allocate, move this pointer one node back.
 * Free doesn't change - add the node to the free list.
*/
void cache_clear(void)
{
	node_t *ptr;

	vs_spin_lock(&cache_lock);

	vs_memset(cache, 0 , sizeof(cls_lru_cache_t));

	/* initialize only free last offset */
	ptr = (node_t *)(((unsigned char *)cache) + LRU_CACHE_TOTAL_SIZE);
	cache->free_last_offset = cache_get_offset(ptr - 1);

	vs_spin_unlock(&cache_lock);

	cache_dbg("*** DBG *** cache (with %d entries) total size = %d, mng is %d, node size = %d, cache %p, last free %p (%d)\n",
			LRU_CACHE_MAX_ENTRIES, LRU_CACHE_TOTAL_SIZE, sizeof(cls_lru_cache_t), sizeof(node_t), cache,
			cache_get_pointer(cache->free_last_offset), cache->free_last_offset);
}

int cache_init(unsigned int *cache_offset)
{
	if (*cache_offset == 0) {
		/* lru cache was not prev allocated. lets allocate */
		cache = heap_calloc(LRU_CACHE_TOTAL_SIZE);
		if (!cache) {
			cache_err("failed to allocate lru cache\n");
			return VSENTRY_ERROR;
		}

		/* update the global database, will be used in the next boot */
		*cache_offset = get_offset(cache);
	} else {
		/* restore prev allocated lru cache */
		cache = get_pointer(*cache_offset);
	}

	/* cache always start empty (hash_offset and queue are empty) */
	cache_clear();

	return VSENTRY_SUCCESS;
}

// always allocate a node_t so size parameter is not needed
static void *cache_malloc(void) {
	free_node_t *ptr1;
	node_t *ptr2;

	// check if we have something in free list, else use the last block
	if (cache->free_head_offset) {
//		cache_dbg("*** DBG *** free_head_offset = %d\n",cache->free_head_offset);
		ptr1 = cache_get_pointer(cache->free_head_offset);
		cache->free_head_offset = ptr1->next_free_offset;
		return ptr1;
	}
//	cache_dbg("*** DBG *** free_last_offset = %d\n",cache->free_last_offset);
	ptr2 = cache_get_pointer(cache->free_last_offset);
	cache->free_last_offset = cache_get_offset(ptr2 - 1);
	/* malloc cannot fail becasue we already checked the size, so if we just used the last free offset,
	 * new free_last_offset is invalid, but from next time only free_head_offset will used */
	return ptr2;
}

static void cache_free(node_t *ptr) {
	free_node_t *free_node = (free_node_t *)ptr;
	free_node->next_free_offset = cache->free_head_offset;
	cache->free_head_offset = cache_get_offset(free_node);
}

// assume this key is not in hash already
static void hash_add(node_t *node)
{
	unsigned int idx = hash32(node->key, LRU_CACHE_HASH_NUM_OF_BITS);
	node->hash_next_offset = cache->hash_offset[ idx ];
	cache->hash_offset[ idx ] = cache_get_offset(node);
}

// assume key is in hash
static void hash_del(unsigned long key)
{
	node_t *prev = NULL;
	unsigned int idx = hash32(key, LRU_CACHE_HASH_NUM_OF_BITS);
	node_t *bucket = cache_get_pointer(cache->hash_offset[ idx ]);
	while (bucket->key != key) {
		prev = bucket;
		bucket = cache_get_pointer(bucket->hash_next_offset);
	}
	if (prev)
		prev->hash_next_offset = bucket->hash_next_offset;
	else
		cache->hash_offset[ idx ] = bucket->hash_next_offset;
}

static node_t *hash_find(unsigned long key)
{
	node_t *bucket = cache_get_pointer(cache->hash_offset[ hash32(key, LRU_CACHE_HASH_NUM_OF_BITS) ]);
	while (bucket != NULL && bucket->key != key)
		bucket = cache_get_pointer(bucket->hash_next_offset);
	return bucket;
}

static void dequeue(void)
{
	node_t* temp = cache_get_pointer(cache->tail_offset);

	// If this is the only node in queue, then change head
	if (cache->head_offset == cache->tail_offset)
		cache->head_offset = 0;

	// Change tail_offset and remove the previous tail
	cache->tail_offset = temp->q_prev_offset;

	cache_free(temp);

	if (cache->tail_offset) { // now this is new tail (after delete of previous tail)
		temp = cache_get_pointer(cache->tail_offset);
		temp->q_next_offset = 0;
	}

	// decrement the number of entries
	cache->count--;
}

// A function to add a given value to cache
static void enqueue(unsigned long key, unsigned int val_offset)
{
	node_t* node, *new_node;
	unsigned int offset;

	// If cache is full, remove the last entry
	if (cache->count == LRU_CACHE_MAX_ENTRIES) {
		node = cache_get_pointer(cache->tail_offset);
		hash_del(node->key); // remove the entry from hash
		dequeue();
	}

	// Create a new node with given key and value and add it to the head of queue
	new_node = cache_malloc();
	new_node->val_offset = val_offset;
	new_node->key = key;
	new_node->q_next_offset = cache->head_offset;

	// If queue is empty, change both head and tail pointers
	if (cache->tail_offset == 0)
		cache->tail_offset = cache->head_offset = cache_get_offset(new_node);
	else { // Else change the head
		node = cache_get_pointer(cache->head_offset);
		offset = cache_get_offset(new_node);
		node->q_prev_offset = offset;
		cache->head_offset = offset;
	}

	// Add new entry to hash also
	hash_add(new_node);

	// increment number of cache entries
	cache->count++;
}

static void delete_node_from_queue(node_t* node)
{
	node_t* temp;

	// If this is the only node in queue, empty it
	if (cache->head_offset == cache->tail_offset) {
		cache->head_offset = cache->tail_offset = 0;
	} else {
		// queue is not empty after delete
		if (node->q_prev_offset) {
			temp = cache_get_pointer(node->q_prev_offset);
			temp->q_next_offset = node->q_next_offset;
		} else {
			// if node head no prev, we need to update head
			cache->head_offset = node->q_next_offset;
		}

		if (node->q_next_offset) {
			temp = cache_get_pointer(node->q_next_offset);
			temp->q_prev_offset = node->q_prev_offset;
		} else {
			// if node head no next, we need to update tail
			cache->tail_offset = node->q_prev_offset;
		}
	}

	cache_free(node);


	// decrement the number of entries
	cache->count--;
}

static void move_to_head(node_t* bucket)
{
	node_t* node;
	unsigned int offset;

	if (cache_get_offset(bucket) != cache->head_offset) {
		// Unlink the key node from its current location in queue
		if (bucket->q_prev_offset) {
			node = cache_get_pointer(bucket->q_prev_offset);
			node->q_next_offset = bucket->q_next_offset;
		}
		if (bucket->q_next_offset) {
			node = cache_get_pointer(bucket->q_next_offset);
			node->q_prev_offset = bucket->q_prev_offset;
		}

		// If the requested node is tail, then change tail (as this node will be moved to head)
		if (cache_get_offset(bucket) == cache->tail_offset) {
			cache->tail_offset = bucket->q_prev_offset;
			node = cache_get_pointer(cache->tail_offset);
			node->q_next_offset = 0;
		}

		// Put the requested node before current head
		bucket->q_next_offset = cache->head_offset;
		bucket->q_prev_offset = 0;

		// Change prev of current head
		node = cache_get_pointer(bucket->q_next_offset);
		offset = cache_get_offset(bucket);
		node->q_prev_offset = offset;

		// Change head to the requested key
		cache->head_offset = offset;
	}
}

/* Two cases:
 * 	1. Key is not there in cache, we insert it at the head of the queue
 * 	2. Key is in the cache, we only move it to head of the queue */
void cache_update(unsigned long key, unsigned int val_offset)
{
	node_t *bucket, *node;

	vs_spin_lock(&cache_lock);

	bucket = hash_find(key);
	if (bucket == NULL)
		enqueue(key, val_offset); // the key is not in cache, bring it
	else {
		move_to_head(bucket); // key is in queue but the head, move pointer to head
		node = cache_get_pointer(cache->head_offset);
		node->val_offset = val_offset; // update value
	}

	vs_spin_unlock(&cache_lock);
}

void cache_delete(unsigned long key)
{
	node_t *node;

	vs_spin_lock(&cache_lock);

	node = hash_find(key);
	if (node) {
		hash_del(key); // remove from hash
		delete_node_from_queue(node); // remove from queue
	}

	vs_spin_unlock(&cache_lock);
}

unsigned int cache_lookup(unsigned long key)
{
	node_t *node;
	unsigned int ret;

	vs_spin_lock(&cache_lock);

	node = hash_find(key);
	if (node) {
		move_to_head(node);
		ret = node->val_offset;
	} else
		ret = 0;

	vs_spin_unlock(&cache_lock);

	return ret;
}

