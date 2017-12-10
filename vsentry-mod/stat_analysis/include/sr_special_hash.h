#ifndef  __SR_SPECIAL_HASH__
#define  __SR_SPECIAL_HASH__
 
#include "sr_hash.h"
#include <sr_ec_common.h>
#include <sr_cyclic_array.h>

#define SR_SPECIAL_HASH_ENT_REPOS_SIZE 100

typedef struct sr_special_hash_ops {
        SR_U32 (*create_key)(void *key);
        SR_U32 (*comp)(void *data_in_hash, void *comp_val);
        void (*free)(void *data_in_hash);
        void (*print)(void *data_in_hash);
} sr_special_hash_ops_t;

typedef struct sr_special_hash_ent {
	struct sr_special_hash_ent *next;
	SR_BOOL should_delete;
	void *data;
} sr_special_hash_ent_t;

typedef struct sr_special_hash_bucket {
        sr_special_hash_ent_t *head;
        SR_BOOL should_delete;
        SR_MUTEX bucket_lock;
} sr_special_hash_bucket_t;

typedef struct sr_special_hash_table {
	SR_U32 size;
	sr_special_hash_ops_t ops;
	sr_special_hash_bucket_t *buckets;
	sr_special_hash_ent_t *LRU_update;
	sr_special_hash_ent_t *LRU_transmit;
	sr_special_hash_ent_t *hash_ents_to_free[SR_SPECIAL_HASH_ENT_REPOS_SIZE];
	sr_cyclic_array_t gc_buffer;
} sr_special_hash_table_t;

sr_special_hash_table_t *sr_special_hash_new_table(int count, sr_special_hash_ops_t *ops);
SR_32 sr_special_hash_insert(sr_special_hash_table_t *table, void *key, void *data, SR_BOOL is_blocking, SR_BOOL is_atomic);
void sr_special_hash_soft_delete(sr_special_hash_table_t *table, void *key);
void *sr_special_hash_lookup(sr_special_hash_table_t *table, void *key);
void sr_special_hash_free_table(sr_special_hash_table_t *table);
SR_32 sr_special_hash_print_table(sr_special_hash_table_t *table);
SR_32 sr_special_hash_garbage_collection(sr_special_hash_table_t *table);
SR_32 sr_special_hash_soft_cleanup(sr_special_hash_table_t *table, SR_BOOL (*cb)(void *data));
SR_U32 sr_special_num_of_entries(sr_special_hash_table_t *table);

#endif
