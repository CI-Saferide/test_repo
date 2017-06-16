#ifndef SR_HASH_H
#define SR_HASH_H

#include "sal_linux.h"
#include "sal_bitops.h"

#define SR_U32 unsigned long

struct sr_hash_ent_t{
	SR_U32 key;
	SR_U32 type;
	struct sr_hash_ent_t *next;
	SR_U32 rule;
	bit_array rules;
	//char pad[1];
};

struct sr_hash_bucket_t{
	struct sr_hash_ent_t *head;
	// SR_U32 count; // might want this
	SR_RWLOCK bucket_lock;
};

struct sr_hash_table_t{
	SR_U32 size;
	SR_U32 count; // for sanity
	struct sr_hash_bucket_t *buckets;
};


struct sr_hash_table_t *sr_hash_new_table(int count);
int sr_hash_insert(struct sr_hash_table_t *table, struct sr_hash_ent_t *ent);
void sr_hash_delete(struct sr_hash_table_t *table, SR_U32 key);
struct sr_hash_ent_t *sr_hash_lookup(struct sr_hash_table_t *table, SR_U32 key);
void sr_hash_free_table(struct sr_hash_table_t *table);
void sr_hash_print_table(struct sr_hash_table_t *table);


#endif
