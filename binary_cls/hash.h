#ifndef __HASH_H__
#define __HASH_H__

#include <stdbool.h>

#define HASH_NAME_SIZE 	32
#define MAX_NUM_OF_BITS	32
#define GOLDEN_RATIO_32 0x61C88647

static inline unsigned int hash_32_generic(unsigned int val)
{
        return (val * GOLDEN_RATIO_32);
}

static inline unsigned int hash32(unsigned int val, unsigned int bits)
{
        /* High bits are more random, so use them. */
        return hash_32_generic(val) >> (MAX_NUM_OF_BITS - bits);
}

typedef struct hash_item {
	unsigned int 	next_offset;
	unsigned int 	data_offset;
} hash_item_t;

typedef struct {
	unsigned int 	head_offset;
} hash_bucket_t;

typedef struct {
	unsigned int 	(*create_key)(void *data, unsigned int number_of_bits);
	bool 		(*comp)(void *candidat, void *searched);
	int 		(*del_data)(void *data);
	void 		(*print)(void *data);
} hash_ops_t;

typedef struct {
	unsigned int  	bits;
	hash_ops_t 	*hash_ops;
	hash_bucket_t 	*buckets;
	char 		name[HASH_NAME_SIZE];
} hash_t;

int     hash_create(hash_t *new_hash);
void    hash_set_ops(hash_t *hash);
int     hash_delete(hash_t *hash);
int     hash_empty_data(hash_t *hash);
int     hash_insert_data(hash_t *hash, void *data);
void   *hash_get_data(hash_t *hash, void *data);
int     hash_delete_data(hash_t *hash, void *data);
void    hash_print(hash_t *hash);

#endif /* __HASH_H__ */
