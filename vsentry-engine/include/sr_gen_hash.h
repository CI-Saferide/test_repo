#ifndef __HASH__H_
#define __HASH__H_

#include <sr_sal_common.h>

typedef struct hash_ops {
        int (*create_key)(void *key);
        int (*comp)(void *data_in_hash, void *comp_val);
        void (*free)(void *data_in_hash);
        void (*print)(void *data_in_hash);
} hash_ops_t;

struct sr_gen_hash *sr_gen_hash_new(int size, hash_ops_t hash_ops);
SR_32 sr_gen_hash_insert(struct sr_gen_hash *hash, void *key, void *data);
SR_32 sr_gen_hash_delete(struct sr_gen_hash *hash, void *key);
void *sr_gen_hash_get(struct sr_gen_hash *hash, void *key);
void sr_gen_hash_destroy(struct sr_gen_hash *hash);
SR_32 sr_gen_hash_delete_all(struct sr_gen_hash *hash);
void sr_gen_hash_print(struct sr_gen_hash *hash);

#endif
