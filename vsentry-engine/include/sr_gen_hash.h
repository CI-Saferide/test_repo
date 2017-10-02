#ifndef __HASH__H_
#define __HASH__H_

#include <sr_sal_common.h>

/*
#ifdef __KERNEL__
#define SR_Malloc(p, t, n) (p = (t) SR_ALLOC((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) SR_ZALLOC((unsigned long)(n)))
#define SR_Free(p) SR_FREE((caddr_t)p);
#else
#define SR_Malloc(p, t, n) (p = (t) malloc((unsigned long)(n)))
#define SR_Zalloc(p, t, n) (p = (t) calloc(1, (unsigned long)(n)))
#define SR_Free(p) free((caddr_t)p);
#endif

#define CHECK 90
*/

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
