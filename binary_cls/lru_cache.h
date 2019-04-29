#ifndef __CACHE_H__
#define __CACHE_H__

int cache_init(unsigned int *cache_offset);
unsigned int cache_lookup(unsigned long key);
void cache_update(unsigned long key, unsigned int val_offset);
void cache_clear(void);
void cache_delete(unsigned long key);

#endif /* __CACHE_H__ */
