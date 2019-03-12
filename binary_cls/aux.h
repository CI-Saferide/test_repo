#ifndef __AUX_H__
#define __AUX_H__

#include <stddef.h>

/* the below function are libc replacement */
void   *memset(void *s, int c, size_t n);
int     memcmp(const void *s1, const void *s2, size_t n);
void   *memcpy(void *dest, const void *src, size_t n);
size_t strlen(const char *s);
void   spin_lock(volatile int *lock);
int    spin_trylock(volatile int *lock);
void   spin_unlock(volatile int *lock);

#endif /* __AUX_H__ */
