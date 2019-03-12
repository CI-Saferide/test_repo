#ifndef __AUX_H__
#define __AUX_H__

#include <stddef.h>

/* the below function are libc replacement */
void   *vs_memset(void *s, int c, size_t n);
int     vs_memcmp(const void *s1, const void *s2, size_t n);
void   *vs_memcpy(void *dest, const void *src, size_t n);
size_t vs_strlen(const char *s);
void   vs_spin_lock(volatile int *lock);
int    vs_spin_trylock(volatile int *lock);
void   vs_spin_unlock(volatile int *lock);

#endif /* __AUX_H__ */
