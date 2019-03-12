#include "aux.h"
#include "classifier.h"

//#define AUX_DEBUG
#ifdef AUX_DEBUG
#define aux_dbg cls_dbg
#define aux_err cls_err
#else
#define aux_dbg(...)
#define aux_err(...)
#endif

void *memset(void *s, int c, size_t n)
{
        char *xs = s;

        while (n--)
                *xs++ = c;

        return s;
}

int memcmp(const void *s1, const void *s2, size_t n)
{
        const unsigned char *su1, *su2;
        int res = 0;

        for (su1 = s1, su2 = s2; 0 < n; ++su1, ++su2, n--)
                if ((res = *su1 - *su2) != 0)
                        break;
        return res;
}

void *memcpy(void *dest, const void *src, size_t n)
{
	char *tmp = dest;
	const char *s = src;

	while (n--)
		*tmp++ = *s++;

	return dest;
}

size_t strlen(const char *s)
{
        const char *sc;

        for (sc = s; *sc != '\0'; ++sc);

        return sc - s;
}

void spin_lock(volatile int *lock)
{
	aux_dbg("locking %p\n", lock);
	while (__sync_lock_test_and_set(lock, 1));
	aux_dbg("locked %p\n", lock);
}

int spin_trylock(volatile int *lock)
{
#ifdef AUX_DEBUG
	int ret;

	aux_dbg("try lock %p\n", lock);
	ret = __sync_lock_test_and_set(lock, 1);

	if (ret == 0) {
		aux_dbg("locked %p\n", lock);
		return 1;
	}

	aux_dbg("failed tot lock %p\n", lock);

	return 0;
#else
	return (__sync_lock_test_and_set(lock, 1) == 0);
#endif
}

void spin_unlock(volatile int *lock)
{
	aux_dbg("unlocking %p\n", lock);
	__sync_lock_release(lock);
	aux_dbg("unlocked %p\n", lock);
}
