#include <asm/bitsperlong.h>
#include "aux.h"
#include "classifier.h"
#include <stdint.h>

//#define AUX_DEBUG
#ifdef AUX_DEBUG
#define aux_dbg cls_dbg
#define aux_err cls_err
#else
#define aux_dbg(...)
#define aux_err(...)
#endif

#if __BITS_PER_LONG == 64
#define ADDRESS_MASK 	0x7
#else
#define ADDRESS_MASK 	0x3
#endif

void *vs_memset(void *s, int c, size_t n)
{
	unsigned long *wbuf;
	unsigned char *buf = s;
	unsigned long x=0, i;

	while (n && ((unsigned long)buf & ADDRESS_MASK)) {
		*buf++ = (unsigned char)c;
		--n;
	}

	if (!n)
		return s;

	for (i = 0; i<sizeof(unsigned long); ++i)
		x |= c << (i*8);

	wbuf = (unsigned long*)buf;
	while (n >= sizeof(unsigned long)) {
		*wbuf++ = x;
		n -= sizeof(unsigned long);
	}

	buf = (unsigned char*)wbuf;
	while (n--)
		*buf++ = (unsigned char)c;

	return s;
}

int vs_memcmp(const void *const s1, const void *const s2, size_t n)
{
	const unsigned long *wbuf1, *wbuf2;
	const unsigned char *buf1 = s1, *buf2 = s2;

	if (((unsigned long)buf1 & ADDRESS_MASK) == ((unsigned long)buf2 & ADDRESS_MASK)) {

		while (n && ((unsigned long)buf1 & ADDRESS_MASK)) {
			if (*buf1++ != *buf2++)
				return n;
			--n;
		}

		wbuf1 = (unsigned long*)buf1;
		wbuf2 = (unsigned long*)buf2;

		while (n >= sizeof(unsigned long)) {
			if (*wbuf1++ != *wbuf2++)
				return n;
			n -= sizeof(unsigned long);
		}

		buf1 = (unsigned char*)wbuf1;
		buf2 = (unsigned char*)wbuf2;
	}

	while (n) {
		if (*buf1++ != *buf2++)
			return n;
		n--;
	}

	return 0;
}

void* vs_memcpy(void *dest, const void *src, size_t n)
{
	const unsigned long *wbufs;
	unsigned long *wbufd;
	const unsigned char *bufs = src;
	unsigned char *bufd = dest;

	if (((unsigned long)bufs & ADDRESS_MASK) == ((unsigned long)bufd & ADDRESS_MASK)) {

		while (n && ((unsigned long)bufs & ADDRESS_MASK)) {
			*bufd++ = *bufs++;
			--n;
		}

		wbufs = (const unsigned long*)bufs;
		wbufd = (unsigned long*)bufd;

		while (n >= sizeof(unsigned long)) {
			*wbufd++ = *wbufs++;
			n -= sizeof(unsigned long);
		}

		bufs = (const unsigned char*)wbufs;
		bufd = (unsigned char*)wbufd;
	}

	while (n--)
		*bufd++ = *bufs++;

	return dest;
}

size_t vs_strlen(const char *s)
{
        const char *sc;

        for (sc = s; *sc != '\0'; ++sc);

        return sc - s;
}

void vs_spin_lock(volatile int *lock)
{
	aux_dbg("locking %p\n", lock);
	while (__sync_lock_test_and_set(lock, 1));
	aux_dbg("locked %p\n", lock);
}

int vs_spin_trylock(volatile int *lock)
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

void vs_spin_unlock(volatile int *lock)
{
	aux_dbg("unlocking %p\n", lock);
	__sync_lock_release(lock);
	aux_dbg("unlocked %p\n", lock);
}
