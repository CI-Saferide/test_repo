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

void *vs_memset(void *s, int c, size_t n)
{
	const size_t word_size = sizeof(unsigned long);
	const size_t word_align = (word_size >= 8) ? word_size : 8;
	const uintptr_t align_mask = word_align - 1;
	unsigned char * buf = s;
	const uintptr_t addr = (uintptr_t) s;
	uintptr_t x = c & 0xff;
	uintptr_t i;
	unsigned long *wbuf;
	const uintptr_t skip = word_align - (addr & align_mask);

	for (i = 1; i<word_size; ++i)
		x |= x << (i*8);

	for (i = 0; i < skip; ++i) {
		*buf++ = (unsigned char)c;
		--n;
	}

	wbuf = (unsigned long*)buf;

	while (n >= word_size) {
		*wbuf++ = x;
		n -= word_size;
	}

	buf = (unsigned char*)wbuf;

	while (n--)
		*buf++ = (unsigned char)c;

	return s;
}

int vs_memcmp(const void *const s1, const void *const s2, size_t n)
{
	const size_t word_size = sizeof(unsigned long);
	const size_t word_align = (word_size >= 8) ? word_size : 8;
	const uintptr_t align_mask = word_align - 1;
	const unsigned char * buf1 = s1;
	const unsigned char * buf2 = s2;
	const uintptr_t addr1 = (uintptr_t) s1;
	const uintptr_t addr2 = (uintptr_t) s2;

	if (s1 == s2)
		return 0;

	if ((addr1 & align_mask) == (addr2 & align_mask)) {
		uintptr_t i;
		const unsigned long *wbuf1, *wbuf2;
		const uintptr_t skip = word_align - (addr1 & align_mask);

		for (i = 0; i < skip; ++i) {
			if (*buf1++ != *buf2++)
				return n;
			--n;
		}

		wbuf1 = (const unsigned long*)buf1;
		wbuf2 = (const unsigned long*)buf2;

		while (n >= word_size) {
			if (*wbuf1++ != *wbuf2++)
				return n;
			n -= word_size;
		}

		buf1 = (const unsigned char*)wbuf1;
		buf2 = (const unsigned char*)wbuf2;
	}

	while (n--) {
		if (*buf1++ != *buf2++)
			return n;
	}

	return 0;
}

void* vs_memcpy(void *dest, const void *src, size_t n)
{
	const size_t word_size = sizeof(unsigned long);
	const size_t word_align = (word_size >= 8) ? word_size : 8;
	const uintptr_t align_mask = word_align - 1;
	unsigned char * buf_dest = dest;
	const unsigned char * buf_src = src;
	uintptr_t addr_dest = (uintptr_t) dest;
	const uintptr_t addr_src = (uintptr_t) src;

	if ((addr_dest & align_mask) == (addr_src & align_mask)) {
		uintptr_t i;
		const unsigned long *wbuf_src;
		unsigned long *wbuf_dest;
		const uintptr_t skip = word_align - (addr_dest & align_mask);

		for (i = 0; i < skip; ++i) {
			*buf_dest++ = *buf_src++;
			--n;
		}

		wbuf_src = (const unsigned long*)buf_src;
		wbuf_dest = (unsigned long*)buf_dest;

		while (n >= word_size) {
			*wbuf_dest++ = *wbuf_src++;
			n -= word_size;
		}

		buf_src = (const unsigned char*)wbuf_src;
		buf_dest = (unsigned char*)wbuf_dest;
	}

	while (n--)
		*buf_dest++ = *buf_src++;

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
