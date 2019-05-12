/*
 * Copyright (c) 2009-2012, Pieter Noordhuis <pcnoordhuis at gmail dot com>
 * Copyright (c) 2009-2012, Salvatore Sanfilippo <antirez at gmail dot com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *   * Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *   * Neither the name of Redis nor the names of its contributors may be used
 *     to endorse or promote products derived from this software without
 *     specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */


#ifndef __REDIS_RIO_H
#define __REDIS_RIO_H

#include <stdio.h>
#include <stdint.h>
//#include <string.h>
#include "sds.h"

struct _rio {
    /* Backend functions.
     * Since this functions do not tolerate short writes or reads the return
     * value is simplified to: zero on error, non zero on complete success. */
    size_t (*read)(struct _rio *, void *buf, size_t len);
    size_t (*write)(struct _rio *, const void *buf, size_t len);
    off_t (*tell)(struct _rio *);
    int (*flush)(struct _rio *);
    /* The update_cksum method if not NULL is used to compute the checksum of
     * all the data that was read or written so far. The method should be
     * designed so that can be called with the current checksum, and the buf
     * and len fields pointing to the new block of data to add to the checksum
     * computation. */
    void (*update_cksum)(struct _rio *, const void *buf, size_t len);

    int (*encrypt)(const char *plaintext, int in_len, char **ciphertext, int *out_len, int last);
    int (*decrypt)(char *ciphertext, int in_len, char *plaintext, int *out_len);
	size_t load_total_bytes;

    /* The current checksum */
    uint64_t cksum;

    /* number of bytes read or written */
    size_t processed_bytes;

    /* maximum single read or write chunk size */
    size_t max_processing_chunk;

    /* Backend-specific vars. */
    union {
        /* In-memory buffer target. */
        struct {
            sds ptr;
            off_t pos;
        } buffer;
        /* Stdio file pointer target. */
        struct {
            FILE *fp;
            off_t buffered; /* Bytes written since last fsync. */
            off_t autosync; /* fsync after 'autosync' bytes written. */
        } file;
        /* Multiple FDs target (used to write to N sockets). */
        struct {
            int *fds;       /* File descriptors. */
            int *state;     /* Error state of each fd. 0 (if ok) or errno. */
            int numfds;
            off_t pos;
            sds buf;
        } fdset;
    } io;
};

typedef struct _rio rio;

static char tmp_read_buf[1024];

/* The following functions are our interface with the stream. They'll call the
 * actual implementation of read / write / tell, and will update the checksum
 * if needed. */

static inline size_t rioWrite(rio *r, const void *buf, size_t len) {
	char *c_buf;
	size_t write_len;
	int bytes_to_write;
//	int i;

//	printf("*** DBG *** rioWrite: %d\n", (int)len);
	/*for (i = 0; i < (int)len; i++)
		printf("%c", ((char *)buf)[i]);
	printf("\n");*/
	while (len) {
		write_len = (r->max_processing_chunk && r->max_processing_chunk < len) ? r->max_processing_chunk : len;
		if (r->encrypt) {
			if (r->encrypt(buf, (int)write_len, &c_buf, &bytes_to_write, 0)) {
//				printf("*** ERR *** rioWrite: encrypt fail\n");
				return 0;
			}
			if (bytes_to_write) {
//				printf("*** DBG *** rioWrite: (enc) bytes_to_write %d\n", bytes_to_write);fflush(stdout);
				if (r->write(r, c_buf, bytes_to_write) == 0) {
//					printf("*** ERR *** rioWrite: (enc) write ret 0\n");
					return 0;
				}
			}
		} else {
			if (r->update_cksum)
				r->update_cksum(r, buf, write_len);
			if (r->write(r, buf, write_len) == 0) {
				printf("*** ERR *** rioWrite: (non enc)write ret 0\n");
				return 0;
			}
		}
		buf = (char *)buf + write_len;
		len -= write_len;
		r->processed_bytes += write_len;
	}
	return 1;
}

static inline size_t rioRead(rio *r, void *buf, size_t len) {
	size_t read_len;
	int read_bytes;

//	printf("*** DBG *** read len %d\n", (int)len);
    while (len) {
        read_len = (r->max_processing_chunk && r->max_processing_chunk < len) ? r->max_processing_chunk : len;
        if (r->decrypt) {
        	if (!r->load_total_bytes) { // fixme remove
        		printf("*** ERR *** decrypt but no load_total_bytes !!!\n");
        		return 0;
        	}
            // first try to use what we have in the decrypted buffer
//        	printf("*** DBG *** dec NULL len %d\n", (int)read_len);fflush(stdout);
        	if (r->decrypt(NULL, (int)read_len, buf, &read_bytes)) {
//        		printf("*** ERR *** rioRead: decrypt fail\n");
        		return 0;
        	}
        	if (read_bytes == (int)read_len) {
        		// have all the bytes we need already read and decrypted
        		buf = (char*)buf + read_len;
        		len -= read_len;
        	} else {
        		 // save the length we need, before reading more from file
        		buf = (char*)buf + read_bytes;
        		read_len -= read_bytes;
        		len -= read_bytes;
        		read_bytes = read_len;

        		// need to read and decrypt more bytes
        		read_len = r->load_total_bytes - r->processed_bytes < 1024 ? r->load_total_bytes - r->processed_bytes : 1024;
//        		printf("*** DBG *** before read: total_bytes %d - processed_bytes %d -> %d (needed %d)\n",
//        				(int)r->load_total_bytes, (int)r->processed_bytes, (int)read_len, read_bytes);fflush(stdout);
        		if (!r->read(r, tmp_read_buf, read_len)) {
//        			printf("*** ERR *** rioRead: read failed\n");
        			return 0;
        		}

        		// todo decrypt read_len bytes and continue with read_bytes bytes we still need to read
//        		printf("*** DBG *** bef: dec BUF len %d -> %d\n", (int)read_len, read_bytes);fflush(stdout);
        		if (r->decrypt(tmp_read_buf, (int)read_len, buf, &read_bytes)) {
//        			printf("*** ERR *** rioRead: decrypt fail\n");
        			return 0;
        		}
//        		printf("*** DBG *** aft: dec BUF len %d -> %d\n", (int)read_len, read_bytes);fflush(stdout);
        		buf = (char*)buf + read_bytes;
        		len -= read_bytes;
        		r->processed_bytes += read_len;
        	}
        } else {
        	if (!r->read(r, buf, read_len)) {
//        		printf("*** ERR *** rioRead: (nor) read failed\n");
        		return 0;
        	}

        	if (r->update_cksum)
        		r->update_cksum(r, buf, read_len);

        	buf = (char*)buf + read_len;
        	len -= read_len;
        	r->processed_bytes += read_len;
        }
    }
    return 1;
}

static inline off_t rioTell(rio *r) {
    return r->tell(r);
}

static inline int rioFlush(rio *r) {
    return r->flush(r);
}

void rioInitWithFile(rio *r, FILE *fp);
void rioInitWithBuffer(rio *r, sds s);
void rioInitWithFdset(rio *r, int *fds, int numfds);

void rioFreeFdset(rio *r);

size_t rioWriteBulkCount(rio *r, char prefix, long count);
size_t rioWriteBulkString(rio *r, const char *buf, size_t len);
size_t rioWriteBulkLongLong(rio *r, long long l);
size_t rioWriteBulkDouble(rio *r, double d);

struct redisObject;
int rioWriteBulkObject(rio *r, struct redisObject *obj);

void rioGenericUpdateChecksum(rio *r, const void *buf, size_t len);
void rioSetAutoSync(rio *r, off_t bytes);

#endif
