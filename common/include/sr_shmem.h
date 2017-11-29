#ifndef __SR_SHMEM__
#define __SR_SHMEM__

#include "sr_types.h"

typedef struct {
	void 	*buffer;
	SR_32	buffer_size;
}sr_shmem;

#ifndef __KERNEL__
#ifndef PAGE_SIZE
#define PAGE_SIZE				4096
#endif
#endif

#define MAX_BUFFER_SIZE 		0x20000 /*128KB per memory buffer*/
#define PAGES_PER_BUFFER 		(MAX_BUFFER_SIZE / PAGE_SIZE)

#define ENG2MOD_PAGE_OFFSET 	0
#define MOD2ENG_PAGE_OFFSET 	(ENG2MOD_PAGE_OFFSET + PAGES_PER_BUFFER)
#define ENG2LOG_PAGE_OFFSET 	(MOD2ENG_PAGE_OFFSET + PAGES_PER_BUFFER)
#define MOD2LOG_PAGE_OFFSET 	(ENG2LOG_PAGE_OFFSET + PAGES_PER_BUFFER)
#define MOD2STAT_PAGE_OFFSET 	(MOD2LOG_PAGE_OFFSET + PAGES_PER_BUFFER)

#define ENG2MOD_SIZE_OFFSET		(ENG2MOD_PAGE_OFFSET * PAGE_SIZE)
#define MOD2ENG_SIZE_OFFSET		(MOD2ENG_PAGE_OFFSET * PAGE_SIZE)
#define ENG2LOG_SIZE_OFFSET 	(ENG2LOG_PAGE_OFFSET * PAGE_SIZE)
#define MOD2LOG_SIZE_OFFSET 	(MOD2LOG_PAGE_OFFSET * PAGE_SIZE)
#define MOD2STAT_SIZE_OFFSET 	(MOD2STAT_PAGE_OFFSET * PAGE_SIZE)

/* define the max size of each msg by type */
#define ENG2MOD_MSG_MAX_SIZE 	64   /* eng -> mod max msg size 64 bytes */
#define MOD2ENG_MSG_MAX_SIZE 	1024   /* mod -> eng max msg size 1024 bytes - it is aggregated */
#define LOG_MSG_MAX_SIZE 		2048 /* mod/eng -> log max msg size 2KB */ 
#define MOD2STAT_MSG_MAX_SIZE 	1024 /* mod/stat -> stat max msg size 1KB */ 

/* define the total number of msgs in each ring buffer */
#define ENG2MOD_TOTAL_MSGS 		(MAX_BUFFER_SIZE / ENG2MOD_MSG_MAX_SIZE)
#define MOD2ENG_TOTAL_MSGS 		(MAX_BUFFER_SIZE / MOD2ENG_MSG_MAX_SIZE)
#define LOG_TOTAL_MSGS 			(MAX_BUFFER_SIZE / LOG_MSG_MAX_SIZE)
#define STAT_TOTAL_MSGS 		(MAX_BUFFER_SIZE / STAT_MSG_MAX_SIZE)

typedef enum {
	ENG2MOD_BUF = 0,
	MOD2ENG_BUF,
	ENG2LOG_BUF,
	MOD2LOG_BUF,
	MOD2STAT_BUF,
	MAX_BUF_TYPE = MOD2STAT_BUF,
	TOTAL_BUFS = (MAX_BUF_TYPE + 1),
} sr_buf_type;

/* the below function are OS depended thus need to implement 
 * them in the sal files but they are common to all */
SR_32 sal_shmem_alloc(sr_shmem *sr_shmem_ptr, SR_32 length, SR_32 type);
SR_32 sal_shmem_free(sr_shmem *sr_shmem_ptr);

#endif /* __SR_SHMEM__ */
