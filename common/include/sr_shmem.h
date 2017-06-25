#ifndef __SR_SHMEM__
#define __SR_SHMEM__

#include "sr_types.h"

typedef struct {
	void* 	buffer; /* buffer pointer page aligned (used by user) */
	SR_32 	buffer_size;/* buffer size after page aligned (used by user) */
}sr_shmem;

#ifndef __KERNEL__
#ifndef PAGE_SIZE
#define PAGE_SIZE				4096
#endif
#endif

#define PAGES_PER_BUFFER 		16
#define MAX_BUFFER_SIZE 		(PAGE_SIZE * PAGES_PER_BUFFER)

#define ENG2MOD_PAGE_OFFSET 	0
#define MOD2ENG_PAGE_OFFSET 	(ENG2MOD_PAGE_OFFSET + PAGES_PER_BUFFER)
#define LOG_BUF_PAGE_OFFSET 	(MOD2ENG_PAGE_OFFSET + PAGES_PER_BUFFER)

#define ENG2MOD_SIZE_OFFSET		(ENG2MOD_PAGE_OFFSET * PAGE_SIZE)
#define MOD2ENG_SIZE_OFFSET		(MOD2ENG_PAGE_OFFSET * PAGE_SIZE)
#define LOG_BUF_SIZE_OFFSET 	(LOG_BUF_PAGE_OFFSET * PAGE_SIZE)

typedef enum {
	ENG2MOD_BUF = 0,
	MOD2ENG_BUF,
	LOG_BUF,
	MAX_BUF_TYPE = LOG_BUF,
	TOTAL_BUFS = (MAX_BUF_TYPE + 1),
} sr_buf_type;

/* the below function are OS depended thus need to implement 
 * them in the sal files but they are common to all */
SR_32 sal_shmem_alloc(sr_shmem *sr_shmem_ptr, SR_32 length, SR_32 type);
SR_32 sal_shmem_free(sr_shmem *sr_shmem_ptr);

#endif /* __SR_SHMEM__ */
