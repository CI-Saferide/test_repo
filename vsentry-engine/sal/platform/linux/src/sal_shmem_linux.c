#include "sr_shmem.h"
#include "sal_linux.h"
#include "sr_sal_common.h"

static int fd = 0;

SR_32 sal_shmem_free(sr_shmem *sr_shmem_ptr)
{
    if (!sr_shmem_ptr || !sr_shmem_ptr->buffer) {
        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"sal_shmem_alloc: wrong params: 0x%p, %p\n",
			sr_shmem_ptr, sr_shmem_ptr->buffer);
        return SR_ERROR;
    }

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"sal_shmem_free: freeing 0x%p:%d is\n",
		sr_shmem_ptr->buffer, sr_shmem_ptr->buffer_size);

	munmap(sr_shmem_ptr->buffer, sr_shmem_ptr->buffer_size);

	sr_shmem_ptr->buffer = NULL;
	sr_shmem_ptr->buffer_size = 0;

	return SR_SUCCESS;
}

SR_32 sal_shmem_alloc(sr_shmem *sr_shmem_ptr, SR_32 length, SR_32 type)
{
	int offset;

    if (!sr_shmem_ptr || (length <= 0) || (length > MAX_BUFFER_SIZE)) {
        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"sal_shmem_alloc: wrong params: 0x%p, %d\n", sr_shmem_ptr, length);
        return -EIO;
    }

	switch (type) {
		case ENG2MOD_BUF:
			offset = ENG2MOD_SIZE_OFFSET;
			break;
		case MOD2ENG_BUF:
			offset = MOD2ENG_SIZE_OFFSET;
			break;
		case ENG2LOG_BUF:
			offset = ENG2LOG_SIZE_OFFSET;
			break;
		case MOD2LOG_BUF:
			offset = MOD2LOG_SIZE_OFFSET;
			break;
		case MOD2STAT_BUF:
			offset = MOD2STAT_SIZE_OFFSET;
			break;
		default:
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
				"sal_shmem_alloc: wrong buf type %d\n", type);
			return SR_ERROR;
	}

	if (fd == 0 ) {
		fd = open(VS_FILE_NAME, O_RDWR|O_SYNC);
		if (fd < 0) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
				"sal_shmem_alloc: faield to open %s\n", VS_FILE_NAME);
			return SR_ERROR;
		}
	}

	sr_shmem_ptr->buffer = mmap(NULL, length, (PROT_READ | PROT_WRITE),
		(MAP_SHARED| MAP_LOCKED) ,fd, offset);
	if (sr_shmem_ptr->buffer == (void*)(-1)) {
		perror("");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"sal_shmem_alloc: failed to mmap type %d %d\n", type, length);
		return SR_ERROR;
	}

	sr_shmem_ptr->buffer_size = length;

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"sal_shmem_alloc: allocated 0x%p size 0x%08x\n",
		sr_shmem_ptr->buffer, sr_shmem_ptr->buffer_size);

	return SR_SUCCESS;
}

