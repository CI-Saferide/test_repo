#include "sr_shmem.h"
#include "sal_linux.h"
#include "sr_sal_common.h"

SR_32 sal_shmem_free(sr_shmem *sr_shmem_ptr)
{
    if (!sr_shmem_ptr || !sr_shmem_ptr->buffer) {
        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=sal_shmem_alloc: wrong params: 0x%p, %p",
			REASON, sr_shmem_ptr, sr_shmem_ptr->buffer);
        return SR_ERROR;
    }

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=sal_shmem_free: freeing 0x%p:%d is",
		MESSAGE, sr_shmem_ptr->buffer, sr_shmem_ptr->buffer_size);

	munmap(sr_shmem_ptr->buffer, sr_shmem_ptr->buffer_size);

	sr_shmem_ptr->buffer = NULL;
	sr_shmem_ptr->buffer_size = 0;

	return SR_SUCCESS;
}

SR_32 sal_shmem_alloc(sr_shmem *sr_shmem_ptr, SR_32 length, SR_32 type)
{
	int offset, fd;

    if (!sr_shmem_ptr || (length <= 0) || (length > MAX_BUFFER_SIZE)) {
        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=sal_shmem_alloc: wrong params: 0x%p, %d", REASON, sr_shmem_ptr, length);
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
				"%s=sal_shmem_alloc: wrong buf type %d", REASON, type);
			return SR_ERROR;
	}

	if (!(fd = sal_get_vsentry_fd())) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=sal_shmem_alloc: no vsenbtry fd", REASON);
		return SR_ERROR;
	}

	sr_shmem_ptr->buffer = mmap(NULL, length, (PROT_READ | PROT_WRITE),
		(MAP_SHARED| MAP_LOCKED) ,fd, offset);
	if (sr_shmem_ptr->buffer == (void*)(-1)) {
		perror("");
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=sal_shmem_alloc: failed to mmap type %d %d", REASON, type, length);
		return SR_ERROR;
	}

	sr_shmem_ptr->buffer_size = length;

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=sal_shmem_alloc: allocated 0x%p size 0x%08x",
		MESSAGE, sr_shmem_ptr->buffer, sr_shmem_ptr->buffer_size);

	return SR_SUCCESS;
}

