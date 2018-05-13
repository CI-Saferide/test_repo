#ifndef __SAL_LINUX_MNG__
#define __SAL_LINUX_MNG__

#include "sr_types.h"

typedef enum {
	SYNC_INFO_GATHER,
	SYNC_ENGINE,
	SYNC_MAX = SYNC_ENGINE,
	SYNC_TOTAL = SYNC_MAX + 1,
} sr_sync_type;

SR_32 sal_linux_mng_readbuf_init(void);
SR_32 sal_linux_mng_readbuf_up(sr_sync_type sync_type);
SR_32 sal_linux_mng_readbuf_down(sr_sync_type sync_type);

#endif
