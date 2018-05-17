/* file: sal_linux_mng.c
*/

#include <linux/mutex.h>
#include "sal_linux.h"
#include "sal_linux_mng.h"
#include "sr_types.h"

static struct mutex mutexs[SYNC_TOTAL] ;

SR_32 sal_linux_mng_readbuf_up(sr_sync_type sync_type)
{
	if (mutex_is_locked(&mutexs[sync_type]))
		mutex_unlock(&mutexs[sync_type]);

	return SR_SUCCESS;
}

SR_32 sal_linux_mng_readbuf_down(sr_sync_type sync_type)
{
	mutex_lock_interruptible(&mutexs[sync_type]);

	return SR_SUCCESS;
}

SR_32 sal_linux_mng_readbuf_init(void)
{
	SR_U32 i;

	for (i = 0; i < SYNC_TOTAL; i++) {
		mutex_init(&mutexs[i]);
		mutex_lock_interruptible(&mutexs[i]);
	}

	return SR_SUCCESS;
}
