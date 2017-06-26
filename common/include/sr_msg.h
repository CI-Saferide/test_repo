#ifndef __SR_MSG__
#define __SR_MSG__

#include "sr_types.h"
#include "sr_shmem.h"

SR_32 sr_msg_alloc_buf(SR_U8 type, SR_32 length);
SR_32 sr_msg_free_buf(SR_U8 type);
SR_32 sr_send_msg(SR_U8 type, SR_U8 *data, SR_U32 length);
SR_32 sr_read_msg(SR_U8 type, SR_U8 *data, SR_U32 length, SR_BOOL copy);
sr_shmem* sr_msg_get_buf(SR_U8 type);

#endif /* __SR_MSG__ */

