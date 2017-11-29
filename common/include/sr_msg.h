#ifndef __SR_MSG__
#define __SR_MSG__

#include "sr_types.h"
#include "sr_shmem.h"

SR_32 sr_msg_alloc_buf(SR_U8 type, SR_32 length);
SR_32 sr_msg_free_buf(SR_U8 type);
SR_8 *sr_read_msg(SR_U8 type, SR_32 *length);
SR_32 sr_free_msg(SR_U8 type);
SR_8 *sr_get_msg(SR_U8 type, SR_32 size);
SR_32 sr_send_msg(SR_U8 type, SR_32 length);
sr_shmem* sr_msg_get_buf(SR_U8 type);
void sr_msg_print_stat(void);
SR_U32 sr_msg_get_buffer_msg_size(SR_U8 type);

#endif /* __SR_MSG__ */

