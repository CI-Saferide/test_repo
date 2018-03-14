#ifndef __SR_MSG__
#define __SR_MSG__

#include "sr_types.h"
#include "sr_shmem.h"

SR_32 sr_msg_alloc_buf(sr_buf_type type, SR_32 length);
SR_32 sr_msg_free_buf(sr_buf_type type);
SR_8 *sr_read_msg(sr_buf_type type, SR_32 *length);
SR_32 sr_free_msg(sr_buf_type type);
SR_8 *sr_get_msg(sr_buf_type type, SR_32 size);
SR_32 sr_send_msg(sr_buf_type type, SR_32 length);
sr_shmem* sr_msg_get_buf(sr_buf_type type);
void sr_msg_print_stat(void);
SR_U32 sr_msg_get_buffer_msg_size(sr_buf_type type);

#endif /* __SR_MSG__ */

