#ifndef __SR_RING_BUF__
#define __SR_RING_BUF__

#include "sr_types.h"

typedef struct {
	SR_32 buf_size;
	SR_32 read_ptr;
	SR_32 write_ptr;
} sr_ring_buffer;

SR_32 init_buf(SR_32 size, sr_ring_buffer *rb);
SR_32 get_max_read_size(sr_ring_buffer *rb);
SR_32 get_max_write_size(sr_ring_buffer *rb);
SR_32 write_to_buf(sr_ring_buffer *rb, SR_U8 *data, SR_32 length);
SR_32 read_buf(sr_ring_buffer *rb, SR_U8 *data, SR_32 size, SR_BOOL copy);
SR_32 reset_buf(sr_ring_buffer *rb);

#endif /* __SR_RING_BUF__ */

