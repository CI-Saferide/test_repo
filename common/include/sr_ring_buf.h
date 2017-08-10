#ifndef __SR_RING_BUF__
#define __SR_RING_BUF__

#include "sr_types.h"

typedef struct {
	SR_32 	content_size;
	SR_32 	offset;
} sr_buffer;

typedef struct {
	SR_32 read_ptr;
	SR_32 write_ptr;
	SR_32 free_ptr;
	SR_32 each_buf_size;
	SR_32 num_of_bufs;
	SR_32 buf_mem_offset;
	SR_64 total_read_bytes;
	SR_64 total_read_bufs;
	SR_64 total_write_bytes;
	SR_64 total_write_bufs;
} sr_ring_buffer;

SR_32 sr_ring_buf_calc_buffers(SR_32 mem_size, SR_32 each_buf_size);
SR_32 sr_ring_buf_calc_mem(SR_32 num_of_buffers, SR_32 each_buf_size);
SR_32 sr_init_ring_buf(sr_ring_buffer *rb, SR_32 mem_size, SR_32 num_of_buffers, SR_32 each_buf_size);
SR_8 *sr_get_buf(sr_ring_buffer *rb, SR_32 size);
SR_32 sr_write_buf(sr_ring_buffer *rb, SR_32 size);
SR_8 *sr_read_buf(sr_ring_buffer *rb, SR_32 *size);
void sr_free_buf(sr_ring_buffer *rb);
void sr_print_rb_info(sr_ring_buffer *rb);

#endif /* __SR_RING_BUF__ */

