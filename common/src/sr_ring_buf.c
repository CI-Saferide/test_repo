#include "sr_ring_buf.h"
#include "sr_sal_common.h"

SR_32 init_buf(SR_32 size, sr_ring_buffer *rb)
{
	rb->buf_size = size;
	rb->free_slots = size;
	rb->read_ptr = 0;
	rb->write_ptr = 0;

	return 0;
}

SR_32 get_max_read_size(sr_ring_buffer *rb)
{
	return (rb->buf_size - rb->free_slots);
}

SR_32 get_max_write_size(sr_ring_buffer *rb)
{
	return rb->free_slots;
}

SR_32 write_to_buf(sr_ring_buffer *rb, SR_U8 *data, SR_32 length)
{
	SR_U8 *buf_ptr = ((SR_U8 *)rb + sizeof(sr_ring_buffer));

	if (length <= get_max_write_size(rb)) {
		if (rb->write_ptr + length < rb->buf_size) {
			sal_memcpy(buf_ptr + rb->write_ptr, data, length);
			rb->write_ptr += length;
		} else {
			SR_32 first_size = rb->buf_size - rb->write_ptr;
			SR_32 second_size = length - first_size;

			sal_memcpy(buf_ptr +rb->write_ptr, data, first_size);
			sal_memcpy(buf_ptr, data + first_size, second_size);
			rb->write_ptr = second_size;
		}
		rb->free_slots -= length;
#ifdef SR_RB_DEBUG
		sal_printf("write_to_buf %p: free_slots %d write_ptr %d\n", rb, rb->free_slots, rb->write_ptr);
#endif
		return length;
	}

	return 0;
}

SR_32 read_buf(sr_ring_buffer *rb, SR_U8 *data, SR_32 size, SR_BOOL copy)
{
	SR_U8 *buf_ptr = ((SR_U8 *)rb + sizeof(sr_ring_buffer));
	SR_32 length = get_max_read_size(rb);

	if (length > size)
		length = size;
		
	if (rb->read_ptr + length < rb->buf_size) {
		if (copy)
			sal_memcpy(data, &buf_ptr[rb->read_ptr], length);
		rb->read_ptr += length;
	} else {
		SR_32 first_size = rb->buf_size - rb->read_ptr;
		SR_32 second_size = length - first_size;

		if (copy) {
			sal_memcpy(data, &buf_ptr[rb->read_ptr], first_size);
			sal_memcpy(&data[first_size], &buf_ptr[0], second_size);
		}
		rb->read_ptr = second_size;
	}

	rb->free_slots += length;
#ifdef SR_RB_DEBUG
	sal_printf("read_buf %p: free_slots %d read_ptr %d\n", rb, rb->free_slots, rb->read_ptr);
#endif

	return length;
}

SR_32 reset_buf(sr_ring_buffer *rb)
{
	rb->read_ptr = 0;
	rb->write_ptr = 0;
	rb->free_slots = 0;
	rb->buf_size = 0;

	return 0;
}

