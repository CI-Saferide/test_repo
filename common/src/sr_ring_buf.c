#include "sr_ring_buf.h"
#include "sr_sal_common.h"

SR_32 init_buf(SR_32 size, sr_ring_buffer *rb)
{
	rb->buf_size = (size - sizeof(sr_ring_buffer));
	rb->read_ptr = 0;
	rb->write_ptr = 0;

#ifdef SR_RB_DEBUG
	sal_printf(" init buf: size %d\n", rb->buf_size);
#endif

	return 0;
}

SR_32 get_max_read_size(sr_ring_buffer *rb)
{
	SR_32 length = rb->write_ptr - rb->read_ptr;

	if (length == 0 )
		return 0;

	if (length < 0)
		length += rb->buf_size;

	return length;
}

SR_32 get_max_write_size(sr_ring_buffer *rb)
{
	SR_32 length = rb->read_ptr - rb->write_ptr;

	if (length <= 0)
		length += rb->buf_size;

	return length;
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
#ifdef SR_RB_DEBUG
		sal_printf("write_to_buf %p: write_ptr %d read_ptr %d\n", rb, rb->write_ptr, rb->read_ptr);
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

#ifdef SR_RB_DEBUG
	sal_printf("read_buf %p: read_ptr %d write_ptr %d\n", rb, rb->read_ptr, rb->write_ptr);
#endif

	return length;
}

SR_32 reset_buf(sr_ring_buffer *rb)
{
	rb->read_ptr = 0;
	rb->write_ptr = 0;
	rb->buf_size = 0;

	return 0;
}

