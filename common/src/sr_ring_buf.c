#include "sr_ring_buf.h"
#include "sr_sal_common.h"
#include "sr_log.h"

SR_32 sr_ring_buf_calc_buffers(SR_32 mem_size, SR_32 each_buf_size)
{
	SR_32 buffers;

	buffers = (mem_size - sizeof(sr_ring_buffer)) / (each_buf_size + sizeof(sr_buffer));

	return buffers;
}

SR_32 sr_ring_buf_calc_mem(SR_32 num_of_buffers, SR_32 each_buf_size)
{
	SR_32 total_mem_needed;

	total_mem_needed = sizeof(sr_ring_buffer);
	total_mem_needed += sizeof(sr_buffer) * num_of_buffers;
	total_mem_needed += num_of_buffers * each_buf_size;

	return total_mem_needed;
}

SR_32 sr_init_ring_buf(sr_ring_buffer *rb, SR_32 mem_size, SR_32 num_of_buffers, SR_32 each_buf_size)
{
	SR_32 total_mem_needed;
	SR_U32 i;
	sr_buffer *buf_ptr;

	total_mem_needed = sr_ring_buf_calc_mem(num_of_buffers, each_buf_size);
	if (total_mem_needed > mem_size) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "ring buffer init", SEVERITY_LOW,
			"sr_init_ring_buf: required mem [%d] is bigger than allocated [%d]\n",
			total_mem_needed, mem_size);
		return 0;
	}

	memset(rb, 0, sizeof(sr_buffer));
	rb->each_buf_size = each_buf_size;
	rb->num_of_bufs = num_of_buffers;
	rb->buf_mem_offset = sizeof(sr_ring_buffer) + (sizeof(sr_buffer) * num_of_buffers);

	buf_ptr = (sr_buffer *)((SR_U8*)rb + sizeof(sr_ring_buffer));
	for (i=0; i<num_of_buffers; i++) {
		buf_ptr->offset = (i * each_buf_size);
		buf_ptr++;
	}

#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_init_ring_buf: used memory size %d\n", total_mem_needed);
	sr_print_rb_info(rb);
#endif

	return total_mem_needed;
}

SR_8 *sr_get_buf(sr_ring_buffer *rb, SR_32 size)
{
	sr_buffer *buf_ptr = (sr_buffer *)((SR_U8*)rb + sizeof(sr_ring_buffer));
	SR_8 *ptr = NULL;
	SR_32 read_ptr = rb->read_ptr;

	if (size > rb->each_buf_size) {
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_get_buf: requested size [%d] bigger than buffer size [%d]\n",
			size, rb->each_buf_size);
#endif
		return ptr;
	}

	if ( ((rb->free_ptr + 1) % rb->num_of_bufs) == read_ptr) {
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_get_buf: no free buffers free_ptr %d read_ptr %d\n", rb->free_ptr, read_ptr);
#endif
		return ptr;
	}

	buf_ptr = &buf_ptr[rb->free_ptr];
	ptr = (SR_8*)rb + rb->buf_mem_offset + buf_ptr->offset;

	rb->free_ptr = (rb->free_ptr + 1) % rb->num_of_bufs;
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_get_buf: new free_ptr %d\n", rb->free_ptr);
#endif
	return ptr;
}

SR_32 sr_write_buf(sr_ring_buffer *rb, SR_32 size)
{
	sr_buffer *buf_ptr = (sr_buffer *)((SR_U8*)rb + sizeof(sr_ring_buffer));
	SR_32 free_ptr = rb->free_ptr;

	if (size > rb->each_buf_size) {
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_wite_buf: requested size [%d] bigger than buffer size [%d]\n",
			size, rb->each_buf_size);
#endif
		return SR_ERROR;
	}

	if (free_ptr == rb->write_ptr) {
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_write_buf: no buffer was allocated, free_ptr %d write_ptr %d\n", free_ptr, rb->write_ptr);
#endif
		return 0;
	}

#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"Writing to buf @offset %d size %d\n", rb->write_ptr, size);
#endif
	buf_ptr = &buf_ptr[rb->write_ptr];
	buf_ptr->content_size = size;
	rb->total_write_bytes += size;
	rb->total_write_bufs++;

	rb->write_ptr = (rb->write_ptr + 1) % rb->num_of_bufs;
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_write_buf: new write_ptr %d\n", rb->write_ptr);
#endif
	return size;
}

SR_8 *sr_read_buf(sr_ring_buffer *rb, SR_32 *size)
{
	sr_buffer *buf_ptr = (sr_buffer *)((SR_U8*)rb + sizeof(sr_ring_buffer));
	SR_8 *ptr = NULL;
	SR_32 write_ptr = rb->write_ptr;

	if (rb->read_ptr == write_ptr) {
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_read_buf: no readable buffers. read_ptr %d write_ptr %d\n", rb->read_ptr, write_ptr);
#endif
		*size = 0;
		return NULL;
	}

	buf_ptr += rb->read_ptr;

#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_read_buf: buf at offset %d size %d\n",
		rb->read_ptr, buf_ptr->content_size);
#endif
	*size = buf_ptr->content_size;
	rb->total_read_bytes += buf_ptr->content_size;
	rb->total_read_bufs++;

	ptr = (SR_8*)rb + rb->buf_mem_offset + buf_ptr->offset;

	return ptr;
}

void sr_free_buf(sr_ring_buffer *rb)
{
	SR_32 write_ptr = rb->write_ptr;

	if ( (write_ptr == rb->read_ptr) ) {
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_free_buf: no used buffers\n");
#endif
		return;
	}

	rb->read_ptr = (rb->read_ptr + 1) % rb->num_of_bufs;
#ifdef SR_RB_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "debug", SEVERITY_LOW,
		"sr_free_buf: new read_ptr %d\n", rb->read_ptr);
#endif
}

void sr_print_rb_info(sr_ring_buffer *rb)
{
	/*SR_32 i;
	sr_buffer *buf_ptr = (sr_buffer *)((SR_U8*)rb + sizeof(sr_ring_buffer));*/

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"read_ptr            = %08x\n", rb->read_ptr);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"write_ptr           = %08x\n", rb->write_ptr);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"free_ptr            = %08x\n", rb->free_ptr);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"each_buf_size       = %08x\n", rb->each_buf_size);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"num_of_bufs         = %08x\n", rb->num_of_bufs);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"buf_mem_offset      = %08x\n", rb->buf_mem_offset);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"total_read_bytes    = %08x\n", rb->total_read_bytes);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"total_read_bufs     = %08x\n", rb->total_read_bufs);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"total_write_bytes   = %08x\n", rb->total_write_bytes);
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
			"total_write_bufs    = %08x\n", rb->total_write_bufs);

	/*for (i=0; i<rb->num_of_bufs; i++) {
		sal_printf("buf_ptr[%08X] %p offset %08x content_size %08x\n", i, buf_ptr, buf_ptr->offset, buf_ptr->content_size);
		buf_ptr++;
	}*/
}

