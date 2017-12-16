#include "sr_shmem.h"
#include "sr_ring_buf.h"
#include "sr_msg.h"
#include "sr_sal_common.h"

static sr_shmem sr_msg_buf_array[TOTAL_BUFS] = {
	{NULL, 0},
	{NULL, 0},
	{NULL, 0},
	{NULL, 0}
	};

SR_8 *buf_names[TOTAL_BUFS] = {
	"ENG2MOD",
	"MOD2ENG",
	"ENG2LOG",
	"MOD2LOG",
	"MOD2STAT",
};

static SR_32 buf_msg_sizes[TOTAL_BUFS] = {
	[MOD2ENG_BUF] = MOD2ENG_MSG_MAX_SIZE, 
	[MOD2STAT_BUF] = MOD2STAT_MSG_MAX_SIZE, 
};

SR_U32 sr_msg_get_buffer_msg_size(SR_U8 type)
{
	if (type >= TOTAL_BUFS)
		return 0;
	return buf_msg_sizes[type];
}

SR_32 sr_msg_alloc_buf(SR_U8 type, SR_32 length)
{
	SR_32 num_of_buffers;
	SR_32 each_buf_size;
	sr_shmem shmem;

	if (type > MAX_BUF_TYPE) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "allocation error", SEVERITY_HIGH,
			"sr_msg_alloc_buf: requested type %d is wrong\n", type);
		return SR_ERROR;
	}

	if (sr_msg_buf_array[type].buffer) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "allocation error", SEVERITY_HIGH,
			"sr_msg_alloc_buf: %s already allocated\n", buf_names[type]);
		return SR_ERROR;
	}

	if (sal_shmem_alloc(&shmem, length, type) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "allocation error", SEVERITY_HIGH,
			"sr_msg_alloc_buf: failed to allocate mem for %s len %d\n", buf_names[type], length);
		return SR_ERROR;
	}

	switch (type) {
		case ENG2MOD_BUF:
			each_buf_size = ENG2MOD_MSG_MAX_SIZE;
			break;
		case MOD2ENG_BUF:
			each_buf_size = MOD2ENG_MSG_MAX_SIZE;
			break;
		case ENG2LOG_BUF:
		case MOD2LOG_BUF:
			each_buf_size = LOG_MSG_MAX_SIZE;
			break;
		case MOD2STAT_BUF:
			each_buf_size = MOD2STAT_MSG_MAX_SIZE;
			break;
		default:
			CEF_log_event(SR_CEF_CID_SYSTEM, "allocation error", SEVERITY_HIGH,
				"sr_msg_alloc_buf: requested type %d is wrong\n", type);
			return SR_ERROR;
	}

	num_of_buffers = sr_ring_buf_calc_buffers(length, each_buf_size);

	CEF_log_event(SR_CEF_CID_SYSTEM, "allocation info", SEVERITY_HIGH,
		"sr_msg_alloc_buf: allocating %d buffers of size %d for %s",
		num_of_buffers, length, buf_names[type]);

	if (sr_init_ring_buf((sr_ring_buffer*)shmem.buffer, length, num_of_buffers, each_buf_size) == 0) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "allocation error", SEVERITY_HIGH,
			"sr_msg_alloc_buf: failed to init ring buffer for %s\n", buf_names[type]);
		return SR_ERROR;
	}

	sr_msg_buf_array[type].buffer_size = shmem.buffer_size;
	sr_msg_buf_array[type].buffer = shmem.buffer;
	
#ifdef SR_MSG_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "allocation info", SEVERITY_HIGH,
		"sr_msg_alloc_buf: buf %s initilized %p", buf_names[type], sr_msg_buf_array[type].buffer);
#endif

	return SR_SUCCESS;
}

SR_32 sr_msg_free_buf(SR_U8 type)
{
	if (type > MAX_BUF_TYPE) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "allocation freeing", SEVERITY_HIGH,
			"sr_msg_free_buf: requested type %d is wrong", type);
		return SR_ERROR;
	}

	if (sal_shmem_free(&sr_msg_buf_array[type]) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "allocation freeing", SEVERITY_HIGH,
			"sr_msg_alloc_buf: failed to free buf %s", buf_names[type]);
		return SR_ERROR;
	}
#ifdef SR_MSG_DEBUG
	CEF_log_debug(SR_CEF_CID_SYSTEM, "allocation freeing", SEVERITY_HIGH,
		"sr_msg_free_buf: buf %s is free", buf_names[type]);
#endif

	return SR_SUCCESS;

}

SR_8 *sr_read_msg(SR_U8 type, SR_32 *length)
{
	sr_ring_buffer *rb;

	if (type > MAX_BUF_TYPE) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "sr_read_msg", SEVERITY_HIGH,
			"sr_read_msg: requested type %d is wrong", type);
		return NULL;
	}

	rb = (sr_ring_buffer*)sr_msg_buf_array[type].buffer;
	if (!rb || !rb->buf_mem_offset) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "sr_read_msg", SEVERITY_HIGH,
			"sr_read_msg: error, %s buffer is NULL", buf_names[type]);
		return NULL;
	}

	return sr_read_buf(rb, length);
}

SR_32 sr_free_msg(SR_U8 type)
{
	sr_ring_buffer *rb;

	if (type > MAX_BUF_TYPE) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "sr_free_msg", SEVERITY_HIGH,
			"sr_free_msg: requested type %d is wrong", type);
		return SR_ERROR;
	}

	rb = (sr_ring_buffer*)sr_msg_buf_array[type].buffer;
	if (!rb || !rb->buf_mem_offset) {
#ifdef SR_MSG_DEBUG
		CEF_log_debug(SR_CEF_CID_SYSTEM, "sr_free_msg", SEVERITY_HIGH,
			"sr_free_msg: error, buffer is NULL");
#endif
		return SR_ERROR;
	}

	sr_free_buf(rb);

	return SR_SUCCESS;
}

SR_8 *sr_get_msg(SR_U8 type, SR_32 size)
{
	sr_ring_buffer *rb;

	if (type > MAX_BUF_TYPE) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "sr_get_msg", SEVERITY_HIGH,
			"sr_get_msg: requested type %d is wrong", type);
		return NULL;
	}

	rb = (sr_ring_buffer*)sr_msg_buf_array[type].buffer;
	if (!rb || !rb->buf_mem_offset) {
#ifdef SR_MSG_DEBUG
		CEF_log_debug(SR_CEF_CID_SYSTEM, "sr_get_msg", SEVERITY_HIGH,
			"sr_get_msg: error, buffer is NULL");
#endif
		return NULL;
	}

	return sr_get_buf(rb, size);
}

SR_32 sr_send_msg(SR_U8 type, SR_32 length)
{
	sr_ring_buffer *rb;

	if (type > MAX_BUF_TYPE) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "sr_send_msg", SEVERITY_HIGH,
			"sr_send_msg: requested type %d is wrong", type);
		return SR_ERROR;
	}

	rb = (sr_ring_buffer*)sr_msg_buf_array[type].buffer;
	if (!rb || !rb->buf_mem_offset) {
#ifdef SR_MSG_DEBUG
		CEF_log_debug(SR_CEF_CID_SYSTEM, "sr_send_msg", SEVERITY_HIGH,
			"sr_send_msg: error, buffer is NULL");
#endif
		return SR_ERROR;
	}

	return sr_write_buf(rb, length);
}

sr_shmem* sr_msg_get_buf(SR_U8 type)
{
	if (type > MAX_BUF_TYPE) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "sr_msg_get_buf", SEVERITY_HIGH,
			"sr_msg_free_buf: requested type %d is wrong", type);
		return 0;
	}

	return &sr_msg_buf_array[type];
}

void sr_msg_print_stat(void)
{
	sr_ring_buffer *rb;
	SR_U8 type;

	for (type = ENG2MOD_BUF; type < TOTAL_BUFS; type ++) {
		rb = (sr_ring_buffer*)sr_msg_buf_array[type].buffer;
		if (!rb || !rb->buf_mem_offset)
			continue;
				CEF_log_event(SR_CEF_CID_SYSTEM, "printing stats", SEVERITY_HIGH,
					"%s statistics:", buf_names[type]);
		sr_print_rb_info(rb);
	}
}

