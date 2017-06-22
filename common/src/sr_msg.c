#include "sr_shmem.h"
#include "sr_ring_buf.h"
#include "sr_msg.h"
#include "sr_sal_common.h"

static sr_shmem sr_msg_buf_array[TOTAL_BUFS];

SR_8 *buf_names[TOTAL_BUFS] = {
	"ENG2MOD",
	"MOD2ENG",
	"LOG_BUF"
};

SR_32 sr_msg_alloc_buf(SR_U8 type, SR_32 length)
{
	if (type > MAX_BUF_TYPE) {
		sal_printf("sr_msg_alloc_buf: requested type %d is wrong\n", type);
		return SR_ERROR;
	}

	if (sr_msg_buf_array[type].buffer) {
		sal_printf("sr_msg_alloc_buf: %s already allocated\n", buf_names[type]);
		return SR_ERROR;
	}

	if (sal_shmem_alloc(&sr_msg_buf_array[type], length, type) != SR_SUCCESS) {
		sal_printf("sr_msg_alloc_buf: failed to allocate mem for %s len %d\n", buf_names[type], length);
		return SR_ERROR;
	}

	init_buf(length, (sr_ring_buffer*)sr_msg_buf_array[type].buffer);

#ifdef SR_MSG_DEBUG
	sal_printf("sr_msg_alloc_buf: buf %s initilized %p\n", buf_names[type], sr_msg_buf_array[type].buffer);
#endif

	return SR_SUCCESS;
}

SR_32 sr_msg_free_buf(SR_U8 type)
{
	if (type > MAX_BUF_TYPE) {
		sal_printf("sr_msg_free_buf: requested type %d is wrong\n", type);
		return SR_ERROR;
	}

	if (sal_shmem_free(&sr_msg_buf_array[type]) != SR_SUCCESS) {
		sal_printf("sr_msg_alloc_buf: failed to free buf %s\n", buf_names[type]);
		return SR_ERROR;
	}
#ifdef SR_MSG_DEBUG
	sal_printf("sr_msg_free_buf: buf %s is free\n", buf_names[type]);
#endif

	return SR_SUCCESS;

}

SR_32 sr_read_msg(SR_U8 type, SR_U8 *data, SR_U32 length, SR_BOOL copy)
{
	sr_ring_buffer *rb;

	if (type > MAX_BUF_TYPE) {
		sal_printf("sr_read_msg: requested type %d is wrong\n", type);
		return SR_ERROR;
	}

	rb = (sr_ring_buffer*)sr_msg_buf_array[type].buffer;
	if (!rb) {
		sal_printf("sr_read_msg: error, %s buffer is NULL\n", buf_names[type]);
		return SR_ERROR;
	}

	if (get_max_read_size(rb) > 0) {
#ifdef SR_MSG_DEBUG
		sal_printf("sr_read_msg: read from %s buf %p\n", buf_names[type], rb); 
#endif
		return read_buf(rb, data, length, copy);
	}

	return 0;
}

SR_32 sr_send_msg(SR_U8 type, SR_U8 *data, SR_U32 length)
{
	sr_ring_buffer *rb;

	if (type > MAX_BUF_TYPE) {
		sal_printf("sr_send_msg: requested type %d is wrong\n", type);
		return SR_ERROR;
	}

	rb = (sr_ring_buffer*)sr_msg_buf_array[type].buffer;
	if (!rb) {
#ifdef SR_MSG_DEBUG
		sal_printf("sr_send_msg: error, buffer is NULL\n");
#endif
		return SR_ERROR;
	}

	if (get_max_write_size(rb) < length) {
		sal_printf("sr_send_msg: error, no room in %s\n", buf_names[type]);
		return 0;
	}

	return write_to_buf(rb, data, length);
}

sr_shmem* sr_msg_get_buf(SR_U8 type)
{
	if (type > MAX_BUF_TYPE) {
		sal_printf("sr_msg_free_buf: requested type %d is wrong\n", type);
		return 0;
	}

	return &sr_msg_buf_array[type];
}

