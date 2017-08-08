#include "sal_module.h"
#include "sr_event_collector.h"
#include "sr_msg.h"

SR_U8 *sr_ec_buffer;
SR_U32 sr_ec_offset; // offset to buffer;
SR_U32 last_send_sec;
SR_U32 last_send_nsec;

static inline SR_32 sr_ec_allocate_buffer(void)
{
	sr_ec_buffer = sr_get_msg(MOD2ENG_BUF, MOD2ENG_MSG_MAX_SIZE); // allocate buffer of 2K size
	if (!sr_ec_buffer) {
		// As long as the engine isn't initialized this will not be available, don't spam the log
		//sal_kernel_print_alert("sr_ec_allocate_buffer: Failed to allocate buffer\n");
		return SR_ERROR;
	}
	memset(sr_ec_buffer, 0, MOD2ENG_MSG_MAX_SIZE);
	sr_ec_offset = 0;
	last_send_sec = sal_get_curr_time();
	last_send_nsec = sal_get_curr_time_nsec();

	return SR_SUCCESS;
}
static inline SR_BOOL sr_ec_sample_period_exceeded(void)
{ // TODO: this could be optimized with OS-specific code (e.g. jiffies...)
	SR_U32 now_sec, now_nsec;
	now_sec = sal_get_curr_time();
	now_nsec = sal_get_curr_time_nsec();
	return ((1000000000*(now_sec-last_send_sec) + ((int)(now_nsec - last_send_nsec))) >= SR_EC_SAMPLE_PERIOD);
}

SR_32 sr_event_collector_init(void)
{
	return sr_ec_allocate_buffer(); // Buffer will only be available once engine initializes
}

void sr_event_collector_uninit(void)
{
	// TODO: free existing buffer
}

int sr_ec_send_event(SR_U8 event_type, void *data)
{
	switch (event_type) {
		case SR_EC_NEW_CONNECTION:
			// collect
			sr_ec_append_event(event_type, data, sizeof(struct sr_ec_new_connection_t));
			break;
		default:
			break;
	}

	return SR_SUCCESS;
	
}

void sr_ec_append_event(SR_U8 event_type, void *sample_data, SR_U32 data_length) 
{
	if ( (!sr_ec_buffer) && (sr_ec_allocate_buffer() == SR_ERROR)) {
		return;
	}
	if ( (sr_ec_offset+data_length > MOD2ENG_MSG_MAX_SIZE) || // buffer full
			(sr_ec_sample_period_exceeded()) ) { // time based constraint
		// send old buffer and allocate a new one
		sr_send_msg(MOD2ENG_BUF, sr_ec_offset);
		if (sr_ec_allocate_buffer() != SR_SUCCESS) {
			return;
		}
	}
	
	sr_ec_buffer[sr_ec_offset++] = event_type;
	memcpy(&sr_ec_buffer[sr_ec_offset], sample_data, data_length);
	sr_ec_offset += data_length;
}

