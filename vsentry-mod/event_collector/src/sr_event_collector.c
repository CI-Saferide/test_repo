#include "sal_module.h"
#include "sr_event_collector.h"
#include "sr_msg.h"

SR_U8 *sr_ec_buffer[TOTAL_BUFS];
SR_U32 sr_ec_offset[TOTAL_BUFS]; // offset to buffer;
SR_U32 last_send_sec[TOTAL_BUFS];
SR_U32 last_send_nsec[TOTAL_BUFS];
static SR_SLEEPLES_LOCK_T sr_ec_locks[TOTAL_BUFS];

static SR_BOOL collect = SR_FALSE;

static inline SR_32 sr_ec_allocate_buffer(SR_U8 type)
{
	SR_U32 size;

	if (!(size = sr_msg_get_buffer_msg_size(type))) {
		return SR_ERROR;
	}
	sr_ec_buffer[type] = sr_get_msg(type, size); // allocate buffer of 2K size
	if (!sr_ec_buffer[type]) {
		// As long as the engine isn't initialized this will not be available, don't spam the log
		//sal_kernel_print_alert("sr_ec_allocate_buffer: Failed to allocate buffer\n");
		return SR_ERROR;
	}
	memset(sr_ec_buffer[type], 0, size);
	sr_ec_offset[type] = 0;
	last_send_sec[type] = sal_get_curr_time();
	last_send_nsec[type] = sal_get_curr_time_nsec();

	return SR_SUCCESS;
}
static inline SR_BOOL sr_ec_sample_period_exceeded(SR_U8 type, SR_U32 now_sec, SR_U32 now_nsec)
{ // TODO: this could be optimized with OS-specific code (e.g. jiffies...)
	return ((1000000000*(now_sec-last_send_sec[type]) + ((int)(now_nsec - last_send_nsec[type]))) >= SR_EC_SAMPLE_PERIOD);
}

SR_32 sr_event_collector_init(void)
{
	SR_32 rc, i;

	for (i = 0;  i < TOTAL_BUFS; i++)
		SR_SLEEPLES_LOCK_INIT(&sr_ec_locks[i]);
	// Buffer will only be available once engine initializes
	if ((rc = sr_ec_allocate_buffer(MOD2ENG_BUF)) != SR_SUCCESS)
		return rc;
	return sr_ec_allocate_buffer(MOD2STAT_BUF);
}

void sr_event_collector_uninit(void)
{
	// TODO: free existing buffer
}

int sr_ec_send_event(SR_U8 buf_type, SR_U8 event_type, void *data)
{
	//struct sr_ec_new_connection_t *pNewConnection = (struct sr_ec_new_connection_t *)data;

	switch (buf_type) {
		case  MOD2ENG_BUF:
			switch (event_type) {
				case SR_EVENT_NEW_CONNECTION:
					// collect
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_new_connection_t), SR_TRUE);
					break;
				case SR_EVENT_FILE_CREATED:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_file_t), SR_TRUE);
					break;
#ifdef CONFIG_STAT_ANALYSIS
				case SR_EVENT_PROCESS_DIED:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_process_died_t), SR_TRUE);
					break;
#endif
				default:
					break;
			}
			break;
#ifdef CONFIG_STAT_ANALYSIS
		case MOD2STAT_BUF:
			switch (event_type) {
				case SR_EVENT_STATS_CONNECTION:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_connection_stat_t), SR_FALSE);
					break;
				case SR_EVENT_STATS_CONNECTION_TRANSMIT:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_connection_transmit_t), SR_FALSE);
				case SR_EVENT_STATS_FILE_OPEN:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_file_open_t), SR_FALSE);
					break;
				case SR_EVENT_CANBUS:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_can_t), SR_FALSE);
					break;
				default:
					break;
			}
			break;
#endif
		default:
			break;
	}

	return SR_SUCCESS;
}

void sr_ec_append_event(SR_U8 buf_type, SR_U8 event_type, void *sample_data, SR_U32 data_length, SR_BOOL is_lock) 
{
	SR_U32 size, now_sec, now_nsec;
	SR_SLEEPLES_LOCK_FLAGS flags;

	if (!(size = sr_msg_get_buffer_msg_size(buf_type)))
		return;
	now_sec = sal_get_curr_time();
	now_nsec = sal_get_curr_time_nsec();

	if (is_lock) {
        	SR_SLEEPLES_LOCK(&sr_ec_locks[buf_type], flags);
	}

	if ( (!sr_ec_buffer[buf_type]) && (sr_ec_allocate_buffer(buf_type) == SR_ERROR)) {
		goto out;
	}
	if ( sr_ec_offset[buf_type] && ((sr_ec_offset[buf_type]+data_length+1 > size) || // buffer full
			(sr_ec_sample_period_exceeded(buf_type, now_sec, now_nsec))) ) { // time based constraint
		// send old buffer and allocate a new one
		sr_send_msg(buf_type, sr_ec_offset[buf_type]);
		if (sr_ec_allocate_buffer(buf_type) != SR_SUCCESS) {
			goto out;
		}
	}
	
	sr_ec_buffer[buf_type][sr_ec_offset[buf_type]++] = event_type;
	memcpy(&sr_ec_buffer[buf_type][sr_ec_offset[buf_type]], sample_data, data_length);
	sr_ec_offset[buf_type] += data_length;

out:
	if (is_lock)
        	SR_SLEEPLES_UNLOCK(&sr_ec_locks[buf_type], flags);
	return;
}

SR_32 sr_collector_handle_message(sr_ec_mode_t ec_mode)
{
	/*
	if (msg->msg_id == CAN_ML_START_PROTECT) {
		// this is an indication for start the protection 
		collect = SR_TRUE;
		CEF_log_event(SR_CEF_CID_ML_CAN, "info", SEVERITY_LOW,
			"%s=can_ml protection started",MESSAGE);
	} else if (msg->msg_id == CAN_ML_STOP_PROTECT) {
		// this is an indication for protection stop 
		if (protect == SR_TRUE) {
			CEF_log_event(SR_CEF_CID_ML_CAN, "info", SEVERITY_LOW,
				"%s=can_ml protection stopped",MESSAGE);
		}
		collect = SR_FALSE;
		sr_ml_can_hash_delete_all();
	}
	*/
	return SR_SUCCESS;
}

SR_BOOL get_collector_state(void)
{
	return (collect);
}

