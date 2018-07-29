#include "sal_module.h"
#include "sr_event_collector.h"
#include "sr_msg.h"
#include "sal_linux_mng.h"

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
				case SR_EVENT_STATS_CONNECTION_WL:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_connection_stat_wl_t), SR_FALSE);
					break;
				case SR_EVENT_STATS_CONNECTION_TRANSMIT:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_connection_transmit_t), SR_FALSE);
					sal_linux_mng_readbuf_up(SYNC_INFO_GATHER);									
					break;
				case SR_EVENT_STATS_FILE_WL:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_file_wl_t), SR_FALSE);
					break;
				case SR_EVENT_STATS_CANBUS:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_can_t), SR_FALSE);
					break;
				case SR_EVENT_STATS_NEW_CONNECTION_WL:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_new_connection_wl_t), SR_FALSE);
					break;
#ifdef CONFIG_SYSTEM_POLICER
				case SR_EVENT_STATS_SYSTEM:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_system_stat_t), SR_FALSE);
					break;
				case SR_EVENT_STATS_SYSTEM_FINISH:
					sr_ec_append_event(buf_type, event_type, data, sizeof(struct sr_ec_system_finish_t), SR_FALSE);
					break;
#endif
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

static SR_32 sr_ec_send_msg_notification(SR_U8 buf_type, SR_U8 event_type)
{
	switch (buf_type) {
		case MOD2ENG_BUF: 
			switch (event_type) {
				case SR_EVENT_STATS_NEW_CONNECTION_WL:
				case SR_EVENT_FILE_CREATED:
				case SR_EVENT_PROCESS_DIED:
					sal_linux_mng_readbuf_up(SYNC_ENGINE);					
					break;
				default:
					break;
			}
		case MOD2STAT_BUF: 
			switch (event_type) {
				case SR_EVENT_STATS_CONNECTION_TRANSMIT:
					sal_linux_mng_readbuf_up(SYNC_INFO_GATHER);					
					break;
				default:
					break;
			}
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
		sr_ec_send_msg_notification(buf_type, event_type);
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

SR_32 sr_collector_handle_message(struct sr_ec_msg *msg)
{
	collect = SR_FALSE;
	
	if (msg->ec_mode  == SR_EC_MODE_ON) {
		collect = SR_TRUE;
	} else if (msg->ec_mode == SR_EC_MODE_OFF) {
		collect = SR_FALSE;
	}
	
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=collection %s",MESSAGE,
		msg->ec_mode == SR_EC_MODE_ON?"EC_MODE_ON":"EC_MODE_OFF");
			
	return SR_SUCCESS;
}

SR_BOOL get_collector_state(void)
{
	return (collect);
}

