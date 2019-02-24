#include "sr_log.h"
#include "sr_types.h"
#include "irdeto_unix_interface.h"
#include "sr_tasks.h"

static SR_BOOL is_run;
static SR_8 g_buffer_tail[MAX_PAYLOAD];
#define IRDETO_CEF_LOG_DELIMITTER			"|-|"
#define IRDETO_CEF_LOG_DELIMETTER_LEN		3		/* strlen of IRDETO_CEF_LOG_DELIMITTER */

static void handle_buffer (SR_8* buffer)
{
	SR_8*	pos;
	SR_U16	buffer_len;
	SR_8	fixed_buf[MAX_PAYLOAD];
	SR_8	tail[MAX_PAYLOAD];
	do {
		pos = strstr(buffer, IRDETO_CEF_LOG_DELIMITTER);
		buffer_len = strlen(buffer);
		if (pos) {
			memset(fixed_buf, 0, MAX_PAYLOAD);
			memcpy(fixed_buf, buffer, pos-buffer);
			memcpy(tail, pos+IRDETO_CEF_LOG_DELIMETTER_LEN, buffer_len-(pos-buffer));
			memset(buffer,0, buffer_len);
			memcpy(buffer, tail, strlen(tail));
			fixed_buf[strlen(fixed_buf)]='\n';
			handle_log_options(fixed_buf, SEVERITY_MEDIUM); /* TODO: find the actual severity from the string */
		} else {
			memcpy(g_buffer_tail, buffer, strlen(buffer));	/* save buffer tail for next iterration */
		}
	} while (pos);
}

static SR_32 handle_data(char *buf, SR_32 fd)
{
	SR_8	concatinate_buffer[2*MAX_PAYLOAD];
	
	memcpy(concatinate_buffer, g_buffer_tail, strlen(g_buffer_tail));
	memcpy(concatinate_buffer+strlen(g_buffer_tail), buf, strlen(buf));
	memset(g_buffer_tail, 0, MAX_PAYLOAD);
	handle_buffer(concatinate_buffer);
	
	return SR_SUCCESS;
}

static SR_BOOL is_run_cb(void)
{
	return is_run;
}

static SR_32 irdeto_unix_interface_server(void *data)
{
	SR_32 rc;

	rc = sal_linux_local_interface(IRDETO_UNIX_INTERFACE_FILE, handle_data, is_run_cb);
	if (rc != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to load irdeto interface server",REASON);
	}

	return SR_SUCCESS;
}

SR_32 irdeto_unix_interface_init(void)
{
	SR_32 ret;
	memset(g_buffer_tail, 0, MAX_PAYLOAD);
	is_run = SR_TRUE;
	ret = sr_start_task(SR_IRDETO_SOCKET, irdeto_unix_interface_server);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed to start irdeto unix socket",REASON);
		return SR_ERROR;	
	}

	return SR_SUCCESS;
}

void irdeto_unix_interface_uninit(void)
{
	is_run = SR_FALSE;
	sr_stop_task(SR_IRDETO_SOCKET);
}
