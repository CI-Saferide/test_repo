#include "sr_log.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"

#if 0
const static SR_8	*log_level_str[8] = {
	"EMERGENCY", /* LOG_EMERG   = system is unusable		       */
	"ALERT",	 /* LOG_ALERT   = action must be taken immediately */
	"CRITICAL",  /* LOG_CRIT	= critical conditions	          */
	"ERROR",	 /* LOG_ERR	 = error conditions                 */
	"WARNING",   /* LOG_WARNING = warning conditions		       */
	"NOTICE",	/* LOG_NOTICE  = normal but significant condition */
	"INFO",	  /* LOG_INFO	= informational                    */
	"DEBUG",	 /* LOG_DEBUG   = debug-level messages	         */
};
#endif

static SR_8 g_app_name[20];

/*static SR_8* file_basename(const SR_8* file)
{
	SR_8* pattern;
	SR_8* tmp = (SR_8*)file;

	pattern = strstr(tmp, "/");
	while (NULL != pattern) {
		pattern+=1;
		tmp = pattern;
		pattern = strstr(pattern, "/");
	}
	return (tmp);
}*/

SR_32 engine_log_loop(void *data)
{
	sr_ring_buffer *rb;
	sr_shmem *vsshmem;
	SR_32 ret;
	CEF_payload *cef;
	SR_U8 *buf;
	SR_32 length = (sizeof(CEF_payload) * 64);

	sal_printf("engine_log_loop started\n");

	ret = sr_msg_alloc_buf(LOG_BUF, length);
	if (ret != SR_SUCCESS){
		sal_printf("failed to init log buf\n");
		return 0;
	}

	vsshmem = sr_msg_get_buf(LOG_BUF);
	if (!vsshmem) {
		sal_printf("failed to init vsshmem\n");
		return 0;
	}

	rb = vsshmem->buffer;
	if (!rb) {
		sal_printf("something is wrong !!!! shouldn't happened\n");
		return 0;
	}

	while (!sr_task_should_stop(SR_LOG_TASK)) {
		if ((ret = get_max_read_size(rb)) > sizeof(CEF_payload)) {
			buf = ((SR_U8*)rb + sizeof(sr_ring_buffer));
			cef = (CEF_payload*)&buf[rb->read_ptr];
			sal_printf("LOG msg: %s\n", cef->extension);
			read_buf(rb, (SR_U8*)cef, sizeof(CEF_payload), SR_FALSE);
		}
	}

	/* free allocated buffer */
	sr_msg_free_buf(LOG_BUF);

	sal_printf("engine_log_loop end\n");

	return 0;
}


SR_32 sr_log_init (const SR_8* app_name, SR_32 flags)
{
	sal_strcpy(g_app_name, (SR_8*)app_name);

	sal_printf("Starting LOG module!\n");
	
	if (sr_start_task(SR_LOG_TASK, engine_log_loop) != SR_SUCCESS) {
		sal_printf("failed to start engine_log_loop\n");
		return SR_ERROR;
	}
	
	return SR_SUCCESS;
}

#if 0
SR_32 __sr_print (enum SR_LOG_PRIORITY priority, SR_32 line, const SR_8 *file, const SR_8 *fmt, ...)
{
	SR_8	 msg[SR_MAX_PATH];
	SR_8	 output_msg[SR_MAX_PATH];
	va_list  args;
	time_t t = time(NULL);
	struct tm tm = *localtime(&t);

	/* create msg */
	va_start(args, fmt);
	vsnprintf(msg, SR_MAX_PATH-1, fmt, args);
	va_end(args);
	msg[SR_MAX_PATH - 1] = 0;
	/* create final message */
	snprintf(output_msg, SR_MAX_PATH-1, "%d-%d-%d %d:%d:%d %s %s[%d] %s\n",
			tm.tm_mday, tm.tm_mon + 1,tm.tm_year + 1900, 
			tm.tm_hour, tm.tm_min, tm.tm_sec,
			g_app_name,file_basename(file), line, msg);

	output_msg[SR_MAX_PATH - 1] = 0;
	fprintf (stderr, "[%s] %s", log_level_str[priority], output_msg);
}
#endif

