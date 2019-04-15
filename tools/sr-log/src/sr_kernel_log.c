#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"
#include "sal_linux_mng.h"
#include "sr_log.h"

//Severity is a string or integer and reflectsthe importance of the event.
//The valid string values are Unknown, Low, Medium, High, and Very-High. 
//The valid integer values are 0-3=Low, 4-6=Medium, 7- 8=High, and 9-10=Very-High.
SR_8 severity_strings[SEVERITY_MAX][10] = { "Unknown", "Low", "Medium", "High", "Very-High"};

void CEF_log_event(const SR_U32 class, const char *event_name,enum SR_CEF_SEVERITY severity, const char *fmt, ...)
{
	SR_U32 i;
	va_list args;
	SR_8 msg[SR_MAX_LOG];
	struct CEF_payload *payload = (struct CEF_payload*)sr_get_msg(MOD2LOG_BUF, sizeof(struct CEF_payload));
	
	
	va_start(args, fmt);
	i = vsnprintf(msg, SR_MAX_LOG-1, fmt, args);
	va_end(args);
	msg[SR_MAX_LOG - 1] = 0;

	if (payload) {
		payload->class = class;
		sal_strcpy(payload->name,(char*)event_name);
		payload->sev = severity;
		sal_strcpy(payload->extension,msg);
		sr_send_msg(MOD2LOG_BUF, sizeof(payload));
		sal_linux_mng_readbuf_up(SYNC_INFO_GATHER);
	}else{
		sal_kernel_print_err ("[vsentry]: %s|%s|%s\n",
			(char*)event_name,
			severity_strings[severity],
			msg );	
	}
	
}
