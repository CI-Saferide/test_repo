#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"
#include "sr_log.h"

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

// FORMAT: Jan 18 11:07:53 host CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
// Severity is a string or integer and reflectsthe importance of the event. The valid string values are Unknown, Low, Medium, High, and Very-High. The valid integer values are 0-3=Low, 4-6=Medium, 7- 8=High, and 9-10=Very-High.
char severity_strings[SEVERITY_MAX][10] = { "Unknown", "Low", "Medium", "High", "Very-High" };

void CEF_log_event(const SR_U32 class, const char *event_name, const SR_U8 severity, const char *fmt, ...)
{
	int i;
	va_list args;
	SR_8 msg[SR_MAX_LOG];
	//printk("CEF:0|SafeRide|vSentry Mobile|1.0|%d|%s|%s|%s\n", cid, event_name, severity_strings[severity], extension);
	struct CEF_payload *payload = (struct CEF_payload*)sr_get_msg(MOD2LOG_BUF, sizeof(struct CEF_payload));
	
	if (payload) {	
		payload->class = class;		
		sal_strcpy(payload->name,(char*)event_name);
		payload->sev = severity;	
		va_start(args, fmt);
		i = vsnprintf(msg, SR_MAX_LOG-1, fmt, args);
		va_end(args);
		msg[SR_MAX_LOG - 1] = 0;
		sal_strcpy(payload->extension,msg);
		sr_send_msg(MOD2LOG_BUF, sizeof(payload));
	}else
		pr_err ("Failed to CEF log... %s\n", __func__);
	
}
