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

void log_print_cef_msg(CEF_payload *cef)
{

	sal_printf("CEF: cef_version %d, vendor %s, product %s, ver %d, ",
		cef->cef_version, cef->dev_vendor, cef->dev_product, cef->dev_version);
	switch (cef->class) {
	case NETWORK:
		sal_printf("class network, ");
		break;
    case FS:
		sal_printf("class fs, ");
		break;
    case PROC:
		sal_printf("class proc, ");
		break;
	default:
		sal_printf("class N/A, ");
		break;
	}
	sal_printf("name %s,\n", cef->name);
	sal_printf("extension : %s\n", cef->extension);
}

SR_32 sr_log_init (const SR_8* app_name, SR_32 flags)
{
	sal_strcpy(g_app_name, (SR_8*)app_name);

	sal_printf("Starting LOG module!\n");
	
	return SR_SUCCESS;
}

