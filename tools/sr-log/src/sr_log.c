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

// FORMAT: Jan 18 11:07:53 host CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
// Severity is a string or integer and reflectsthe importance of the event. The valid string values are Unknown, Low, Medium, High, and Very-High. The valid integer values are 0-3=Low, 4-6=Medium, 7- 8=High, and 9-10=Very-High.
char severity_strings[SEVERITY_MAX][10] = { "Unknown", "Low", "Medium", "High", "Very-High" };

static SR_8 g_app_name[20];

typedef const char* cef_str;
FILE* log_fp = 0;
const int max_log_size = 1024*1024*2;
const int max_no = 4;
cef_str cef_prefix = "cef_";
cef_str cef_postfix = ".log";

void log_cef_msg(cef_str str)
{
    char file1[64], file2[64];
	int i;

    if(!log_fp){
		
		sprintf(file1,"%s%d%s", cef_prefix, 0, cef_postfix);
		log_fp = fopen(file1,"a");
    }

    if(log_fp){
		if( ftell(log_fp) > max_log_size){
			fclose(log_fp);
            log_fp = 0;

            for(i = (max_no-1);i >= 0;i--){
				sprintf(file1,"%s%d%s",cef_prefix, i,cef_postfix );
				sprintf(file2,"%s%d%s",cef_prefix, i+1,cef_postfix );
				rename(file1, file2);
			}

            sprintf(file1,"%s%d%s",cef_prefix,0,cef_postfix);
            log_fp = fopen(file1, "a");
        }

        fputs(str,log_fp);
        fflush(log_fp);
    }
}

void log_print_cef_msg(CEF_payload *cef)
{	
	char cef_buffer[1024];
	char cef_class[32];
	time_t timer;
    char buffer[26];
    struct tm* tm_info;
    
    time(&timer);
    tm_info = localtime(&timer);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);


	//CEF:0|SafeRide|vSentry Mobile|1.0|%d|%s|%s|%s
	//printf("%s CEF: cef_version %d, vendor %s, product %s, ver %d, ",buffer,cef->cef_version, cef->dev_vendor, cef->dev_product, cef->dev_version);
		
	switch (cef->class) {
	case SR_CEF_CID_FILE:
		sal_strcpy(cef_class,"File");
		break;
    case SR_CEF_CID_NETWORK:
		sal_strcpy(cef_class,"Network");
		break;
    case SR_CEF_CID_CAN:
		sal_strcpy(cef_class,"CAN");
		break;
	case SR_CEF_CID_SYSTEM:
		sal_strcpy(cef_class,"System");
		break;
	default:
		sal_strcpy(cef_class,"Class N/A, ");	
		break;
	}
	
	sprintf(cef_buffer,"%s CEF: %d| vendor %s|product %s|ver %d|%s|%s|%s\n",
			buffer,cef->cef_version, cef->dev_vendor, cef->dev_product, cef->dev_version,cef_class,cef->name, cef->extension);
		
	log_cef_msg(cef_buffer);
}


void CEF_log_event(const SR_U32 class, const char *event_name, const SR_U8 severity, const char *fmt, ...)
{
	int i = 0;
	va_list args;
	SR_8 msg[SR_MAX_LOG];
	//printk("CEF:0|SafeRide|vSentry Mobile|1.0|%d|%s|%s|%s\n", cid, event_name, severity_strings[severity], extension);
	struct CEF_payload *payload = malloc (sizeof (struct CEF_payload));
	
	if (payload) {	
		payload->class = class;		
		sal_strcpy(payload->name,(char*)event_name);
		payload->sev = severity;	
		va_start(args, fmt);
		i = vsnprintf(msg, SR_MAX_LOG-1, fmt, args);
		va_end(args);
		msg[SR_MAX_LOG - 1] = 0;
		sal_strcpy(payload->extension,msg);
		
		log_print_cef_msg(payload);
	}else
		printf("Failed to CEF log...%x\n",i);
		
	
	free (payload);	
}

SR_32 sr_log_init (const SR_8* app_name, SR_32 flags)
{
	sal_strcpy(g_app_name, (SR_8*)app_name);

	printf("Starting LOG module!\n");
	return SR_SUCCESS;
}

