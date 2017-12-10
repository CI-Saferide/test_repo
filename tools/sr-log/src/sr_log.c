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
	char cef_buffer[128];
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
	case NETWORK:
		//sal_printf("class network, ");
		sal_strcpy(cef_class,"class network, ");
		break;
    case FS:
		//sal_printf("class fs, ");
		sal_strcpy(cef_class,"class fs, ");
		break;
    case PROC:
		//sal_printf("class proc, ");
		sal_strcpy(cef_class,"class proc, ");
		break;
	default:
		//sal_printf("class N/A, ");
		sal_strcpy(cef_class,"class N/A, ");	
		break;
	}

	sprintf(cef_buffer,"%s CEF: %d| vendor %s|product %s|ver %d|%s|%s|%s\n",
			buffer,cef->cef_version, cef->dev_vendor, cef->dev_product, cef->dev_version,cef_class,cef->name, cef->extension);
		
	log_cef_msg(cef_buffer);
}

SR_32 sr_log_init (const SR_8* app_name, SR_32 flags)
{
	sal_strcpy(g_app_name, (SR_8*)app_name);

	sal_printf("Starting LOG module!\n");
	
	return SR_SUCCESS;
}

