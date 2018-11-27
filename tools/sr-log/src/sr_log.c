#include "sr_log.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"
#include "sr_config_parse.h"
#include "engine_sal.h"
#include "sal_linux.h"
#include "sr_ver.h"

SR_MUTEX cef_lock = SR_MUTEX_INIT_VALUE; //for locking the cef wirte to file function

// FORMAT: CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
// Severity is a string or integer and reflectsthe importance of the event. 
//The valid string values are Unknown, Low, Medium, High, and Very-High. The valid integer values are 0-3=Low, 4-6=Medium, 7- 8=High, and 9-10=Very-High.
char severity_strings[SEVERITY_MAX][10] = { "Unknown", "Low", "Medium", "High", "Very-High"};

static SR_8 		g_app_name[20];
static SR_BOOL		g_log_init = SR_FALSE;

typedef const SR_8* cef_str;
FILE* log_fp = 0;
SR_U32 MB; // 1MB

void log_cef_msg(cef_str str)
{
    SR_8 file1[FILENAME_MAX], file2[FILENAME_MAX];
    struct config_params_t *config_params;

    config_params = sr_config_get_param();

    if(!log_fp){
		memset(file1, 0, FILENAME_MAX);	
		sprintf(file1,"%s%s%d%s",config_params->CEF_log_path,LOG_CEF_PREFIX,0,LOG_CEF_SUFFIX);
		log_fp = fopen(file1,"a");
    }

    if(log_fp){
		if( ftell(log_fp) > MB){
			
			fclose(log_fp);
            log_fp = 0;
            
            SR_32 i_log = 0;

            for(i_log = (config_params->cef_file_cycling-1);i_log >= 0;i_log--){
				
				memset(file1, 0, FILENAME_MAX);
				memset(file2, 0, FILENAME_MAX);
				sprintf(file1,"%s%s%d%s",config_params->CEF_log_path,LOG_CEF_PREFIX,i_log,LOG_CEF_SUFFIX );
				sprintf(file2,"%s%s%d%s",config_params->CEF_log_path,LOG_CEF_PREFIX, i_log+1,LOG_CEF_SUFFIX );
				sal_rename(file1, file2);
			}
			
			memset(file1, 0, FILENAME_MAX);
            sprintf(file1,"%s%s%d%s",config_params->CEF_log_path,LOG_CEF_PREFIX,0,LOG_CEF_SUFFIX);
            log_fp = fopen(file1, "a");
            
        }

        fputs(str,log_fp);
        fflush(log_fp);
    }
}

void log_print_cef_msg(CEF_payload *cef)
{	
	SR_8 cef_buffer[MAX_PAYLOAD];
	time_t timer;
    SR_8 buffer[26]; //for time
    SR_8 buffer_tz[8]; //for timezone
    struct tm* tm_info;
    struct timeval tv;
    struct config_params_t *config_params;

    config_params = sr_config_get_param();

    gettimeofday(&tv, NULL); 
    time(&timer);
    tm_info = localtime(&timer);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
    strftime(buffer_tz,sizeof(buffer_tz), "%z", tm_info);

	sprintf(cef_buffer,"CEF:%d|%s|%s|%d.%d|%d|%s|%d|%s=%s.%.3ld%s %s=%s %s=%s %s\n",
			CEF_VER,
			VENDOR_NAME,PRODUCT_NAME,
			VSENTRY_VER_MAJOR,VSENTRY_VER_MINOR,
			cef->class,
			cef->name,
			cef->sev,
			DEVIC_RECEIPT_TIME,buffer,tv.tv_usec/1000,buffer_tz,
			DEVICE_EXTERNAL_ID,config_params->vin, // the vin would be in the beginning of the extension filed.
			DEVICE_FACILITY,LOG_FROM_ENGINE,
			cef->extension);
	
	if (SR_FALSE == g_log_init)
		printf ("%s", cef_buffer);
	if (config_params->log_type & LOG_TYPE_CURL) {
		SR_MUTEX_LOCK(&cef_lock);
		log_cef_msg(cef_buffer);
		SR_MUTEX_UNLOCK(&cef_lock);
	}

	if (config_params->log_type & LOG_TYPE_SYSLOG)
		sal_log (cef_buffer, cef->sev);
}


void CEF_log_event(const SR_U32 class, const char *event_name, enum SR_CEF_SEVERITY severity, const char *fmt, ...)
{
	SR_U32 i;
	va_list args;
	SR_8 msg[SR_MAX_LOG];
	struct CEF_payload *payload;
	
	SR_Malloc(payload,struct CEF_payload *,sizeof (struct CEF_payload));
	
	va_start(args, fmt);
	i = vsnprintf(msg, SR_MAX_LOG-1, fmt, args);
	va_end(args);
	msg[SR_MAX_LOG - 1] = 0;
	
	if (payload) {	
		payload->class = class;		
		sal_strcpy(payload->name,(char*)event_name);
		payload->sev = severity;
		sal_strcpy(payload->extension,msg);
		
		log_print_cef_msg(payload);
	}else{
		printf("Failed to CEF log: %s|%s|%s %x\n",(char*)event_name,severity_strings[severity],msg,i);
	}
		
	SR_Free(payload);	
}

SR_32 sr_log_init (const SR_8* app_name, SR_32 flags)
{
	sal_strcpy(g_app_name, (SR_8*)app_name);
	struct config_params_t *config_params;

	config_params = sr_config_get_param();

	MB = 1024*1024*config_params->cef_file_size;
	
	if (config_params->log_type & LOG_TYPE_SYSLOG)
		sal_openlog();

	printf("LOG module started succesfully\n");
	g_log_init = SR_TRUE;
	return SR_SUCCESS;
}

void sr_log_deinit(void)
{
	struct config_params_t *config_params;

	config_params = sr_config_get_param();

	if (config_params->log_type & LOG_TYPE_SYSLOG)
		sal_closelog();
	g_log_init = SR_FALSE;
}
