#include "sr_log.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_ring_buf.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"
#include "sr_config_parse.h"
#include "engine_sal.h"

extern struct config_params_t config_params;

// FORMAT: Jan 18 11:07:53 host CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]
// Severity is a string or integer and reflectsthe importance of the event. The valid string values are Unknown, Low, Medium, High, and Very-High. The valid integer values are 0-3=Low, 4-6=Medium, 7- 8=High, and 9-10=Very-High.
char severity_strings[SEVERITY_MAX][10] = { "Unknown", "Low", "Medium", "High", "Very-High"};

static SR_8 g_app_name[20];

typedef const SR_8* cef_str;
FILE* log_fp = 0;
SR_U32 MB = 1024*1024; // 1MB
cef_str cef_prefix = "vsentry";
cef_str cef_postfix = ".log";

void log_cef_msg(cef_str str)
{
    SR_8 file1[64], file2[64];
	SR_U32 i;

    if(!log_fp){
		
		sprintf(file1,"%s%s%d%s",config_params.CEF_log_path,cef_prefix,0,cef_postfix);
		log_fp = fopen(file1,"a");
    }

    if(log_fp){
		if( ftell(log_fp) > MB){
			fclose(log_fp);
            log_fp = 0;

            for(i = (config_params.cef_file_cycling-1);i >= 0;i--){
				sprintf(file1,"%s%s%d%s",config_params.CEF_log_path,cef_prefix,i,cef_postfix );
				sprintf(file2,"%s%s%d%s",config_params.CEF_log_path,cef_prefix, i+1,cef_postfix );
				sal_rename(file1, file2);
			}

            sprintf(file1,"%s%s%d%s",config_params.CEF_log_path,cef_prefix,0,cef_postfix);
            log_fp = fopen(file1, "a");
        }

        fputs(str,log_fp);
        fflush(log_fp);
    }
}

void log_print_cef_msg(CEF_payload *cef)
{	
	SR_8 cef_buffer[MAX_PAYLOAD];
	SR_8 cef_class[32];
	time_t timer;
    SR_8 buffer[26]; //for time
    struct tm* tm_info;
    
    time(&timer);
    tm_info = localtime(&timer);
    strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);
	
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
		sal_strcpy(cef_class,"Class N/A");	
		break;
	}
	
		
	sprintf(cef_buffer,"%s CEF:%d.%d|%s|%s|%d.%d|%s|%s|%s\n",
			buffer,
			CEF_VER_MAJOR,CEF_VER_MINOR,
			VENDOR_NAME,PRODUCT_NAME,
			VSENTRY_VER_MAJOR,VSENTRY_VER_MINOR,
			cef_class,cef->name, cef->extension);
			
	log_cef_msg(cef_buffer);
}


void CEF_log_event(const SR_U32 class, const char *event_name, enum SR_CEF_SEVERITY severity, const char *fmt, ...)
{
	SR_U32 i = 0;
	va_list args;
	SR_8 msg[SR_MAX_LOG];
	struct CEF_payload *payload;
	//payload = malloc (sizeof (struct CEF_payload));
	
	SR_Malloc(payload,struct CEF_payload *,sizeof (struct CEF_payload));
	
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
	}else{
		printf("Failed to CEF log...%x\n",i);
	}
		
	SR_Free(payload);	
}

SR_32 sr_log_init (const SR_8* app_name, SR_32 flags)
{
	sal_strcpy(g_app_name, (SR_8*)app_name);

	MB *=config_params.cef_file_size;
	printf("Starting LOG module!\n");
	return SR_SUCCESS;
}

