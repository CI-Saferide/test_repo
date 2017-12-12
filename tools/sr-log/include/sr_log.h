#ifndef SR_LOG_H
#define SR_LOG_H
#include "sr_sal_common.h"
#include "sr_ver.h"

#define CEF_VER_MAJOR	0
#define CEF_VER_MINOR	0
#define VENDOR_NAME		"SafeRide"
#define PRODUCT_NAME	"vSentry"

#ifdef __cplusplus
extern "C" {
#endif

enum SR_CEF_SEVERITY {
	SEVERITY_UNKNOWN =0,
	SEVERITY_LOW,
	SEVERITY_MEDIUM,
	SEVERITY_HIGH,
	SEVERITY_VERY_HIGH,
	SEVERITY_MAX
};

enum SR_CEF_CLASS_ID {
	SR_CEF_CID_FILE = 100,
	SR_CEF_CID_NETWORK = 200,
	SR_CEF_CID_CAN = 300, 
	SR_CEF_CID_SYSTEM = 400,
};


#define NETLINK_USER		 31
#define NETLINK_LOG_USER 	 18

#define MAX_PAYLOAD 2024 /* maximum payload size*/

#define SR_LOG_EMERG			1
#define SR_LOG_ALERT			1
#define SR_LOG_CRIT				1
#define SR_LOG_ERR				1
#define SR_LOG_WARN				1
#define SR_LOG_NOTICE			1
#define SR_LOG_INFO				1
#define SR_LOG_DEBUG			1

enum SR_LOG_PRIORITY {
    LOG_EMERG,
    LOG_ALERT,
    LOG_CRIT,
    LOG_ERR,
    LOG_WARN,
    LOG_NOTICE,
    LOG_INFO,
    LOG_DEBUG
};

/*
cef example:

CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]

CEF:1.2|SafeRide|vSentry|1.0|100|Malware stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

CEF:1.0|SafeRide|vSentry|1.0|0|None|None| 
*/

/*
enum dev_event_class_ID {
	NETWORK, 
	FS, 
	PROC
};*/

enum severity {
	EMERGENCY,
	ALERT,
	CRITICAL,
	ERROR,
	WARNING,
	NOTICE,
	INFO,
	LOG_DEBUG1 //need to change, redifinition!!!
};
										
typedef struct CEF_payload
{   			
	enum SR_CEF_CLASS_ID		class;
	char						name[32];
    enum severity				sev;
    char 						extension[512]; 
} CEF_payload;

int sr_log_init (const char* app_name, int flags);
#if 0
int __sr_print (enum SR_LOG_PRIORITY priority, int line, const char *file, const char *fmt, ...);
#define sr_print(priority, ...) __sr_print(priority, __LINE__, __FILE__, __VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

void CEF_log_event(const SR_U32 class, const char *event_name, const SR_U8 severity, const char *fmt, ...);
void log_print_cef_msg(CEF_payload *cef);

#ifdef DEBUG
#define pr_fmt(fmt) fmt
#define CEF_log_debug(class, event_name, severity, fmt, ...) \
	CEF_log_event(class, event_name, severity, pr_fmt(fmt), ##__VA_ARGS__)
#else
#define CEF_log_debug(class, event_name, severity, fmt, ...)
#endif

#endif /* SR_LOG_H */
