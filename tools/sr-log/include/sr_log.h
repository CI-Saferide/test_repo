#ifndef SR_LOG_H
#define SR_LOG_H
#include "sr_sal_common.h"

#define CEF_VER_MAJOR	0 /*September 28,2017 By HP ArcSight*/
#define CEF_VER_MINOR	0
#define VENDOR_NAME		"SafeRide"
#define PRODUCT_NAME	"vSentry"

#ifdef __cplusplus
extern "C" {
#endif

enum SR_CEF_SEVERITY {
	SEVERITY_UNKNOWN = 0,
	SEVERITY_LOW,
	SEVERITY_MEDIUM,
	SEVERITY_HIGH,
	SEVERITY_VERY_HIGH,
	SEVERITY_MAX
};

enum SR_CEF_CLASS_ID {
	SR_CEF_CID_FILE = 100,			/* file classifier events */
	SR_CEF_CID_NETWORK = 200,		/* ip classifier events */
	SR_CEF_CID_CAN = 300,			/* CAN CLASSIFIER EVENTS */
	SR_CEF_CID_SYSTEM = 400,		/* general vsentry system events */
	SR_CEF_CID_ML_CAN = 500,		/* CAN machine learning events */
	SR_CEF_CID_STAT_IP = 600,		/* IP statisstical analysis events */
};


#define NETLINK_USER		 31
#define NETLINK_LOG_USER 	 18

#define MAX_PAYLOAD 2024 /* maximum payload size*/

#define LOG_CEF_PREFIX "vsentry"
#define LOG_CEF_SUFFIX ".log"

/*deviceFacility*/
#define LOG_FROM_ENGINE "engine"
#define LOG_FROM_KERNEL "kernel"

/*Special CEF mappings*/
#define RULE_NUM_KEY "cs1" //cs1 is a deviceCustomString1 that means Rule Number in firewalls


/*
cef example:

CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]

CEF:0|SafeRide|vSentry|0.2|300|CAN message drop|3|rt=2018-04-04 10:50:55.908850 deviceExternalId=NMTBE3JE00R197385K deviceFacility=engine cs1=1 act=Drop CanID=77 deviceDirection=1
CEF:0|SafeRide|vSentry|0.2|100|File operation drop|3|rt=2018-04-04 10:50:56.653316 deviceExternalId=NMTBE3JE00R197385K deviceFacility=engine cs1=3 fileHash=10065 filePermission=Read
CEF:0|SafeRide|vSentry|0.2|200|Connection allow|1|rt=2018-04-04 10:50:55.930858 deviceExternalId=NMTBE3JE00R197385K deviceFacility=engine cs1=14 act=Allow proto=UDP src=127.00.00.01 spt=53 dst=127.00.00.01 dpt=56449

CEF:0|SafeRide|vSentry|1.0|0|None|None| 

*/

										
typedef struct CEF_payload
{   			
	enum SR_CEF_CLASS_ID		class;
	SR_8						name[32];
    enum SR_CEF_SEVERITY		sev;
    SR_8 						extension[512];
} CEF_payload;

int sr_log_init (const char* app_name, int flags);
void sr_log_deinit (void);
#if 0
int __sr_print (enum SR_CEF_SEVERITY severity, int line, const char *file, const char *fmt, ...);
#define sr_print(severity, ...) __sr_print(severity, __LINE__, __FILE__, __VA_ARGS__)
#endif

#ifdef __cplusplus
}
#endif

void CEF_log_event(const SR_U32 class, const char *event_name, enum SR_CEF_SEVERITY severity, const char *fmt, ...);
void log_print_cef_msg(CEF_payload *cef);

#ifdef DEBUG
#define pr_fmt(fmt) fmt
#define CEF_log_debug(class, event_name, SR_CEF_SEVERITY, fmt, ...) \
	CEF_log_event(class, event_name, SR_CEF_SEVERITY, pr_fmt(fmt), ##__VA_ARGS__)
#else
#define CEF_log_debug(class, event_name, SR_CEF_SEVERITY, fmt, ...)
#endif

#endif /* SR_LOG_H */
