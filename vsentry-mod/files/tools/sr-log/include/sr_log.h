#ifndef SR_LOG_H
#define SR_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#define NETLINK_USER		 31
#define NETLINK_LOG_USER 	 18

#define MAX_PAYLOAD 2024 /* maximum payload size*/

#define MAX_MSG_LEN             1024

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

enum dev_event_class_ID {
	NETWORK, 
	FS, 
	PROC
};

enum severity {
	EMERGENCY,
	ALERT,
	CRITICAL,
	ERROR,
	WARNING,
	NOTICE,
	INFO,
	DEBUG
};
										
typedef struct CEF_payload
{   
    float						cef_version;
    char						dev_vendor[32];
    char						dev_product[32];
    float						dev_version;			
	enum dev_event_class_ID		class;
	char						name[32];
    enum severity				sev;
    char 						extension[512]; 
}CEF_payload;

int sr_log_init (const char* app_name, int flags);

int __sr_print (enum SR_LOG_PRIORITY priority, int line, const char *file, const char *fmt, ...);

int sr_net_init (void/*hardcoded for now...*/);//netlink userspace init

#define sr_print(priority, ...) __sr_print(priority, __LINE__, __FILE__, __VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif /* SR_LOG_H */
