#ifndef SR_LOG_H
#define SR_LOG_H
#include "sr_sal_common.h"

#define CEF_VER			2 

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
	SR_CEF_CID_SP = 700,            /* System policer */

	SR_FORENSIC_NETWORK = 2000		/* forensic network information */
};


#define NETLINK_USER		31
#define NETLINK_LOG_USER 	18

#define MAX_PAYLOAD 		2048 			/* maximum payload size*/

#define LOG_CEF_PREFIX "vsentry"
#define LOG_CEF_SUFFIX ".log"

/*deviceFacility*/
#define LOG_FROM_ENGINE "engine"
#define LOG_FROM_KERNEL "kernel"

/********************************************/
/*											*/
/*			Special CEF mappings			*/
/*	September 28,2017 By HP ArcSight		*/
/*											*/
/********************************************/
 
/*Action taken by the device.*/
#define DEVICE_ACTION 				"act"

/*Represents the category assigned by the originating device. 
 *Devices often use their own categorization schema to classify event. 
 *Example: “/Monitor/Disk/Read”*/
#define DEVICE_EVENT_CATEGORY 		"cat"

/*0 for inbound or “1” for outbound*/
#define DEVICE_DIRECTION 			"deviceDirection"

#define IF_ID 						"interfaceId"

/*(VIN in our case)A name that uniquely identifies the device generating this event.*/
#define DEVICE_EXTERNAL_ID 			"deviceExternalId"

/*kernel or sr_engine in our case*/
#define DEVICE_FACILITY 			"deviceFacility"

/*Interface on which the packet or data entered the device(eth0, can0,slcan0 etc.)*/
#define DEVICE_INBOUND_INTERFACE	"deviceInboundInterface"

/*Interface on which the packet or data left the device (futue...)*/
#define DEVICE_OUTBOUND_INTERFACE 	"deviceOutboundInterface"

/*Unique identifier for the payload associated with the event.*/
#define DEVICE_PAYLOAD_ID 			"devicePayloadId"

/*Process name associated with the event. 
 * An example might be the process generating the syslog entry in UNIX.*/
#define DEVICE_PROCESS_NAME 		"deviceProcessName"

/*The valid port numbers are between 0 and 65535.*/
#define DEVICE_DEST_PORT 					"dpt"

/*Identifies the destination address that the event refers to in an IP network. 
 * The format is an IPv4 address.*/
#define DEVICE_DEST_IP				 		"dst"

/*The timezone for the device generating the event.*/
#define DEVICE_TIMEZONE		 		"dtz"

/*Hash of a file. (or inode number in UNIX)*/
#define INODE_NUMBER 				"inodeNumber"

/*Full path to the file, including file name itself. 
 * Example: C:\ProgramFiles\WindowsNT\Accessories\wordpad.exe or /usr/bin/zip*/
#define DEVICE_FILE_PATH		 			"filePath"

/*Permissions of the file...(RWX)*/
#define FILE_PERMISSION 			"filePermission"

/*Number of bytes transferred
 * inbound, relative to the source to
 * destination relationship, meaning
 * that data was flowing from source
 * to destination.*/
#define BYTES_INBOUNT 				"in"

/*An arbitrary message giving more
 * details about the event. Multi-line
 * entries can be produced by using
 * \n as the new line separator.*/
#define MESSAGE 					"msg"

/*Number of bytes transferred outbound relative to the source to destination relationship. 
 * For example, the byte number of data flowing from the destination to the source.*/
#define BYTES_OUT			 		"out"

/*Displays the outcome, usually as ‘success’ or ‘failure’.*/
#define EVENT_OUTCOME 				"outcome"

/*Identifies the Layer-4 protocol used. The possible values are protocols such as TCP or UDP.*/
#define TRANSPORT_PROTOCOL 			"proto"

/*The reason an audit event was generated. 
 * For example “badd password” or “unknown user”. 
 * This could also be an error or return code. 
 * Example: “0x1234”*/
#define REASON 						"reason"

/*The time at which the event related to the activity was received. 
 * The format is MMM dd yyyy HH:mm:ss or milliseconds since epoch (Jan 1st 1970)*/
#define DEVIC_RECEIPT_TIME 			"rt"

/*The valid port numbers are 0 to 65535.*/
#define DEVICE_SRC_PORT 			"spt"

/*Identifies the source that an event refers to in an IP network. 
 * The format is an IPv4 address. 
 * Example: “192.168.10.1”.*/
#define DEVICE_SRC_IP 				"src"

/**/
#define DEVICE_UID 		"suser"

/*Don't need to be captain obvious...*/
#define CAN_MSG_ID 					"mid" 

/*cs1 is a deviceCustomString1 that means Rule Number in firewalls.*/
#define RULE_NUM_KEY 				"rule" 

/* A count associated with this event. How many times was this same event observed? Count can be omitted if it is 1 */
#define BASE_EVENT_COUNT                        "cnt"

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
void handle_log_options(SR_8* cef_log, enum SR_CEF_SEVERITY severity);

#ifdef DEBUG
#define pr_fmt(fmt) fmt
#define CEF_log_debug(class, event_name, SR_CEF_SEVERITY, fmt, ...) \
	CEF_log_event(class, event_name, SR_CEF_SEVERITY, pr_fmt(fmt), ##__VA_ARGS__)
#else
#define CEF_log_debug(class, event_name, SR_CEF_SEVERITY, fmt, ...)
#endif

#endif /* SR_LOG_H */
