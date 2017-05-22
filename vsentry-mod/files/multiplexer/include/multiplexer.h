#ifndef _MULTIPLEXER_H
#define _MULTIPLEXER_H

#define MAIN_SOCKET_INDEX		0
#define LOG_SOCKET_INDEX		1

#define PRODUCT_VENDOR	"saferide"
#define MODULE_NAME		"vsentry"
#define CEF_VERSION 	23.0f //a float number
#define VSENTRY_VERSION 1.0f //a float number


void main_socket_process_cb(void *data);
void log_socket_process_cb(void *data);

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
										
typedef struct CEF_payload {   
    float						cef_version;
    char						dev_vendor[32];
    char						dev_product[32];
    float						dev_version;			
	enum dev_event_class_ID		class;
	char						name[32];
    enum severity				sev;
    char 						extension[256]; 
}CEF_payload;

typedef struct _identifier {
/*
the kernel doesn't make a real distinction between pid and tid: 
threads are just like processes but they share some things (memory, fds...) with other instances of the same group.
a tid is actually the identifier of the schedulable object in the kernel (thread), 
while the pid is the identifier of the group of schedulable objects that share memory and fds (process).
*/	
	unsigned char event_name[32];
	unsigned long gid; /* group identifier */
	unsigned long tid; /* thread identifier */
	unsigned long pid; /* process identifier */
}identifier;


typedef union {

/* FS related functions  */
	struct _fileinfo {
		identifier id;
		unsigned char filename[128];
		unsigned char fullpath[128];
	}fileinfo;

/* socket related functions */
	struct _sock_info {
		identifier id;
		unsigned char ipv4[32];
		unsigned char ipv6[32];
		unsigned int port;
	}sock_info;

}mpx_info_t;

int mpx_mkdir(mpx_info_t* info);
int mpx_rmdir(mpx_info_t* info);
int mpx_sk_connect(mpx_info_t* info);


#endif /* _MULTIPLEXER_H */
