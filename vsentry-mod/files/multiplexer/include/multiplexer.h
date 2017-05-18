#ifndef _MULTIPLEXER_H
#define _MULTIPLEXER_H

#define MAIN_SOCKET_INDEX		0
#define LOG_SOCKET_INDEX		1

void main_socket_process_cb(void *data);
void log_socket_process_cb(void *data);

/* FS related functions */
typedef struct _fileinfo {
        unsigned char filename[128];
        unsigned char fullpath[128];
        unsigned long gid; /* group id */
        unsigned long tid; /* thread id */
        unsigned long pid; /* pid */
}fileinfo;

/**
cef example:

CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]

CEF:1.2|SafeRide|vSentry|1.0|100|Malware stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

CEF:1.0|SafeRide|vSentry|1.0|0|None|None| 
 * **/
enum module_name 	{LSM, LOG};
enum class_ID   	{NETWORK, FS, PROC};
enum severity		{ONE = 1,
					TWO,
					THREE,
					FOUR,
					FIVE,
					SIX,
					SEVEN,
					EIGHT,
					NINE,
					TEN
					};

typedef struct CEF_payload
{   
    int		 cef_version;
    char 	 dev_vendor[32];
    char 	 dev_product[32];

    enum severity		sev;
    enum module_name	module;
	enum class_ID		class;
	
	int extension_size;
    char extension[256]; 
}CEF_payload;

int mpx_mkdir(fileinfo* info);


#endif /* _MULTIPLEXER_H */
