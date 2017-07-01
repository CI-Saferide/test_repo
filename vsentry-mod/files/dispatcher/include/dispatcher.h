#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include "sr_log.h"
#include "sr_types.h"

#define MAIN_SOCKET_INDEX		0
#define LOG_SOCKET_INDEX		1

#define PRODUCT_VENDOR	"saferide"
#define MODULE_NAME		"vsentry"
#define CEF_VERSION 	23.0f //a float number
#define VSENTRY_VERSION 1.0f //a float number

#define SR_MAX_PATH_SIZE 512

typedef struct _identifier {
/*
	the kernel doesn't make a real distinction between pid and tid: 
	threads are just like processes but they share some things (memory, fds...) with other instances of the same group.
	a tid is actually the identifier of the schedulable object in the kernel (thread), 
	while the pid is the identifier of the group of schedulable objects that share memory and fds (process).
*/	
	SR_U8		event_name[32];
	SR_U32 		gid; /* group identifier */
	SR_U32 		tid; /* thread identifier */
	SR_U32 		pid; /* process identifier */
}identifier;


typedef union {

/* FS related functions  */
	struct _fileinfo {
		identifier id;
		SR_U8 	filename[128];
		SR_U8 	fullpath[128];
		SR_U8 	old_path[128];
	}fileinfo;

/* socket related functions */
	struct _address_info {
		identifier id;
		SR_U8 	ipv4[16];
		SR_U8	ipv6[32];
		SR_U16 	port;
	}address_info;
	
	struct _socket_info {
		identifier id;
		SR_U8 	family[16];		//family contains the requested protocol family.
		SR_U8 	type[16];		//type contains the requested communications type.
		SR_U32 	protocol;		//protocol contains the requested protocol.
		SR_BOOL kern;			//kern set to 1 if a kernel socket.
	}socket_info;
}disp_info_t;

CEF_payload cef_init(char* event_name,enum severity sev,enum dev_event_class_ID	class);

SR_BOOL disp_mkdir(disp_info_t* info);
SR_BOOL disp_rmdir(disp_info_t* info);

SR_BOOL disp_inode_create(disp_info_t* info);
SR_BOOL disp_path_chmod(disp_info_t* info);
SR_BOOL disp_file_open(disp_info_t* info);

SR_BOOL disp_inode_link(disp_info_t* info);
SR_BOOL disp_inode_unlink(disp_info_t* info);
SR_BOOL disp_inode_symlink(disp_info_t* info);

SR_BOOL disp_socket_connect(disp_info_t* info);
SR_BOOL disp_socket_create(disp_info_t* info);


#endif /* _DISPATCHER_H */
