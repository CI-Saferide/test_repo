#ifndef _DISPATCHER_H
#define _DISPATCHER_H

#include "sr_log.h"
#include "sr_types.h"
#include "sr_sal_common.h"

#define MAIN_SOCKET_INDEX		0
#define LOG_SOCKET_INDEX		1

#define PRODUCT_VENDOR	"saferide"
#define MODULE_NAME		"vsentry"
#define CEF_VERSION 	230
#define VSENTRY_VERSION 10

#define SR_MAX_PATH_SIZE 512

enum hook_events {
	HOOK_MKDIR,
	HOOK_UNLINK,
	HOOK_SYMLINK,
	HOOK_RMDIR,
	HOOK_CHMOD,
	HOOK_INODE_CREATE,
	HOOK_FILE_OPEN,
	HOOK_INODE_LINK,
	MAX_HOOK
	/* NOTE: when addidng hooks make sure to update also event_mediator.c hook_event_names */
};

typedef struct _identifier {
/*
	the kernel doesn't make a real distinction between pid and tid: 
	threads are just like processes but they share some things (memory, fds...) with other instances of the same group.
	a tid is actually the identifier of the schedulable object in the kernel (thread), 
	while the pid is the identifier of the group of schedulable objects that share memory and fds (process).
*/	
	SR_U8				event_name[32];
	enum hook_events	event;
	SR_U32 				gid; /* group identifier */
	SR_U32 				tid; /* thread identifier */
	SR_U32 				pid; /* process identifier */
}identifier;


typedef union {

/* FS related functions  */
	struct _fileinfo {
		identifier 	id;
		SR_U32		current_inode;
		SR_U32		parent_inode;
		SR_U32		old_inode;
		SR_U8 		filename[128];
		SR_U8 		fullpath[128];
		SR_U8 		old_path[128];
	}fileinfo;

/* socket related functions */
	struct _tuple_info {
		struct {
			struct in_addr v4addr;
			// FUTURE struct in6_addr v6addr;
		} saddr;
		struct {
			struct in_addr v4addr;
			// FUTURE struct in6_addr v6addr;
		} daddr;
		SR_U16 	sport;
		SR_U16 	dport;
		SR_U8   ip_proto;
	}tuple_info;
	
	struct _socket_info {
		identifier id;
		SR_U8 	family[16];		//family contains the requested protocol family.
		SR_U8 	type[16];		//type contains the requested communications type.
		SR_U32 	protocol;		//protocol contains the requested protocol.
		SR_BOOL kern;			//kern set to 1 if a kernel socket.
	}socket_info;
}disp_info_t;

typedef struct _event_name {
	enum hook_events	event;
	SR_U8				name[32];
}event_name;

CEF_payload *cef_init(char* event_name,enum severity sev,enum dev_event_class_ID	class);

SR_BOOL disp_mkdir(disp_info_t* info);
SR_BOOL disp_rmdir(disp_info_t* info);

SR_BOOL disp_inode_create(disp_info_t* info);
SR_BOOL disp_path_chmod(disp_info_t* info);
SR_BOOL disp_file_open(disp_info_t* info);

SR_BOOL disp_inode_link(disp_info_t* info);
SR_BOOL disp_inode_unlink(disp_info_t* info);
SR_BOOL disp_inode_symlink(disp_info_t* info);

SR_BOOL disp_socket_connect(disp_info_t* info);
SR_32 disp_incoming_connection(disp_info_t* info);
SR_BOOL disp_socket_create(disp_info_t* info);


#endif /* _DISPATCHER_H */
