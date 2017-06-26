#ifndef _MULTIPLEXER_H
#define _MULTIPLEXER_H

#include "sr_log.h"

#define MAIN_SOCKET_INDEX		0
#define LOG_SOCKET_INDEX		1

#define PRODUCT_VENDOR	"saferide"
#define MODULE_NAME		"vsentry"
#define CEF_VERSION 	23.0f //a float number
#define VSENTRY_VERSION 1.0f //a float number

#define SR_MPX_MAX_PATH_SIZE 512

typedef struct _identifier {
/*
the kernel doesn't make a real distinction between pid and tid: 
threads are just like processes but they share some things (memory, fds...) with other instances of the same group.
a tid is actually the identifier of the schedulable object in the kernel (thread), 
while the pid is the identifier of the group of schedulable objects that share memory and fds (process).
*/	
	unsigned char event_name[32];
	unsigned int gid; /* group identifier */
	unsigned int tid; /* thread identifier */
	unsigned int pid; /* process identifier */
}identifier;


typedef union {

/* FS related functions  */
	struct _fileinfo {
		identifier id;
		unsigned char filename[128];
		unsigned char fullpath[128];
		unsigned char old_path[128];
	}fileinfo;

/* socket related functions */
	struct _address_info {
		identifier id;
		unsigned char ipv4[16];
		unsigned char ipv6[32];
		unsigned int port;
	}address_info;
	
	struct _socket_info {
		identifier id;
		unsigned char family[16];	//family contains the requested protocol family.
		unsigned char type[16];		//type contains the requested communications type.
		unsigned int protocol;		//protocol contains the requested protocol.
		unsigned int kern;			//kern set to 1 if a kernel socket.
	}socket_info;

}mpx_info_t;

void main_socket_process_cb(void *data);
void log_socket_process_cb(void *data);

CEF_payload cef_init(char* event_name,enum severity sev,enum dev_event_class_ID	class);

int mpx_mkdir(mpx_info_t* info);
int mpx_rmdir(mpx_info_t* info);

int mpx_inode_create(mpx_info_t* info);
int mpx_path_chmod(mpx_info_t* info);
int mpx_file_open(mpx_info_t* info);

int mpx_inode_link(mpx_info_t* info);
int mpx_inode_unlink(mpx_info_t* info);
int mpx_inode_symlink(mpx_info_t* info);

int mpx_socket_connect(mpx_info_t* info);
int mpx_socket_create(mpx_info_t* info);


#endif /* _MULTIPLEXER_H */
