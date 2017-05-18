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
										
typedef struct CEF_payload
{   
    float						cef_version;
    char						dev_vendor[32];
    char						dev_product[32];
    float						dev_version;			
	enum dev_event_class_ID		class;
	char						name[32];
    enum severity				sev;
    char 						extension[256]; 
}CEF_payload;

/* FS related functions */
typedef struct _fileinfo {
        unsigned char filename[128];
        unsigned char fullpath[128];
        unsigned long gid; /* group id */
        unsigned long tid; /* thread id */
        unsigned long pid; /* pid */
}fileinfo;


int mpx_mkdir(fileinfo* info);

/*
typedef union {

	struct _file_open_info{
		struct file *file;
		const struct cred *cred;
	}file_open_info;

	struct _inode_create_info{
		struct inode *dir;
		struct dentry *dentry;
		umode_t mode;
	}inode_create_info;

	struct _chmod_info{
		struct path *path;
		umode_t mode;
	}chmod_info;

	struct _link_info {
		struct dentry *old_dentry;
		struct inode *dir;
		struct dentry *new_dentry;
	}link_info;

	struct _unlink_info {
		struct inode *dir;
		struct dentry *dentry;
	}unlink_info;

	struct _symlink_info {
		struct inode *dir;
		struct dentry *dentry;
		const char *name;
	}symlink_info;

	struct _mkdir_info {
		struct inode *dir;
		struct dentry *dentry;
		int mask;
	}mkdir_info;

	struct _rmdir_info {
		struct inode *dir;
		struct dentry *dentry;
	}rmdir_info;
	
	struct _socket_connect_info {
		struct socket *sock;
		struct sockaddr *address;
		int addrlen;
	}socket_connect_info;

	struct _socket_create_info {
		int family;
		int type; 
		int protocol; 
		int kern;
	}socket_create_info;

	struct _socket_bind_info {
		struct socket *sock; 
		struct sockaddr *address;
		int addrlen;
	}socket_bind_info;

	struct _socket_listen_info {
		struct socket *sock; 
		int backlog;
	}socket_listen_info;

	struct _socket_accept_info {
		struct socket *sock; 
		struct socket *newsock;
	}socket_accept_info;

	struct _socket_sendmsg_info {
		struct socket *sock;
		struct msghdr *msg; 
		int size;
	}socket_sendmsg_info;

	struct _socket_recvmsg_info {
		struct socket *sock;
		struct msghdr *msg;
		int size;
		int flags;
	}socket_recvmsg_info;

	struct _socket_shutdown_info {
		struct socket *sock;
		int how;
	}socket_shutdown_info;

}perm_info_t;
*/


#endif /* _MULTIPLEXER_H */
