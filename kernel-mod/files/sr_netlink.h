#ifndef SR_NETLINK_H
#define SR_NETLINK_H

#ifdef __cplusplus
extern "C" {
#endif

#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/version.h>   // for LINUX_VERSION_CODE macro
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/utsname.h>   // for the utsname() release feature
#include <linux/kd.h>
#include <linux/tracehook.h>
#include <linux/errno.h>
#include <linux/sched.h>
#include <linux/xattr.h>
#include <linux/capability.h>
#include <linux/unistd.h>
#include <linux/mm.h>
#include <linux/mman.h>
#include <linux/slab.h>
#include <linux/pagemap.h>
#include <linux/proc_fs.h>
#include <linux/swap.h>
#include <linux/spinlock.h>
#include <linux/syscalls.h>
#include <linux/dcache.h>
#include <linux/file.h>
#include <linux/fdtable.h>
#include <linux/namei.h>
#include <linux/mount.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv6.h>
#include <linux/tty.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/net_namespace.h>
#include <net/netlabel.h>
#include <linux/uaccess.h>
#include <asm/ioctls.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <net/netlink.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <net/af_unix.h>	/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <net/ipv6.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#include <linux/lsm_hooks.h>
#include <net/inet_connection_sock.h>
#include <linux/inet.h>
#include <linux/lsm_audit.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <net/xfrm.h>
#include <linux/xfrm.h>
#endif

#include <linux/module.h>
#include <net/sock.h> 
#include <linux/netlink.h>
#include <linux/skbuff.h>

#define NETLINK_USER 31

#define SYSCALL_CONNECT		__NR_connect
#define SYSCALL_LINK		__NR_link
#define SYSCALL_UNLINK		__NR_unlink
#define SYSCALL_SYMLINK		__NR_symlink
#define SYSCALL_MKDIR		__NR_mkdir
#define SYSCALL_RMDIR		__NR_rmdir
#define SYSCALL_CHMOD		__NR_chmod
#define SYSCALL_CREATE		__NR_creat
#define SYSCALL_OPEN        __NR_open

#define BUFF_SIZE 512

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
extern struct security_hook_heads security_hook_heads;
#else
extern struct security_operations *security_ops;
#endif
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
/******** SECURITY_NETWORK *************/

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

int sr_netlink_init(void);
void sr_netlink_exit(void);
int sr_netlink_send_up(char *msg, int msg_len);


#ifdef __cplusplus
}
#endif

#endif /* SR_NETLINK_H */
