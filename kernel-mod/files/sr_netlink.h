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
#include <linux/uaccess.h>
#include <linux/atomic.h>
#include <linux/bitops.h>
#include <linux/interrupt.h>
#include <linux/netdevice.h>	/* for network interface checks */
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/dccp.h>
#include <linux/quota.h>
#include <linux/un.h>		/* for Unix socket types */
#include <linux/parser.h>
#include <linux/nfs_mount.h>
#include <linux/hugetlb.h>
#include <linux/personality.h>
#include <linux/audit.h>
#include <linux/string.h>
#include <linux/mutex.h>
#include <linux/posix-timers.h>
#include <linux/syslog.h>
#include <linux/user_namespace.h>
#include <linux/netlink.h>
#include <linux/skbuff.h>

#include <net/sock.h> 
#include <net/af_unix.h>	/* for Unix socket types */
#include <net/ipv6.h>
#include <net/netlink.h>
#include <net/icmp.h>
#include <net/ip.h>		/* for local_port_range[] */
#include <net/tcp.h>		/* struct or_callable used in sock_rcv_skb */
#include <net/net_namespace.h>
#include <net/netlabel.h>

#include <asm/ioctls.h>


#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
#include <linux/lsm_hooks.h>

#include <linux/inet.h>
#include <linux/lsm_audit.h>
#include <linux/export.h>
#include <linux/msg.h>
#include <linux/shm.h>
#include <linux/xfrm.h>
#include <net/inet_connection_sock.h>
#include <net/xfrm.h>

#endif /* LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0) */

#define NETLINK_USER 31

#define BUFF_SIZE 512

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
extern struct security_hook_heads security_hook_heads;
#else
extern struct security_operations *security_ops;
#endif/*LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)*/

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
