#ifndef SR_LSM_HOOKS_H
#define SR_LSM_HOOKS_H

#include <linux/version.h>
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

int register_lsm_hooks (void);
int unregister_lsm_hooks (void);


							
typedef enum {
	VS_HOOK_BINDER_SET_CONTEXT_MGR,
	VS_HOOK_BINDER_TRANSACTION,
	VS_HOOK_BINDER_TRANSFER_BINDER,
	VS_HOOK_BINDER_TRANSFER_FILE,
	VS_HOOK_PTRACE_ACCESS_CHECK,
	VS_HOOK_PTRACE_TRACEME,
	VS_HOOK_CAPGET,
	VS_HOOK_CAPSET,
	VS_HOOK_CAPABLE,
	VS_HOOK_QUOTACTL,
	VS_HOOK_QUOTA_ON,
	VS_HOOK_SYSLOG,
	VS_HOOK_SETTIME,
	VS_HOOK_VM_ENOUGH_MEMORY,
	VS_HOOK_BPRM_SET_CREDS,
	VS_HOOK_BPRM_CHECK_SECURITY,
	VS_HOOK_BPRM_SECUREEXEC,
	VS_HOOK_BPRM_COMMITTING_CREDS,
	VS_HOOK_BPRM_COMMITTED_CREDS,
	VS_HOOK_SB_ALLOC_SECURITY,
	VS_HOOK_SB_FREE_SECURITY,
	VS_HOOK_SB_COPY_DATA,
	VS_HOOK_SB_REMOUNT,
	VS_HOOK_SB_KERN_MOUNT,
	VS_HOOK_SB_SHOW_OPTIONS,
	VS_HOOK_SB_STATFS,
	VS_HOOK_SB_MOUNT,
	VS_HOOK_SB_UMOUNT,
	VS_HOOK_SB_PIVOTROOT,
	VS_HOOK_SB_SET_MNT_OPTS,
	VS_HOOK_SB_CLONE_MNT_OPTS,
	VS_HOOK_SB_PARSE_OPTS_STR,
	VS_HOOK_DENTRY_INIT_SECURITY,
#ifdef CONFIG_SECURITY_PATH
	VS_HOOK_PATH_UNLINK,
	VS_HOOK_PATH_MKDIR,
	VS_HOOK_PATH_RMDIR,
	VS_HOOK_PATH_MKNOD,
	VS_HOOK_PATH_TRUNCATE,
	VS_HOOK_PATH_SYMLINK,
	VS_HOOK_PATH_LINK,
	VS_HOOK_PATH_RENAME,
	VS_HOOK_PATH_CHMOD,
	VS_HOOK_PATH_CHOWN,
	VS_HOOK_PATH_CHROOT,
#endif
	VS_HOOK_INODE_ALLOC_SECURITY,
	VS_HOOK_INODE_FREE_SECURITY,
	VS_HOOK_INODE_INIT_SECURITY,
	VS_HOOK_INODE_CREATE,
	VS_HOOK_INODE_LINK,
	VS_HOOK_INODE_UNLINK,
	VS_HOOK_INODE_SYMLINK,
	VS_HOOK_INODE_MKDIR,
	VS_HOOK_INODE_RMDIR,
	VS_HOOK_INODE_MKNOD,
	VS_HOOK_INODE_RENAME,
	VS_HOOK_INODE_READLINK,
	VS_HOOK_INODE_FOLLOW_LINK,
	VS_HOOK_INODE_PERMISSION,
	VS_HOOK_INODE_SETATTR,
	VS_HOOK_INODE_GETATTR,
	VS_HOOK_INODE_SETXATTR,
	VS_HOOK_INODE_POST_SETXATTR,
	VS_HOOK_INODE_GETXATTR,
	VS_HOOK_INODE_LISTXATTR,
	VS_HOOK_INODE_REMOVEXATTR,
	VS_HOOK_INODE_NEED_KILLPRIV,
	VS_HOOK_INODE_KILLPRIV,
	VS_HOOK_INODE_GETSECURITY,
	VS_HOOK_INODE_SETSECURITY,
	VS_HOOK_INODE_LISTSECURITY,
	VS_HOOK_INODE_GETSECID,
	VS_HOOK_FILE_PERMISSION,
	VS_HOOK_FILE_ALLOC_SECURITY,
	VS_HOOK_FILE_FREE_SECURITY,
	VS_HOOK_FILE_IOCTL,
	VS_HOOK_MMAP_ADDR,
	VS_HOOK_MMAP_FILE,
	VS_HOOK_FILE_MPROTECT,
	VS_HOOK_FILE_LOCK,
	VS_HOOK_FILE_FCNTL,
	VS_HOOK_FILE_SET_FOWNER,
	VS_HOOK_FILE_SEND_SIGIOTASK,
	VS_HOOK_FILE_RECEIVE,
	VS_HOOK_FILE_OPEN,
	VS_HOOK_TASK_CREATE,
	VS_HOOK_TASK_FREE,
	VS_HOOK_CRED_ALLOC_BLANK,
	VS_HOOK_CRED_FREE,
	VS_HOOK_CRED_PREPARE,
	VS_HOOK_CRED_TRANSFER,
	VS_HOOK_KERNEL_ACT_AS,
	VS_HOOK_KERNEL_CREATE_FILES_AS,
	VS_HOOK_KERNEL_FW_FROM_FILE,
	VS_HOOK_KERNEL_MODULE_REQUEST,
	VS_HOOK_KERNEL_MODULE_FROM_FILE,
	VS_HOOK_TASK_SETPGID,
	VS_HOOK_TASK_GETPGID,
	VS_HOOK_TASK_GETSID,
	VS_HOOK_TASK_GETSECID,
	VS_HOOK_TASK_SETNICE,
	VS_HOOK_TASK_SETIOPRIO,
	VS_HOOK_TASK_GETIOPRIO,
	VS_HOOK_TASK_SETRLIMIT,
	VS_HOOK_TASK_SETSCHEDULER,
	VS_HOOK_TASK_GETSCHEDULER,
	VS_HOOK_TASK_MOVEMEMORY,
	VS_HOOK_TASK_KILL,
	VS_HOOK_TASK_WAIT,
	VS_HOOK_TASK_PRCTL,
	VS_HOOK_TASK_TO_INODE,
	VS_HOOK_IPC_PERMISSION,
	VS_HOOK_IPC_GETSECID,
	VS_HOOK_MSG_MSG_ALLOC_SECURITY,
	VS_HOOK_MSG_MSG_FREE_SECURITY,
	VS_HOOK_MSG_QUEUE_ALLOC_SECURITY,
	VS_HOOK_MSG_QUEUE_FREE_SECURITY,
	VS_HOOK_MSG_QUEUE_ASSOCIATE,
	VS_HOOK_MSG_QUEUE_MSGCTL,
	VS_HOOK_MSG_QUEUE_MSGSND,
	VS_HOOK_MSG_QUEUE_MSGRCV,
	VS_HOOK_SHM_ALLOC_SECURITY,
	VS_HOOK_SHM_FREE_SECURITY,
	VS_HOOK_SHM_ASSOCIATE,
	VS_HOOK_SHM_SHMCTL,
	VS_HOOK_SHM_SHMAT,
	VS_HOOK_SEM_ALLOC_SECURITY,
	VS_HOOK_SEM_FREE_SECURITY,
	VS_HOOK_SEM_ASSOCIATE,
	VS_HOOK_SEM_SEMCTL,
	VS_HOOK_SEM_SEMOP,
	VS_HOOK_NETLINK_SEND,
	VS_HOOK_D_INSTANTIATE,
	VS_HOOK_GETPROCATTR,
	VS_HOOK_SETPROCATTR,
	VS_HOOK_ISMACLABEL,
	VS_HOOK_SECID_TO_SECCTX,
	VS_HOOK_SECCTX_TO_SECID,
	VS_HOOK_RELEASE_SECCTX,
	VS_HOOK_INODE_NOTIFYSECCTX,
	VS_HOOK_INODE_SETSECCTX,
	VS_HOOK_INODE_GETSECCTX,
#ifdef CONFIG_SECURITY_NETWORK
	VS_HOOK_UNIX_STREAM_CONNECT,
	VS_HOOK_UNIX_MAY_SEND,
	VS_HOOK_SOCKET_CREATE,
	VS_HOOK_SOCKET_POST_CREATE,
	VS_HOOK_SOCKET_BIND,
	VS_HOOK_SOCKET_CONNECT,
	VS_HOOK_SOCKET_LISTEN,
	VS_HOOK_SOCKET_ACCEPT,
	VS_HOOK_SOCKET_SENDMSG,
	VS_HOOK_SOCKET_RECVMSG,
	VS_HOOK_SOCKET_GETSOCKNAME,
	VS_HOOK_SOCKET_GETPEERNAME,
	VS_HOOK_SOCKET_GETSOCKOPT,
	VS_HOOK_SOCKET_SETSOCKOPT,
	VS_HOOK_SOCKET_SHUTDOWN,
	VS_HOOK_SOCKET_SOCK_RCV_SKB,
	VS_HOOK_SOCKET_GETPEERSEC_STREAM,
	VS_HOOK_SOCKET_GETPEERSEC_DGRAM,
	VS_HOOK_SK_ALLOC_SECURITY,
	VS_HOOK_SK_FREE_SECURITY,
	VS_HOOK_SK_CLONE_SECURITY,
	VS_HOOK_SK_GETSECID,
	VS_HOOK_SOCK_GRAFT,
	VS_HOOK_INET_CONN_REQUEST,
	VS_HOOK_INET_CSK_CLONE,
	VS_HOOK_INET_CONN_ESTABLISHED,
	VS_HOOK_SECMARK_RELABEL_PACKET,
	VS_HOOK_SECMARK_REFCOUNT_INC,
	VS_HOOK_SECMARK_REFCOUNT_DEC,
	VS_HOOK_REQ_CLASSIFY_FLOW,
	VS_HOOK_TUN_DEV_ALLOC_SECURITY,
	VS_HOOK_TUN_DEV_FREE_SECURITY,
	VS_HOOK_TUN_DEV_CREATE,
	VS_HOOK_TUN_DEV_ATTACH_QUEUE,
	VS_HOOK_TUN_DEV_ATTACH,
	VS_HOOK_TUN_DEV_OPEN,
	VS_HOOK_SKB_OWNED_BY,
#endif  /* CONFIG_SECURITY_NETWORK */
#ifdef CONFIG_SECURITY_NETWORK_XFRM
	VS_HOOK_XFRM_POLICY_ALLOC_SECURITY,
	VS_HOOK_XFRM_POLICY_CLONE_SECURITY,
	VS_HOOK_XFRM_POLICY_FREE_SECURITY,
	VS_HOOK_XFRM_POLICY_DELETE_SECURITY,
	VS_HOOK_XFRM_STATE_ALLOC,
	VS_HOOK_XFRM_STATE_ALLOC_ACQUIRE,
	VS_HOOK_XFRM_STATE_FREE_SECURITY,
	VS_HOOK_XFRM_STATE_DELETE_SECURITY,
	VS_HOOK_XFRM_POLICY_LOOKUP,
	VS_HOOK_XFRM_STATE_POL_FLOW_MATCH,
	VS_HOOK_XFRM_DECODE_SESSION,
#endif  /* CONFIG_SECURITY_NETWORK_XFRM */
#ifdef CONFIG_KEYS
	VS_HOOK_KEY_ALLOC,
	VS_HOOK_KEY_FREE,
	VS_HOOK_KEY_PERMISSION,
	VS_HOOK_KEY_GETSECURITY,
#endif  /* CONFIG_KEYS */
#ifdef CONFIG_AUDIT
	VS_HOOK_AUDIT_RULE_INIT,
	VS_HOOK_AUDIT_RULE_KNOWN,
	VS_HOOK_AUDIT_RULE_MATCH,
	VS_HOOK_AUDIT_RULE_FREE,
#endif /* CONFIG_AUDIT */

	VS_HOOK_MAX,
} vsentry_hook_type;

#endif /* SR_LSM_HOOKS_H */
