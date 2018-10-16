/* file: sr_lsm_hooks.c
 * purpose: this file registering the vsentry hooks into the linux os sys_calls
*/
#include "sr_lsm_hooks.h"
#include "dispatcher.h"
#include "sr_sal_common.h"
#include "event_mediator.h"
#include "sr_control.h"

/*implement filter for our sr-engine */
int hook_filter(void)
{
	/*if the statement is true in means the SYS_CALL invoked by sr-engine */
	if ((vsentry_get_pid()) == (current->pid)-1)
		return SR_TRUE;

	return SR_FALSE;
}

/*parsing data helper functions*/
void parse_sinaddr(const struct in_addr saddr, char* buffer, int length)
{
	snprintf(buffer, length, "%d.%d.%d.%d",
		(saddr.s_addr&0xFF),
		((saddr.s_addr&0xFF00)>>8),
		((saddr.s_addr&0xFF0000)>>16),
		((saddr.s_addr&0xFF000000)>>24));
}

char* get_path(struct dentry *dentry, char *buffer, int len)
{
	char path[SR_MAX_PATH_SIZE], *path_ptr;

	path_ptr = dentry_path_raw(dentry, path, SR_MAX_PATH_SIZE);
	if (IS_ERR(path))
		return NULL;

	memcpy(buffer, path_ptr, MIN(len, 1+strlen(path_ptr)));

	return buffer;
}

static int vsentry_path_unlink(struct path *path, struct dentry *dentry)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_path_rmdir(struct path *dir, struct dentry *dentry)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_path_symlink(struct path *dir, struct dentry *dentry, const char *old_name)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,unsigned int dev)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_path_rename(struct path *old_dir, struct dentry *old_dentry, struct path *new_dir,struct dentry *new_dentry)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_path_chown(struct path *old_dir,kuid_t uid,kgid_t gid)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static int vsentry_inode_follow_link(struct dentry *dentry, struct inode *inode, bool rcu)
#else
static int vsentry_inode_follow_link(struct dentry *dentry, struct nameidata *nd)
#endif
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_path_truncate(struct path *path)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_file_permission(struct file *file, int mask)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_file_alloc_security(struct file *file)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static void vsentry_file_free_security(struct file *file)
{
	if(hook_filter())
		return;

	return;
}

static int vsentry_file_ioctl(struct file *file, unsigned int cmd,unsigned long arg)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_mmap_addr(unsigned long addr)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_mmap_file(struct file *file, unsigned long reqport,unsigned long port,unsigned long flags)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_file_mprotect(struct vm_area_struct *vma, unsigned long reqport,unsigned long port)
{
	if(hook_filter())
		return 0;

	return 0;
}

static int vsentry_file_lock(struct file *file, unsigned int cmd)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_file_fcntl(struct file *file, unsigned int cmd,unsigned long arg)
{
	if(hook_filter())
		return 0;

	return 0;
}

static int vsentry_task_create(unsigned long clone_flags)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_kernel_module_request(char *kmod_name)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_task_setpgid(struct task_struct *p,pid_t pgid)
{
	if(hook_filter())
		return 0;

	return 0;
}

static int vsentry_task_setnice(struct task_struct *p,int nice)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_task_setrlimit(struct task_struct *p,unsigned int resource, struct rlimit *new_rlim)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_task_movememory(struct task_struct *p)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_task_kill(struct task_struct *p,struct siginfo *info, int sig, u32 secid)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static void vsentry_task_to_inode(struct task_struct *p,struct inode *inode)
{
	if(hook_filter())
		return;

	return;
}

#ifdef CONFIG_SECURITY_NETWORK
static int vsentry_unix_stream_connect(struct sock *sock,struct sock *other, struct sock *newsk)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_unix_may_send(struct socket *sock,struct socket *other)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

static int vsentry_socket_bind(struct socket *sock, struct sockaddr *address,int addrlen)
{
	if(hook_filter())
		return 0;
	
	return 0;
}

static int vsentry_socket_listen(struct socket *sock,int backlog)
{
	if(hook_filter())
		return 0;

	return 0;
}

#if 0 // testing shows that returning EACCESS will result in an endless loop of calling this hook.
      // moving this functionality to the netfilter incoming packet hook

static int vsentry_socket_accept(struct socket *sock,struct socket *newsock)
{
	sal_kernel_print_info("vsentry_socket_accept: Entry, %lx->%lx\n", sock, newsock);
	return -EACCES;
	if(hook_filter())
		return 0;

	return -EACCES;
}
#endif // 0

static int vsentry_socket_shutdown(struct socket *sock,int how)
{
	if(hook_filter())
		return 0;
	//TODO: handle permission for sys call
	return 0;
}
#endif /* CONFIG_SECURITY_NETWORK */

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static struct security_hook_list vsentry_security_hooks[VS_HOOK_MAX];
struct security_hook_heads *lsm_hook_head_ptr;

typedef struct {
	vsentry_hook_type vs_type;
	void* 	func_ptr;
} vs_hook_t;

static vs_hook_t vsentry_hooks[] = {
	{ VS_HOOK_SK_ALLOC_SECURITY, (void*)vsentry_sk_alloc_security },
	{ VS_HOOK_SK_FREE_SECURITY, (void*)vsentry_sk_free_security },
	{ VS_HOOK_BPRM_CHECK_SECURITY, (void*)vsentry_bprm_check_security },
#ifdef CONFIG_SECURITY_PATH
	{ VS_HOOK_PATH_UNLINK, (void*)vsentry_path_unlink },
	{ VS_HOOK_PATH_MKDIR, (void*)vsentry_path_mkdir },
	{ VS_HOOK_PATH_RMDIR, (void*)vsentry_path_rmdir },
	{ VS_HOOK_PATH_MKNOD, (void*)vsentry_path_mknod },
	{ VS_HOOK_PATH_TRUNCATE, (void*)vsentry_path_truncate },
	{ VS_HOOK_PATH_SYMLINK, (void*)vsentry_path_symlink },
	{ VS_HOOK_PATH_RENAME, (void*)vsentry_path_rename },
	{ VS_HOOK_PATH_CHMOD, (void*)vsentry_path_chmod },
	{ VS_HOOK_PATH_CHOWN, (void*)vsentry_path_chown },
#endif
	{ VS_HOOK_INODE_CREATE, (void*)vsentry_inode_create },
	{ VS_HOOK_INODE_LINK, (void*)vsentry_inode_link },
	{ VS_HOOK_INODE_UNLINK, (void*)vsentry_inode_unlink },
	{ VS_HOOK_INODE_SYMLINK, (void*)vsentry_inode_symlink },
	{ VS_HOOK_INODE_MKDIR, (void*)vsentry_inode_mkdir },
	{ VS_HOOK_INODE_RMDIR, (void*)vsentry_inode_rmdir },
	{ VS_HOOK_INODE_MKNOD, (void*)vsentry_inode_mknod },
	{ VS_HOOK_INODE_RENAME, (void*)vsentry_inode_rename },
	{ VS_HOOK_INODE_FOLLOW_LINK, (void*)vsentry_inode_follow_link },
	{ VS_HOOK_FILE_PERMISSION, (void*)vsentry_file_permission },
	{ VS_HOOK_FILE_ALLOC_SECURITY, (void*)vsentry_file_alloc_security },
	{ VS_HOOK_FILE_FREE_SECURITY, (void*)vsentry_file_free_security },
	{ VS_HOOK_FILE_IOCTL, (void*)vsentry_file_ioctl },
	{ VS_HOOK_MMAP_ADDR, (void*)vsentry_mmap_addr },
	{ VS_HOOK_MMAP_FILE, (void*)vsentry_mmap_file },
	{ VS_HOOK_FILE_MPROTECT, (void*)vsentry_file_mprotect },
	{ VS_HOOK_FILE_LOCK, (void*)vsentry_file_lock },
	{ VS_HOOK_FILE_FCNTL, (void*)vsentry_file_fcntl },
	{ VS_HOOK_FILE_OPEN, (void*)vsentry_file_open },
	{ VS_HOOK_TASK_CREATE, (void*)vsentry_task_create },
	{ VS_HOOK_TASK_FREE, (void*)vsentry_task_free },
	{ VS_HOOK_KERNEL_MODULE_REQUEST, (void*)vsentry_kernel_module_request },
	{ VS_HOOK_TASK_SETPGID, (void*)vsentry_task_setpgid },
	{ VS_HOOK_TASK_SETNICE, (void*)vsentry_task_setnice },
	{ VS_HOOK_TASK_SETRLIMIT, (void*)vsentry_task_setrlimit },
	{ VS_HOOK_TASK_MOVEMEMORY, (void*)vsentry_task_movememory },
	{ VS_HOOK_TASK_KILL, (void*)vsentry_task_kill },
	{ VS_HOOK_TASK_TO_INODE, (void*)vsentry_task_to_inode },
#ifdef CONFIG_SECURITY_NETWORK
	{ VS_HOOK_UNIX_STREAM_CONNECT, (void*)vsentry_unix_stream_connect },
	{ VS_HOOK_UNIX_MAY_SEND, (void*)vsentry_unix_may_send },
	{ VS_HOOK_SOCKET_CREATE, (void*)vsentry_socket_create },
#ifdef CONFIG_STAT_ANALYSIS
	{ VS_HOOK_INET_CONN_ESTABLISHED, (void*)vsentry_inet_conn_established },
	{ VS_HOOK_INET_CONN_REQUEST, (void*)vsentry_inet_conn_request },
#endif
	{ VS_HOOK_SOCKET_BIND, (void*)vsentry_socket_bind },
	{ VS_HOOK_SOCKET_CONNECT, (void*)vsentry_socket_connect },
	{ VS_HOOK_SOCKET_LISTEN, (void*)vsentry_socket_listen },
	//{ VS_HOOK_SOCKET_ACCEPT, (void*)vsentry_socket_accept },
	{ VS_HOOK_SOCKET_SENDMSG, (void*)vsentry_socket_sendmsg },
	{ VS_HOOK_SOCKET_RECVMSG, (void*)vsentry_socket_recvmsg },
	{ VS_HOOK_SOCKET_SHUTDOWN, (void*)vsentry_socket_shutdown },
	{ VS_HOOK_SOCKET_SOCK_RCV_SKB, (void*)vsentry_socket_sock_rcv_skb },
#endif  /* CONFIG_SECURITY_NETWORK */
};

void init_vsentry_hooks(int type, void* func_ptr)
{
	switch (type) {
	case VS_HOOK_BPRM_CHECK_SECURITY:
		vsentry_security_hooks[type].hook.path_unlink = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->bprm_check_security;
		break;
	case VS_HOOK_PATH_UNLINK:
		vsentry_security_hooks[type].hook.path_unlink = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_unlink;
		break;
	case VS_HOOK_PATH_MKDIR:
		vsentry_security_hooks[type].hook.path_mkdir = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_mkdir;
		break;
	case VS_HOOK_PATH_RMDIR:
		vsentry_security_hooks[type].hook.path_rmdir = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_rmdir;
		break;
	case VS_HOOK_PATH_MKNOD:
		vsentry_security_hooks[type].hook.path_mknod = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_mknod;
		break;
	case VS_HOOK_PATH_TRUNCATE:
		vsentry_security_hooks[type].hook.path_truncate= func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_truncate;
		break;
	case VS_HOOK_PATH_SYMLINK:
		vsentry_security_hooks[type].hook.path_symlink = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_symlink;
		break;
	case VS_HOOK_PATH_RENAME:
		vsentry_security_hooks[type].hook.path_rename = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_rename;
		break;
	case VS_HOOK_PATH_CHMOD:
		vsentry_security_hooks[type].hook.path_chmod = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_chmod;
		break;
	case VS_HOOK_PATH_CHOWN:
		vsentry_security_hooks[type].hook.path_chown = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->path_chown;
		break;
	case VS_HOOK_INODE_CREATE:
		vsentry_security_hooks[type].hook.inode_create = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_create;
		break;
	case VS_HOOK_INODE_LINK:
		vsentry_security_hooks[type].hook.inode_link = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_link;
		break;
	case VS_HOOK_INODE_UNLINK:
		vsentry_security_hooks[type].hook.inode_unlink = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_unlink;
		break;
	case VS_HOOK_INODE_SYMLINK:
		vsentry_security_hooks[type].hook.inode_symlink = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_symlink;
		break;
	case VS_HOOK_INODE_MKDIR:
		vsentry_security_hooks[type].hook.inode_mkdir = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_mkdir;
		break;
	case VS_HOOK_INODE_RMDIR:
		vsentry_security_hooks[type].hook.inode_rmdir = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_rmdir;
		break;
	case VS_HOOK_INODE_MKNOD:
		vsentry_security_hooks[type].hook.inode_mknod = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_mknod;
		break;
	case VS_HOOK_INODE_RENAME:
		vsentry_security_hooks[type].hook.inode_rename = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_rename;
		break;
	case VS_HOOK_INODE_FOLLOW_LINK:
		vsentry_security_hooks[type].hook.inode_follow_link = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inode_follow_link;
	case VS_HOOK_FILE_PERMISSION:
		vsentry_security_hooks[type].hook.file_permission = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->file_permission;
		break;
	case VS_HOOK_FILE_ALLOC_SECURITY:
		vsentry_security_hooks[type].hook.file_alloc_security = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->file_alloc_security;
		break;
	case VS_HOOK_FILE_FREE_SECURITY:
		vsentry_security_hooks[type].hook.file_free_security = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->file_free_security;
		break;
	case VS_HOOK_FILE_IOCTL:
		vsentry_security_hooks[type].hook.file_ioctl = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->file_ioctl;
		break;
	case VS_HOOK_MMAP_ADDR:
		vsentry_security_hooks[type].hook.mmap_addr = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->mmap_addr;
		break;
	case VS_HOOK_MMAP_FILE:
		vsentry_security_hooks[type].hook.mmap_file = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->mmap_file;
		break;
	case VS_HOOK_FILE_MPROTECT:
		vsentry_security_hooks[type].hook.file_mprotect = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->file_mprotect;
		break;
	case VS_HOOK_FILE_LOCK:
		vsentry_security_hooks[type].hook.file_lock = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->file_lock;
		break;
	case VS_HOOK_FILE_FCNTL:
		vsentry_security_hooks[type].hook.file_fcntl = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->file_fcntl;
		break;
	case VS_HOOK_FILE_OPEN:
		vsentry_security_hooks[type].hook.file_open = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->file_open;
		break;
	case VS_HOOK_TASK_CREATE:
		vsentry_security_hooks[type].hook.task_create = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->task_create;
		break;
	case VS_HOOK_TASK_FREE:
		vsentry_security_hooks[type].hook.task_free = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->task_free;
		break;
	case VS_HOOK_KERNEL_MODULE_REQUEST:
		vsentry_security_hooks[type].hook.kernel_module_request = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->kernel_module_request;
		break;
	case VS_HOOK_TASK_SETPGID:
		vsentry_security_hooks[type].hook.task_setpgid = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->task_setpgid;
		break;
	case VS_HOOK_TASK_SETNICE:
		vsentry_security_hooks[type].hook.task_setnice = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->task_setnice;
		break;
	case VS_HOOK_TASK_SETRLIMIT:
		vsentry_security_hooks[type].hook.task_setrlimit = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->task_setrlimit;
		break;
	case VS_HOOK_TASK_MOVEMEMORY:
		vsentry_security_hooks[type].hook.task_movememory = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->task_movememory;
		break;
	case VS_HOOK_TASK_KILL:
		vsentry_security_hooks[type].hook.task_kill = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->task_kill;
		break;
	case VS_HOOK_TASK_TO_INODE:
		vsentry_security_hooks[type].hook.task_to_inode = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->task_to_inode;
		break;
	case VS_HOOK_UNIX_STREAM_CONNECT:
		vsentry_security_hooks[type].hook.unix_stream_connect = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->unix_stream_connect;
		break;
	case VS_HOOK_UNIX_MAY_SEND:
		vsentry_security_hooks[type].hook.unix_may_send = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->unix_may_send;
		break;
	case VS_HOOK_SOCKET_CREATE:
		vsentry_security_hooks[type].hook.socket_create = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_create;
		break;
#ifdef CONFIG_STAT_ANALYSIS
	case VS_HOOK_INET_CONN_ESTABLISHED:
		vsentry_security_hooks[type].hook.inet_conn_established = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inet_conn_established;
		break;
	case VS_HOOK_INET_CONN_REQUEST:
		vsentry_security_hooks[type].hook.inet_conn_request = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->inet_conn_request;
		break;
#endif
	case VS_HOOK_SOCKET_BIND:
		vsentry_security_hooks[type].hook.socket_bind = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_bind;
		break;
	case VS_HOOK_SOCKET_CONNECT:
		vsentry_security_hooks[type].hook.socket_connect = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_connect;
		break;
	case VS_HOOK_SOCKET_LISTEN:
		vsentry_security_hooks[type].hook.socket_listen = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_listen;
		break;
	case VS_HOOK_SOCKET_ACCEPT:
		vsentry_security_hooks[type].hook.socket_accept = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_accept;
		break;
	case VS_HOOK_SOCKET_SENDMSG:
		vsentry_security_hooks[type].hook.socket_sendmsg = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_sendmsg;
		break;
	case VS_HOOK_SOCKET_RECVMSG:
		vsentry_security_hooks[type].hook.socket_recvmsg = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_recvmsg;
		break;
	case VS_HOOK_SOCKET_SHUTDOWN:
		vsentry_security_hooks[type].hook.socket_shutdown = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_shutdown;
		break;
	case VS_HOOK_SOCKET_SOCK_RCV_SKB:
		vsentry_security_hooks[type].hook.socket_sock_rcv_skb = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->socket_sock_rcv_skb;
		break;
	case VS_HOOK_SK_ALLOC_SECURITY:
		vsentry_security_hooks[type].hook.sk_alloc_security = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->sk_alloc_security;
		break;
	case VS_HOOK_SK_FREE_SECURITY:
		vsentry_security_hooks[type].hook.sk_free_security = func_ptr;
		vsentry_security_hooks[type].head = &lsm_hook_head_ptr->sk_free_security;
		break;

	default:
		pr_err("this hook type is not supported [%d]\n", type);
		break;
	}
}

#else

void init_vsentry_hooks(struct security_operations *ops)
{
	memset(ops->name, 0, SECURITY_NAME_MAX+1);
	memcpy(ops->name, "vsentry", 7);
#ifdef CONFIG_SECURITY_PATH
	ops->path_unlink =			vsentry_path_unlink;
	ops->path_symlink =			vsentry_path_symlink;
	ops->path_mkdir =			vsentry_path_mkdir;
	ops->path_rmdir =			vsentry_path_rmdir;
	ops->path_rename =			vsentry_path_rename;
	ops->path_chmod =			vsentry_path_chmod;
	ops->path_chown = 			vsentry_path_chown;
	ops->path_mknod = 			vsentry_path_mknod;
	ops->path_truncate = 		vsentry_path_truncate;
#endif
	ops->inode_link =			vsentry_inode_link;
	ops->inode_unlink =			vsentry_inode_unlink;
	ops->inode_symlink =		vsentry_inode_symlink;
	ops->inode_mkdir =			vsentry_inode_mkdir;
	ops->inode_rmdir =			vsentry_inode_rmdir;
	ops->inode_create =			vsentry_inode_create;
	ops->inode_rename =			vsentry_inode_rename;
	ops->inode_follow_link =	vsentry_inode_follow_link;
	ops->inode_mknod = 			vsentry_inode_mknod;
	ops->file_open = 			vsentry_file_open;
	ops->file_permission = 		vsentry_file_permission;
	ops->file_alloc_security = 	vsentry_file_alloc_security;
	ops->file_free_security = 	vsentry_file_free_security;
	ops->file_ioctl = 			vsentry_file_ioctl;
	ops->file_mprotect = 		vsentry_file_mprotect;
	ops->file_lock = 			vsentry_file_lock;
	ops->file_fcntl = 			vsentry_file_fcntl;
	ops->mmap_addr = 			vsentry_mmap_addr;
	ops->mmap_file = 			vsentry_mmap_file;
	ops->task_create = 			vsentry_task_create;
	ops->task_free = 			vsentry_task_free;
	ops->task_setpgid = 		vsentry_task_setpgid;
	ops->task_setnice = 		vsentry_task_setnice;
	ops->task_setrlimit = 		vsentry_task_setrlimit;
	ops->task_movememory = 		vsentry_task_movememory;
	ops->task_kill = 			vsentry_task_kill;
	ops->task_to_inode = 		vsentry_task_to_inode;
	ops->kernel_module_request=	vsentry_kernel_module_request;
#ifdef CONFIG_SECURITY_NETWORK
	ops->socket_connect = 		vsentry_socket_connect;
	ops->unix_stream_connect = 	vsentry_unix_stream_connect;
	ops->unix_may_send = 		vsentry_unix_may_send;
	ops->socket_create = 		vsentry_socket_create;
#ifdef CONFIG_STAT_ANALYSIS
	ops->inet_conn_established = vsentry_inet_conn_established;
	ops->inet_conn_request = vsentry_inet_conn_request;
#endif
	ops->socket_bind = 			vsentry_socket_bind;
	ops->socket_listen = 		vsentry_socket_listen;
	//ops->socket_accept = 		vsentry_socket_accept;
	ops->socket_sendmsg = 		vsentry_socket_sendmsg;
	ops->socket_recvmsg = 		vsentry_socket_recvmsg;
	ops->socket_sock_rcv_skb = 	vsentry_socket_sock_rcv_skb;
	ops->socket_shutdown = 		vsentry_socket_shutdown;
#endif

}
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)*/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static void vsentry_security_delete_hooks(void)
{
	int i;

	for (i = 0; i < VS_HOOK_MAX; i++) {
		if (vsentry_security_hooks[i].head)
			list_del_rcu(&vsentry_security_hooks[i].list);
	}
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(4,2,0)
struct security_operations default_security_ops;
#endif

int register_lsm_hooks (void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	unsigned long addr;
	int i;

	addr = kallsyms_lookup_name("security_hook_heads");
	if (!addr) {
		pr_err("%s: failed to get security_hook_heads address\n", __func__);
		return -EFAULT;
	}

	lsm_hook_head_ptr = (struct security_hook_heads *)addr;
	memset(vsentry_security_hooks, 0, sizeof(vsentry_security_hooks));
	for (i=0; i<ARRAY_SIZE(vsentry_hooks); i++)
		init_vsentry_hooks(vsentry_hooks[i].vs_type,
			vsentry_hooks[i].func_ptr);

	for (i=0; i<VS_HOOK_MAX; i++) {
		if (vsentry_security_hooks[i].head)
			list_add_tail_rcu(&vsentry_security_hooks[i].list,
				vsentry_security_hooks[i].head);
	}

#else
	struct security_operations* default_security_ops_ptr;
	void (*reset_security_ops_func)(void);

	default_security_ops_ptr = (struct security_operations*)kallsyms_lookup_name("default_security_ops");
	if (!default_security_ops_ptr) {
		pr_err("%s: failed to get security_ops address\n", __func__);
		return -EFAULT;
	}

	reset_security_ops_func = (void*)kallsyms_lookup_name("reset_security_ops");
	if (!reset_security_ops_func) {
		pr_err("%s: failed to get reset_security_ops address\n", __func__);
		return -EFAULT;
	}

	memcpy(&default_security_ops, default_security_ops_ptr, sizeof(default_security_ops));
	init_vsentry_hooks(default_security_ops_ptr);

	reset_security_ops_func();
#endif

	return 0;
}

int unregister_lsm_hooks (void)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	vsentry_security_delete_hooks();
#else
	struct security_operations* default_security_ops_ptr;
	void (*reset_security_ops_func)(void);

	default_security_ops_ptr = (struct security_operations*)kallsyms_lookup_name("default_security_ops");
	if (!default_security_ops_ptr) {
		pr_err("%s: failed to get security_ops address\n", __func__);
		return -EFAULT;
	}

	reset_security_ops_func = (void*)kallsyms_lookup_name("reset_security_ops");
	if (!reset_security_ops_func) {
		pr_err("%s: failed to get reset_security_ops address\n", __func__);
		return -EFAULT;
	}

	memcpy(default_security_ops_ptr, &default_security_ops, sizeof(default_security_ops));

	reset_security_ops_func();	
#endif
	return 0;
}
