/* file: sr_lsm_hooks.c
 * purpose: this file registering the vsentry hooks into the linux os sys_calls
*/
#include "sr_lsm_hooks.h"
#include "dispatcher.h"
#include "sr_sal_common.h"
#include "event_mediator.h"

/* Supported address families. */
/*
const char static *address_family[] = {"AF_UNSPEC",	
									   "AF_UNIX",		
									   "AF_LOCAL",	
									   "AF_INET",		
									   "AF_AX25",		
									   "AF_IPX",		
									   "AF_APPLETALK",
									   "AF_NETROM",	
									   "AF_BRIDGE",	
									   "AF_ATMPVC",	
									   "AF_X25",		
									   "AF_INET6",	
									   "AF_ROSE",		
									   "AF_DECnet",	
									   "AF_NETBEUI",	
									   "AF_SECURITY",	
									   "AF_KEY",		
									   "AF_NETLINK",	
									   "AF_ROUTE",	
									   "AF_PACKET",	
									   "AF_ASH",		
									   "AF_ECONET",	
									   "AF_ATMSVC",	
									   "AF_RDS",		
									   "AF_SNA",		
									   "AF_IRDA",		
									   "AF_PPPOX",	
									   "AF_WANPIPE",	
									   "AF_LLC",		
									   "AF_IB",		
									   "AF_MPLS",		
									   "AF_CAN",		
									   "AF_TIPC",		
									   "AF_BLUETOOTH",
									   "AF_IUCV",		
									   "AF_RXRPC",	
									   "AF_ISDN",		
									   "AF_PHONET",	
									   "AF_IEEE802154",
									   "AF_CAIF",		
									   "AF_ALG",		 
									   "AF_NFC",		 
									   "AF_VSOCK",	 
									   "AF_KCM",		 
									   "AF_QIPCRTR",	 
									   "AF_SMC",
									   "AF_MAX"
									   };*/
/* Protocol families, same as address families. */
const static char *protocol_family[] = {//"PF_UNSPEC",	
										"PF_UNIX",		
										"PF_LOCAL",	
										"PF_INET",		
										"PF_AX25",		
										"PF_IPX",		
										"PF_APPLETALK",
										"PF_NETROM",	
										"PF_BRIDGE",	
										"PF_ATMPVC",	
										"PF_X25",		
										"PF_INET6",	
										"PF_ROSE",		
										"PF_DECnet",	
										"PF_NETBEUI",	
										"PF_SECURITY",	
										"PF_KEY",		
										"PF_NETLINK",	
//										"PF_ROUTE",	
										"PF_PACKET",	
										"PF_ASH",		
										"PF_ECONET",	
										"PF_ATMSVC",	
										"PF_RDS",		
										"PF_SNA",		
										"PF_IRDA",		
										"PF_PPPOX",	
										"PF_WANPIPE",	
										"PF_LLC",		
										"PF_IB",		
										"PF_MPLS",		
										"PF_CAN",		
										"PF_TIPC",		
										"PF_BLUETOOTH",
										"PF_IUCV",		
										"PF_RXRPC",	
										"PF_ISDN",		
										"PF_PHONET",	
										"PF_IEEE802154",
										"PF_CAIF",		
										"PF_ALG",		
										"PF_NFC",		
										"PF_VSOCK",	
										"PF_KCM",		
										"PF_QIPCRTR",	
										"PF_SMC",		
										"PF_MAX"
										};

extern int sr_vsentryd_pid;

/*implement filter for our sr-engine */
int hook_filter(void)
{
	/*if the statement is true in means the SYS_CALL invoked by sr-engine */
	if ((sr_vsentryd_pid) == (current->pid)-1)
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
	char path[SR_disp_MAX_PATH_SIZE], *path_ptr;

	path_ptr = dentry_path_raw(dentry, path, SR_disp_MAX_PATH_SIZE);
	if (IS_ERR(path))
		return NULL;

	memcpy(buffer, path_ptr, MIN(len, 1+strlen(path_ptr)));

	return buffer;
}

static int vsentry_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	disp_info_t em;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter())
		return 0;

	strncpy(em.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(em.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(em.fileinfo.filename, old_dentry->d_iname,
		MIN(sizeof(em.fileinfo.filename), 1+strlen(old_dentry->d_iname)));
	get_path(new_dentry, em.fileinfo.fullpath, sizeof(em.fileinfo.fullpath));
	get_path(old_dentry, em.fileinfo.old_path, sizeof(em.fileinfo.old_path));

	em.fileinfo.id.gid = (int)rcred->gid.val;
	em.fileinfo.id.tid = (int)rcred->uid.val;
	em.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (disp_inode_link(&em));
}

static int vsentry_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	disp_info_t em;
	
	struct task_struct *ts = current;
	const struct cred *rcred = ts->real_cred;		
	
	if(hook_filter())
		return 0;
	
	strncpy(em.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(em.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(em.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(em.fileinfo.filename), 1+strlen(dentry->d_iname)));
	get_path(dentry, em.fileinfo.fullpath, sizeof(em.fileinfo.fullpath));

	em.fileinfo.id.gid = (int)rcred->gid.val;
	em.fileinfo.id.tid = (int)rcred->uid.val;
	em.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (disp_inode_unlink(&em));
}

static int vsentry_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name)
{
	disp_info_t em;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter())
		return 0;
	
	strncpy(em.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(em.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(em.fileinfo.filename, (char *)name,
		MIN(sizeof(em.fileinfo.filename), 1+strlen(name)));
	get_path(dentry, em.fileinfo.fullpath, sizeof(em.fileinfo.fullpath));

	em.fileinfo.id.gid = (int)rcred->gid.val;
	em.fileinfo.id.tid = (int)rcred->uid.val;
	em.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (disp_inode_symlink(&em));
}

static int vsentry_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	disp_info_t em;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter())
		return 0;

	strncpy(em.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(em.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(em.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(em.fileinfo.filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, em.fileinfo.fullpath, sizeof(em.fileinfo.fullpath));

	em.fileinfo.id.gid = (int)rcred->gid.val;
	em.fileinfo.id.tid = (int)rcred->uid.val;
	em.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (disp_rmdir(&em));
}

static int vsentry_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen)
{
	disp_info_t em;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	struct sockaddr_in *ipv4;
	
	if(hook_filter())
		return 0;
	
	ipv4 = (struct sockaddr_in *)address;
	strncpy(em.address_info.id.event_name, __FUNCTION__,
		MIN(sizeof(em.address_info.id.event_name), 1+strlen(__FUNCTION__)));
	parse_sinaddr(ipv4->sin_addr, em.address_info.ipv4, sizeof(em.address_info.ipv4));
	em.address_info.port = (int)ntohs(ipv4->sin_port);	
	em.address_info.id.gid = (int)rcred->gid.val;
	em.address_info.id.tid = (int)rcred->uid.val;
	em.address_info.id.pid = current->pid;

	//TODO: handle permission for sys call
	return (disp_socket_connect(&em));
}


static int vsentry_path_chmod(struct path *path, umode_t mode)
{
	disp_info_t em;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter())
		return 0;
	
	strncpy(em.fileinfo.id.event_name,__FUNCTION__,
		MIN(sizeof(em.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	get_path(path->dentry, em.fileinfo.fullpath, sizeof(em.fileinfo.fullpath));
	em.fileinfo.id.gid = (int)rcred->gid.val;
	em.fileinfo.id.tid = (int)rcred->uid.val;
	em.fileinfo.id.pid = current->pid;

	//TODO: handle permission for sys call
	return (disp_path_chmod(&em));
}

static int vsentry_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	disp_info_t em;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter())
		return 0;

	strncpy(em.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(em.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(em.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(em.fileinfo.filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, em.fileinfo.fullpath, sizeof(em.fileinfo.fullpath));
	em.fileinfo.id.gid = (int)rcred->gid.val;
	em.fileinfo.id.tid = (int)rcred->uid.val;
	em.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (disp_inode_create(&em));
}

__attribute__ ((unused))
static int vsentry_file_open(struct file *file, const struct cred *cred)
{
	disp_info_t em;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	
	if(hook_filter())
		return 0;	

	strncpy(em.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(em.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	get_path(file->f_path.dentry, em.fileinfo.filename, sizeof(em.fileinfo.filename));

	em.fileinfo.id.gid = (int)rcred->gid.val;
	em.fileinfo.id.tid = (int)rcred->uid.val;
	em.fileinfo.id.pid = current->pid;

	//TODO: handle permission for sys call
	return (disp_file_open(&em));
}

__attribute__ ((unused))
static void vsentry_bprm_committing_creds(struct linux_binprm *bprm)
{
	if(hook_filter())
		return;

	return;
}

__attribute__ ((unused))
static int vsentry_path_unlink(struct path *path, struct dentry *dentry)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode)
{
	if(hook_filter())
		return 0;

	printk("%s CALLED\n",__FUNCTION__);
	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_rmdir(struct path *dir, struct dentry *dentry)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_symlink(struct path *dir, struct dentry *dentry, const char *old_name)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,unsigned int dev)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,struct dentry *new_dentry)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_rename(struct path *old_dir, struct dentry *old_dentry, struct path *new_dir,struct dentry *new_dentry)
{
	if(hook_filter())
		return 0;
	
	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_chown(struct path *old_dir,kuid_t uid,kgid_t gid)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_chroot(struct path *old_dir,kuid_t uid,kgid_t gid)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_inode_readlink(struct dentry *dentry)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_inode_follow_link(struct dentry *dentry, struct inode *inode, bool rcu)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_truncate(struct path *path)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_file_permission(struct file *file, int mask)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_file_alloc_security(struct file *file)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_file_free_security(struct file *file)
{
	if(hook_filter())
		return;

	return;
}

__attribute__ ((unused))
static int vsentry_file_ioctl(struct file *file, unsigned int cmd,unsigned long arg)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_mmap_addr(unsigned long addr)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_mmap_file(struct file *file, unsigned long reqport,unsigned long port,unsigned long flags)
{
	if(hook_filter())
return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_file_mprotect(struct vm_area_struct *vma, unsigned long reqport,unsigned long port)
{
	if(hook_filter())
		return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_file_lock(struct file *file, unsigned int cmd)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_file_fcntl(struct file *file, unsigned int cmd,unsigned long arg)
{
	if(hook_filter())
		return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_task_create(unsigned long clone_flags)
{
	if(hook_filter())
return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_task_free(struct task_struct *task)
{
	if(hook_filter())
		return;

	return;
}

__attribute__ ((unused))
static int vsentry_kernel_fw_from_file(struct file *file,char * buf,size_t size)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_kernel_module_request(char *kmod_name)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_kernel_module_from_file(struct file *file)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_fix_setuid(struct cred *new, const struct cred *old, int flags)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_setpgid(struct task_struct *p,pid_t pgid)
{
	if(hook_filter())
		return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_task_setnice(struct task_struct *p,int nice)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_setrlimit(struct task_struct *p,unsigned int resource, struct rlimit *new_rlim)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_movememory(struct task_struct *p)
{
	if(hook_filter())
		return 0;
	
	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_kill(struct task_struct *p,struct siginfo *info, int sig, u32 secid)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_task_to_inode(struct task_struct *p,struct inode *inode)
{
	if(hook_filter())
		return;

	return;
}

__attribute__ ((unused))
static int vsentry_unix_stream_connect(struct sock *sock,struct sock *other, struct sock *newsk)
{
	if(hook_filter())
		return 0;
	
	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_unix_may_send(struct socket *sock,struct socket *other)
{
	if(hook_filter())
		return 0;
	
	//TODO: handle permission for sys call
	return 0;
}
/*
 * @socket_create:
 *	Check permissions prior to creating a new socket.
 *	@family contains the requested protocol family.
 *	@type contains the requested communications type.
 *	@protocol contains the requested protocol.
 *	@kern set to 1 if a kernel socket.
 */
static int vsentry_socket_create(int family, int type, int protocol, int kern)
{
	disp_info_t em;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter())
		return 0;	
	
	strncpy(em.socket_info.id.event_name, __FUNCTION__,
		MIN(sizeof(em.socket_info.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(em.socket_info.family, protocol_family[family],
		MIN(sizeof(em.socket_info.family), 1+strlen(protocol_family[family])));
	sprintf(em.socket_info.type,"socket type: %d",type);
		
	em.socket_info.protocol = protocol;
	em.socket_info.kern = kern;
	
	em.socket_info.id.gid = (int)rcred->gid.val;
	em.socket_info.id.tid = (int)rcred->uid.val;
	em.socket_info.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (disp_socket_create(&em));
}

__attribute__ ((unused))
static int vsentry_socket_bind(struct socket *sock, struct sockaddr *address,int addrlen)
{
	if(hook_filter())
		return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_socket_listen(struct socket *sock,int backlog)
{
	if(hook_filter())
		return 0;
	
	return 0;
}

__attribute__ ((unused))
static int vsentry_socket_accept(struct socket *sock,struct socket *newsock)
{
	if(hook_filter())
		return 0;

	return 0;
}

/* @socket_sendmsg:
 *	Check permission before transmitting a message to another socket.
 *	@sock contains the socket structure.
 *	@msg contains the message to be transmitted.
 *	@size contains the size of message.
 *	Return 0 if permission is granted.
 */
__attribute__ ((unused))
static int vsentry_socket_sendmsg(struct socket *sock,struct msghdr *msg,int size)
{
	if(hook_filter())
		return 0;

	return 0;
}

/* @socket_recvmsg:
 *	Check permission before receiving a message from a socket.
 *	@sock contains the socket structure.
 *	@msg contains the message structure.
 *	@size contains the size of message structure.
 *	@flags contains the operational flags.
 *	Return 0 if permission is granted.
 */
__attribute__ ((unused))
static int vsentry_socket_recvmsg(struct socket *sock,struct msghdr *msg,int size,int flags)
{
	if(hook_filter())
		return 0;
	
	if (current->pid == 0)
		printk(KERN_INFO"%s PID: %d\n",__FUNCTION__,current->pid);

	return 0;
}

static int vsentry_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_socket_shutdown(struct socket *sock,int how)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_sk_alloc_security(struct socket *sk,int family, gfp_t priority)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_sk_free_security(struct socket *sk)
{
	if(hook_filter())
		return;

	return;
}

__attribute__ ((unused))
static void vsentry_sk_clone_security(struct socket *sk,struct sock *newsk)
{
	if(hook_filter())
		return;

	return;
}

__attribute__ ((unused))
static int vsentry_shm_alloc_security(struct shmid_kernel *shp)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_shm_free_security(struct shmid_kernel *shp)
{
	if(hook_filter())
		return;

	return;
}

__attribute__ ((unused))
static int vsentry_shm_associate(struct shmid_kernel *shp, int shmflg)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_shm_shmctl(struct shmid_kernel *shp, int cmd)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,int shmflg)
{
	if(hook_filter())
		return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_ptrace_access_check(struct task_struct *child,unsigned int mode)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_ptrace_traceme(struct task_struct *parent)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_syslog(int type)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_settime(const struct timespec64 *ts, const struct timezone *tz)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_vm_enough_memory(struct mm_struct *mm, long pages)
{
	if(hook_filter())
		return 0;

	//TODO: handle permission for sys call
	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static struct security_hook_list vsentry_hooks[] = {

	LSM_HOOK_INIT(path_unlink, vsentry_path_unlink),
	LSM_HOOK_INIT(path_symlink, vsentry_path_symlink),
	LSM_HOOK_INIT(path_mkdir, vsentry_path_mkdir),
	LSM_HOOK_INIT(path_rmdir, vsentry_path_rmdir),
	LSM_HOOK_INIT(path_chmod, vsentry_path_chmod),
	LSM_HOOK_INIT(path_mknod, vsentry_path_mknod),
	LSM_HOOK_INIT(path_rename, vsentry_path_rename),
	LSM_HOOK_INIT(path_chown, vsentry_path_chown),
	//LSM_HOOK_INIT(path_chroot, vsentry_path_chroot),
	LSM_HOOK_INIT(path_truncate, vsentry_path_truncate),

	LSM_HOOK_INIT(inode_link, vsentry_inode_link),
	LSM_HOOK_INIT(inode_unlink, vsentry_inode_unlink),
	LSM_HOOK_INIT(inode_symlink, vsentry_inode_symlink),
	LSM_HOOK_INIT(inode_mkdir, vsentry_inode_mkdir),
	LSM_HOOK_INIT(inode_rmdir, vsentry_inode_rmdir),
	LSM_HOOK_INIT(inode_create, vsentry_inode_create),
	LSM_HOOK_INIT(inode_mknod, vsentry_inode_mknod),
	LSM_HOOK_INIT(inode_rename, vsentry_inode_rename),
	//LSM_HOOK_INIT(inode_readlink, vsentry_inode_readlink),
	//LSM_HOOK_INIT(inode_follow_link, vsentry_inode_follow_link),
#if(1)
	LSM_HOOK_INIT(file_open, vsentry_file_open),
	LSM_HOOK_INIT(file_permission, vsentry_file_permission),
	LSM_HOOK_INIT(file_alloc_security, vsentry_file_alloc_security),
	LSM_HOOK_INIT(file_free_security, vsentry_file_free_security),
	LSM_HOOK_INIT(file_ioctl, vsentry_file_ioctl),
	LSM_HOOK_INIT(file_mprotect, vsentry_file_mprotect),
	LSM_HOOK_INIT(file_lock, vsentry_file_lock),
	LSM_HOOK_INIT(file_fcntl, vsentry_file_fcntl),

	LSM_HOOK_INIT(mmap_addr, vsentry_mmap_addr),
	LSM_HOOK_INIT(mmap_file, vsentry_mmap_file),

	LSM_HOOK_INIT(task_create, vsentry_task_create),
	LSM_HOOK_INIT(task_free, vsentry_task_free),
	LSM_HOOK_INIT(task_fix_setuid, vsentry_task_fix_setuid),
	LSM_HOOK_INIT(task_setpgid, vsentry_task_setpgid),
	LSM_HOOK_INIT(task_setnice, vsentry_task_setnice),
	LSM_HOOK_INIT(task_setrlimit, vsentry_task_setrlimit),
	LSM_HOOK_INIT(task_movememory, vsentry_task_movememory),
	LSM_HOOK_INIT(task_kill, vsentry_task_kill),
	LSM_HOOK_INIT(task_to_inode, vsentry_task_to_inode),

	LSM_HOOK_INIT(unix_stream_connect, vsentry_unix_stream_connect),
	LSM_HOOK_INIT(unix_may_send, vsentry_unix_may_send),
#endif
	
	//LSM_HOOK_INIT(kernel_fw_from_file, vsentry_kernel_fw_from_file), //not in every kern version
	LSM_HOOK_INIT(kernel_module_request, vsentry_kernel_module_request),
	//LSM_HOOK_INIT(kernel_module_from_file, vsentry_kernel_module_from_file), //not in every kern version

	LSM_HOOK_INIT(socket_connect, vsentry_socket_connect),
	LSM_HOOK_INIT(socket_create, vsentry_socket_create),
	LSM_HOOK_INIT(socket_bind, vsentry_socket_bind),
	LSM_HOOK_INIT(socket_listen, vsentry_socket_listen),
	LSM_HOOK_INIT(socket_accept, vsentry_socket_accept),
	LSM_HOOK_INIT(socket_sendmsg, vsentry_socket_sendmsg),
	LSM_HOOK_INIT(socket_recvmsg, vsentry_socket_recvmsg),
	LSM_HOOK_INIT(socket_shutdown, vsentry_socket_shutdown),
	LSM_HOOK_INIT(socket_sock_rcv_skb,vsentry_socket_sock_rcv_skb),

	//LSM_HOOK_INIT(sk_alloc_security, vsentry_sk_alloc_security),
	//LSM_HOOK_INIT(sk_free_security, vsentry_sk_free_security),
	//LSM_HOOK_INIT(sk_clone_security, vsentry_sk_clone_security),

	//LSM_HOOK_INIT(shm_alloc_security, vsentry_shm_alloc_security),
	//LSM_HOOK_INIT(shm_free_security, vsentry_shm_free_security),
	//LSM_HOOK_INIT(shm_associate, vsentry_shm_associate),
	//LSM_HOOK_INIT(shm_shmctl, vsentry_shm_shmctl),
	//LSM_HOOK_INIT(shm_shmat, vsentry_shm_shmat),

	//LSM_HOOK_INIT(ptrace_access_check, vsentry_ptrace_access_check),
	//LSM_HOOK_INIT(ptrace_traceme, vsentry_ptrace_traceme),

	//LSM_HOOK_INIT(syslog, vsentry_syslog),
	LSM_HOOK_INIT(settime, vsentry_settime),
	//LSM_HOOK_INIT(vm_enough_memory, vsentry_vm_enough_memory),
	
	//LSM_HOOK_INIT(bprm_committing_creds, vsentry_bprm_committing_creds), 
};
#else
static struct security_operations vsentry_ops = {

	.path_unlink =				vsentry_path_unlink,
	.path_symlink =				vsentry_path_symlink,
	.path_mkdir = 				vsentry_path_mkdir,
	.path_rmdir = 				vsentry_path_rmdir,
	//.path_mknod =				vsentry_path_mknod,
	.path_rename =				vsentry_path_rename,	
	.path_chmod =		 		vsentry_path_chmod,
	//.path_chown =				vsentry_path_chown,
	//.path_chroot =			vsentry_path_chroot,
	//.path_truncate =			vsentry_path_truncate,

	.inode_link =				vsentry_inode_link,
	.inode_unlink =				vsentry_inode_unlink,
	.inode_symlink =			vsentry_inode_symlink,
	.inode_mkdir =				vsentry_inode_mkdir,
	.inode_rmdir =				vsentry_inode_rmdir,
	.inode_create =		 		vsentry_inode_create,
	//.inode_mknod =			vsentry_inode_mknod,
	.inode_rename =				vsentry_inode_rename,
	//.inode_readlink =			vsentry_inode_readlink,
	.inode_follow_link =		vsentry_inode_follow_link,

	//.file_open =			vsentry_file_open,
	//.file_permission = 		vsentry_file_permission,
	//.file_alloc_security =	vsentry_file_alloc_security,
	//.file_ioctl =				vsentry_file_ioctl,
	//.file_mprotect =			vsentry_file_mprotect,
	//.file_lock =				vsentry_file_lock,
	//.file_fcntl =				vsentry_file_fcntl,

	//.mmap_addr =				vsentry_mmap_addr,
	//.mmap_file =				vsentry_mmap_file,

	//.task_create =			vsentry_task_create,
	//.task_free = 				vsentry_task_free,
	//.task_fix_setuid =		vsentry_task_fix_setuid,
	//.task_setpgid =			vsentry_task_setpgid,
	//.task_setnice =			vsentry_task_setnice,
	//.task_setrlimit = 		vsentry_task_setrlimit,
	//.task_movememory =		vsentry_task_movememory,
	//.task_kill =				vsentry_task_kill,
	//.task_to_inode =			vsentry_task_to_inode,

	//.unix_stream_connect =	vsentry_unix_stream_connect,
	//.unix_may_send =			vsentry_unix_may_send,

	//.kernel_fw_from_file =	vsentry_kernel_fw_from_file,
	//.kernel_module_request = 	vsentry_kernel_module_request,
	//.kernel_module_from_file =vsentry_kernel_module_from_file,

	.socket_connect =			vsentry_socket_connect,
	//.socket_create = 			vsentry_socket_create,
	//.socket_bind =			vsentry_socket_bind,
	//.socket_listen = 			vsentry_socket_listen,
	//.socket_accept = 			vsentry_socket_accept,
	//.socket_sendmsg = 		vsentry_socket_sendmsg,
	//.socket_recvmsg = 		vsentry_socket_recvmsg,
	//.socket_shutdown =		vsentry_socket_shutdown,

	//.sk_alloc_security =		vsentry_sk_alloc_security,
	//.sk_free_security = 		vsentry_sk_free_security,
	//.sk_clone_security = 		vsentry_sk_clone_security,

	//.shm_alloc_security = 	vsentry_shm_alloc_security,
	//.shm_free_security = 		vsentry_shm_free_security,
	//.shm_associate = 			vsentry_shm_associate,
	//.shm_shmctl = 			vsentry_shm_shmctl,
	//.shm_shmat = 				vsentry_shm_shmat,

	//.ptrace_access_check =	vsentry_ptrace_access_check,
	//.ptrace_traceme = 		vsentry_ptrace_traceme,

	//.syslog =					vsentry_syslog,
	//.settime = 				vsentry_settime,
	//.vm_enough_memory = 		vsentry_vm_enough_memory,

	.bprm_committing_creds =	vsentry_bprm_committing_creds,
};
#endif /*LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)*/

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static inline void security_delete_hooks(struct security_hook_list *hooks,int count)
{
	int i;

	for (i = 0; i < count; i++)
		list_del_rcu(&hooks[i].list);
}
#endif

int register_lsm_hooks (void)
{
	security_add_hooks(vsentry_hooks, ARRAY_SIZE(vsentry_hooks));
	return 0;
}

int unregister_lsm_hooks (void)
{
	security_delete_hooks(vsentry_hooks, ARRAY_SIZE(vsentry_hooks));
	return 0;
}
