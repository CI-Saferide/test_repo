/* file: sr_lsm_hooks.c
 * purpose: this file registering the vsentry hooks into the linux os sys_calls
*/
#include "sr_lsm_hooks.h"
#include "multiplexer.h"
#include "sal_linux.h"

/* "Socket"-level control message types: */
const char static *SCM_type[] = {"UNKNOWN",
								 "SCM_RIGHTS",		 /* SCM_RIGHTS	0x01	rw: access rights (array of int) */
								 "SCM_CREDENTIALS", /*SCM_CREDENTIALS 0x02  rw: struct ucred				 */	
								 "SCM_SECURITY"	 /*SCM_SECURITY	0x03	rw: security label				 */
								};

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

//#define BUFF_SIZE 256

extern int sr_vsentryd_pid;

/*implement filter for our sr-engine */
int hook_filter(void){
	/*if the statement is true in means the SYS_CALL invoked by sr-engine */
    if ((sr_vsentryd_pid) == (current->pid)-1)
		return TRUE;
		
	return FALSE;
}

/*parsing data helper functions*/
char* parse_sinaddr(const struct in_addr saddr){
    static char ip_str[16];
    //bzero(ip_str, sizeof(ip_str));
    int printed_bytes = 0;

    printed_bytes = snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d",
        (saddr.s_addr&0xFF),
        ((saddr.s_addr&0xFF00)>>8),
        ((saddr.s_addr&0xFF0000)>>16),
        ((saddr.s_addr&0xFF000000)>>24));

    if (printed_bytes > sizeof(ip_str))
    	return NULL;

    return ip_str;
}

char* get_path(struct dentry *dentry){

	char *buffer, *path;

	buffer = (char *)__get_free_page(GFP_KERNEL);
	if (!buffer)
		return NULL;

	path = dentry_path_raw(dentry, buffer, PAGE_SIZE);
	if (IS_ERR(path))
		return NULL;
	
	free_page((unsigned long)buffer);

	return path;
}

static int vsentry_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry){
	
	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter()) return 0;
	/*
	char *file, path[BUFF_SIZE];	
	char *file, *old_path, *new_path,*buff;
	char *file, old_path[BUFF_SIZE], new_path[BUFF_SIZE],buff[BUFF_SIZE];
	file = old_dentry->d_iname;
	old_path = kmalloc(strlen(get_path(info->link_info.old_dentry))+1,GFP_KERNEL);
	new_path = kmalloc(strlen(get_path(info->link_info.new_dentry))+1,GFP_KERNEL);
	strcpy(old_path,get_path(old_dentry));
	strcpy(new_path,get_path(new_dentry));
	printk("[VSENTRY]: link file %s\n",file);
	printk("[VSENTRY]: old path %s\n", old_path);
	printk("[VSENTRY]: new path %s\n", new_path);
	buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	sprintf(buff,"[VSENTRY]: link file %s\nold path %s\nnew path %s\n",file,old_path,new_path);	
	sprintf(buff,"link file %s\nold path %s\nnew path %s\n",file,old_path,new_path);
	file = dentry->d_iname;
	strcpy(path,get_path(dentry->d_parent));
	*/
	
	strcpy(mpx.fileinfo.id.event_name,__FUNCTION__);
	strcpy(mpx.fileinfo.filename,old_dentry->d_iname);
	strcpy(mpx.fileinfo.fullpath, get_path(new_dentry));
	strcpy(mpx.fileinfo.old_path, get_path(old_dentry));

	mpx.fileinfo.id.gid = (int)rcred->gid.val;
	mpx.fileinfo.id.tid = (int)rcred->uid.val;
	mpx.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (mpx_inode_link(&mpx));
}

static int vsentry_inode_unlink(struct inode *dir, struct dentry *dentry){
	
	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred = ts->real_cred;		
	
	if(hook_filter()) return 0;
	
	strcpy(mpx.fileinfo.id.event_name,__FUNCTION__);
	strcpy(mpx.fileinfo.filename,dentry->d_iname);
	strcpy(mpx.fileinfo.fullpath, get_path(dentry));

	mpx.fileinfo.id.gid = (int)rcred->gid.val;
	mpx.fileinfo.id.tid = (int)rcred->uid.val;
	mpx.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (mpx_inode_unlink(&mpx));
}

static int vsentry_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name){
	
	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter()) return 0;
	
	strcpy(mpx.fileinfo.id.event_name,__FUNCTION__);
	strcpy(mpx.fileinfo.filename,(char *)name);
	strcpy(mpx.fileinfo.fullpath, get_path(dentry));

	mpx.fileinfo.id.gid = (int)rcred->gid.val;
	mpx.fileinfo.id.tid = (int)rcred->uid.val;
	mpx.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (mpx_inode_symlink(&mpx));
}

static int vsentry_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask){
	
	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter()) return 0;

	strcpy(mpx.fileinfo.id.event_name,__FUNCTION__);
	strcpy(mpx.fileinfo.filename,dentry->d_iname);
	strcpy(mpx.fileinfo.fullpath, get_path(dentry->d_parent));

	mpx.fileinfo.id.gid = (int)rcred->gid.val;
	mpx.fileinfo.id.tid = (int)rcred->uid.val;
	mpx.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (mpx_mkdir(&mpx));
}

static int vsentry_inode_rmdir(struct inode *dir, struct dentry *dentry){

	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter()) return 0;

	strcpy(mpx.fileinfo.id.event_name,__FUNCTION__);
	strcpy(mpx.fileinfo.filename,dentry->d_iname);
	strcpy(mpx.fileinfo.fullpath, get_path(dentry->d_parent));

	mpx.fileinfo.id.gid = (int)rcred->gid.val;
	mpx.fileinfo.id.tid = (int)rcred->uid.val;
	mpx.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (mpx_rmdir(&mpx));
}


static int vsentry_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen){

	mpx_info_t mpx;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
			
	struct sockaddr_in *ipv4;
	
	if(hook_filter()) return 0;
	
	ipv4 = (struct sockaddr_in *)address;
	
	strcpy(mpx.address_info.id.event_name,__FUNCTION__);
	strcpy(mpx.address_info.ipv4,parse_sinaddr(ipv4->sin_addr));
	
	mpx.address_info.port = (int)ntohs(ipv4->sin_port);	
	mpx.address_info.id.gid = (int)rcred->gid.val;
	mpx.address_info.id.tid = (int)rcred->uid.val;
	mpx.address_info.id.pid = current->pid;

	//TODO: handle permission for sys call
	return (mpx_socket_connect(&mpx));
}


static int vsentry_path_chmod(struct path *path, umode_t mode){
	
	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter()) return 0;
	
	strcpy(mpx.fileinfo.id.event_name,__FUNCTION__);
	strcpy(mpx.fileinfo.fullpath, get_path(path->dentry));

	mpx.fileinfo.id.gid = (int)rcred->gid.val;
	mpx.fileinfo.id.tid = (int)rcred->uid.val;
	mpx.fileinfo.id.pid = current->pid;

	//TODO: handle permission for sys call
	return (mpx_path_chmod(&mpx));
}

static int vsentry_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode){

	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter()) return 0;

	strcpy(mpx.fileinfo.id.event_name,__FUNCTION__);
	strcpy(mpx.fileinfo.filename,dentry->d_iname);
	strcpy(mpx.fileinfo.fullpath, get_path(dentry->d_parent));

	mpx.fileinfo.id.gid = (int)rcred->gid.val;
	mpx.fileinfo.id.tid = (int)rcred->uid.val;
	mpx.fileinfo.id.pid = current->pid;
	
	//TODO: handle permission for sys call
	return (mpx_inode_create(&mpx));
}

__attribute__ ((unused))
static int vsentry_file_open(struct file *file, const struct cred *cred){
	
	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter()) return 0;	

	strcpy(mpx.fileinfo.id.event_name,__FUNCTION__);
	strcpy(mpx.fileinfo.filename,get_path(file->f_path.dentry));

	mpx.fileinfo.id.gid = (int)rcred->gid.val;
	mpx.fileinfo.id.tid = (int)rcred->uid.val;
	mpx.fileinfo.id.pid = current->pid;

	//TODO: handle permission for sys call
	return (mpx_file_open(&mpx));
}

__attribute__ ((unused))
static void vsentry_bprm_committing_creds(struct linux_binprm *bprm){
	
	//perm_info_t perm_info;

	if(hook_filter()) return ;

	return ;
}

__attribute__ ((unused))
static int vsentry_path_unlink(struct path *path, struct dentry *dentry){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_rmdir(struct path *dir, struct dentry *dentry){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_symlink(struct path *dir, struct dentry *dentry, const char *old_name){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,unsigned int dev){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,struct dentry *new_dentry){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_rename(struct path *old_dir, struct dentry *old_dentry, struct path *new_dir,struct dentry *new_dentry){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;
	
	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_chown(struct path *old_dir,kuid_t uid,kgid_t gid){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_chroot(struct path *old_dir,kuid_t uid,kgid_t gid){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_inode_readlink(struct dentry *dentry){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_inode_follow_link(struct dentry *dentry, struct inode *inode, bool rcu){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_path_truncate(struct path *path){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_file_permission(struct file *file, int mask){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_file_alloc_security(struct file *file){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_file_free_security(struct file *file){

	//perm_info_t perm_info;

	if(hook_filter()) return ;

	return ;
}

__attribute__ ((unused))
static int vsentry_file_ioctl(struct file *file, unsigned int cmd,unsigned long arg){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_mmap_addr(unsigned long addr){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_mmap_file(struct file *file, unsigned long reqport,unsigned long port,unsigned long flags){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_file_mprotect(struct vm_area_struct *vma, unsigned long reqport,unsigned long port){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_file_lock(struct file *file, unsigned int cmd){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_file_fcntl(struct file *file, unsigned int cmd,unsigned long arg){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_task_create(unsigned long clone_flags){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_task_free(struct task_struct *task){

	//perm_info_t perm_info;

	if(hook_filter()) return ;

	return ;
}

__attribute__ ((unused))
static int vsentry_kernel_fw_from_file(struct file *file,char * buf,size_t size){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_kernel_module_request(char *kmod_name){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_kernel_module_from_file(struct file *file){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_fix_setuid(struct cred *new, const struct cred *old, int flags){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_setpgid(struct task_struct *p,pid_t pgid){

	//perm_info_t perm_info;

	if(hook_filter()) return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_task_setnice(struct task_struct *p,int nice){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_setrlimit(struct task_struct *p,unsigned int resource, struct rlimit *new_rlim){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_movememory(struct task_struct *p){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;
	
	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_task_kill(struct task_struct *p,struct siginfo *info, int sig, u32 secid){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_task_to_inode(struct task_struct *p,struct inode *inode){

	//perm_info_t perm_info;
	
	if(hook_filter()) return ;

	return ;
}

__attribute__ ((unused))
static int vsentry_unix_stream_connect(struct sock *sock,struct sock *other, struct sock *newsk){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;
	
	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_unix_may_send(struct sock *sock,struct sock *other){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;
	
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
static int vsentry_socket_create(int family, int type, int protocol, int kern){

	mpx_info_t mpx;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	if(hook_filter()) return 0;	
	
		printk(KERN_INFO"family:%s, type:%s, protocol:%d, kern:%d, pid=%d, gid=%d, tid=%d", 
			protocol_family[family], 
			SCM_type[type],
			protocol,
			kern,   
			current->pid,
			(int)rcred->gid.val, 
			(int)rcred->uid.val);
			
	//return 0;
	
	strcpy(mpx.socket_info.id.event_name,__FUNCTION__);
	strcpy(mpx.socket_info.family,protocol_family[family]);
	strcpy(mpx.socket_info.type, SCM_type[type]);
	mpx.socket_info.protocol = protocol;
	mpx.socket_info.kern = kern;
	
	mpx.socket_info.id.gid = (int)rcred->gid.val;
	mpx.socket_info.id.tid = (int)rcred->uid.val;
	mpx.socket_info.id.pid = current->pid;
	
		/*printk(KERN_INFO"family:%s, type:%s, protocol:%d, kern:%d, pid=%d, gid=%d, tid=%d", 
			mpx.socket_info.family, 
			mpx.socket_info.type,
			mpx.socket_info.protocol,
			mpx.socket_info.kern,   
			mpx.socket_info.id.pid,
			mpx.socket_info.id.gid, 
			mpx.socket_info.id.tid);*/
			
	
	
	//TODO: handle permission for sys call
	return (mpx_socket_create(&mpx));
}

__attribute__ ((unused))
static int vsentry_socket_bind(struct socket *sock, struct sockaddr *address,int addrlen){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_socket_listen(struct socket *sock,int backlog){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_socket_accept(struct socket *sock,struct socket *newsock){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
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
static int vsentry_socket_sendmsg(struct socket *sock,struct msghdr *msg,int size){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
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
static int vsentry_socket_recvmsg(struct socket *sock,struct msghdr *msg,int size,int flags){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_socket_shutdown(struct socket *sock,int how){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_sk_alloc_security(struct socket *sk,int family, gfp_t priority){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_sk_free_security(struct socket *sk){

	//perm_info_t perm_info;
	
	if(hook_filter()) return ;

	return ;
}

__attribute__ ((unused))
static void vsentry_sk_clone_security(struct socket *sk,struct sock *newsk){

	//perm_info_t perm_info;
	
	if(hook_filter()) return ;

	return ;
}

__attribute__ ((unused))
static int vsentry_shm_alloc_security(struct shmid_kernel *shp){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static void vsentry_shm_free_security(struct shmid_kernel *shp){

	//perm_info_t perm_info;
	
	if(hook_filter()) return ;

	return ;
}

__attribute__ ((unused))
static int vsentry_shm_associate(struct shmid_kernel *shp, int shmflg){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_shm_shmctl(struct shmid_kernel *shp, int cmd){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,int shmflg){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	return 0;
}

__attribute__ ((unused))
static int vsentry_ptrace_access_check(struct task_struct *child,unsigned int mode){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_ptrace_traceme(struct task_struct *parent){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_syslog(int type){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_settime(const struct timespec64 *ts, const struct timezone *tz){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

	//TODO: handle permission for sys call
	return 0;
}

__attribute__ ((unused))
static int vsentry_vm_enough_memory(struct mm_struct *mm, long pages){

	//perm_info_t perm_info;
	
	if(hook_filter()) return 0;

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
#if(0)
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
	//LSM_HOOK_INIT(socket_bind, vsentry_socket_bind),
	//LSM_HOOK_INIT(socket_listen, vsentry_socket_listen),
	//LSM_HOOK_INIT(socket_accept, vsentry_socket_accept),
	//LSM_HOOK_INIT(socket_sendmsg, vsentry_socket_sendmsg),
	//LSM_HOOK_INIT(socket_recvmsg, vsentry_socket_recvmsg),
	//LSM_HOOK_INIT(socket_shutdown, vsentry_socket_shutdown),

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
    .path_chmod =          		vsentry_path_chmod,
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

	//.file_open =          	vsentry_file_open,
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
static inline void security_delete_hooks(struct security_hook_list *hooks,int count){

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
