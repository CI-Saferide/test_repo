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

MODULE_LICENSE("proprietary");
MODULE_DESCRIPTION("vSentry Kernel Module");

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

/*kernel debug printing*/
void dbg_print(char *func){

	char buff[BUFF_SIZE];
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	int ruid = (int)rcred->uid.val;
	int guid = (int)rcred->gid.val;

	//printk("**************************************************************************\n");
	//printk("[VSENTRY]: entered function %s\n", func);
	//printk("[VSENTRY]: Check \"%s\" permission PID:%d UID:%d GID:%d\n",current->comm,current->pid,ruid,guid);

	//sprintf(buff, "[VSENTRY]: entered function %s\nCheck \"%s\" permission PID:%d UID:%d GID:%d\n", func,current->comm,current->pid,ruid,guid);
	sprintf(buff, "entered function %s\nCheck \"%s\" permission PID:%d UID:%d GID:%d\n", func,current->comm,current->pid,ruid,guid);
	sr_netlink_send_up(buff, strlen(buff));
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

    if (printed_bytes > sizeof(ip_str)) return NULL;

    return ip_str;
}

char* get_path(struct dentry *dentry){

	char *buffer, *path;

	buffer = (char *)__get_free_page(GFP_KERNEL);

	if (!buffer)
		return NULL;

	path = dentry_path_raw(dentry, buffer, PAGE_SIZE);

	if (IS_ERR(path)){

		return NULL;
	}

	free_page((unsigned long)buffer);

	return path;
}
/*following functions used only inside check_perm()*/
int check_connect_perm(perm_info_t *info){

	struct sockaddr_in *ipv4;
	char *ipAddress;
	//char *buff;
	char buff[BUFF_SIZE];
	int port;

	ipv4= (struct sockaddr_in *)info->socket_connect_info.address;
	ipAddress = parse_sinaddr(ipv4->sin_addr);
	port = (int)ntohs(ipv4->sin_port);

	dbg_print(__FUNCTION__);

	//printk("[VSENTRY]: IP:PORT = %s:%d\n",ipAddress,port);

	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	//sprintf(buff,"[VSENTRY]: IP:PORT = %s:%d\n",ipAddress,port);
	sprintf(buff,"IP:PORT = %s:%d\n",ipAddress,port);	
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);

	return 0;
}

int check_link_perm(perm_info_t *info){

	//char *file, *old_path, *new_path,*buff;
	char *file, old_path[BUFF_SIZE], new_path[BUFF_SIZE],buff[BUFF_SIZE];

	file = info->link_info.old_dentry->d_iname;

	//old_path = kmalloc(strlen(get_path(info->link_info.old_dentry))+1,GFP_KERNEL);
	//new_path = kmalloc(strlen(get_path(info->link_info.new_dentry))+1,GFP_KERNEL);

	strcpy(old_path,get_path(info->link_info.old_dentry));
	strcpy(new_path,get_path(info->link_info.new_dentry));

	dbg_print(__FUNCTION__);

	//printk("[VSENTRY]: link file %s\n",file);
	//printk("[VSENTRY]: old path %s\n", old_path);
	//printk("[VSENTRY]: new path %s\n", new_path);

	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);

	//sprintf(buff,"[VSENTRY]: link file %s\nold path %s\nnew path %s\n",file,old_path,new_path);
	sprintf(buff,"link file %s\nold path %s\nnew path %s\n",file,old_path,new_path);	
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);
	//kfree(old_path);
	//kfree(new_path);

	return 0;
}

int check_unlink_perm(perm_info_t *info){

	//char *file, *path,*buff;
	char *file, path[BUFF_SIZE],buff[BUFF_SIZE];

	file = info->unlink_info.dentry->d_iname;

	//path = kmalloc(strlen(get_path(info->unlink_info.dentry))+1,GFP_KERNEL);
	strcpy(path,get_path(info->unlink_info.dentry));

	dbg_print(__FUNCTION__);

	//printk("[VSENTRY]: unlink file %s\n",file);
	//printk("[VSENTRY]: from path %s\n", path);

	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	//sprintf(buff,"[VSENTRY]: unlink %s\nfrom path %s\n",file,path);
	sprintf(buff,"unlink %s\nfrom path %s\n",file,path);	
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);
	//kfree(path);

	return 0;
}

int check_symlink_perm(perm_info_t *info){

	//char *file, *path,*buff;
	char *file, path[BUFF_SIZE],buff[BUFF_SIZE];


	file =(char *)info->symlink_info.name;

	//path = kmalloc(strlen(get_path(info->symlink_info.dentry))+1,GFP_KERNEL);
	strcpy(path,get_path(info->symlink_info.dentry));
	
	dbg_print(__FUNCTION__);

	//printk("[VSENTRY]: symlink file %s\n",file);
	//printk("[VSENTRY]: from path %s\n",path);

	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	//sprintf(buff,"[VSENTRY]: symlink %s\nfrom path %s\n",file,path);
	sprintf(buff,"symlink %s\nfrom path %s\n",file,path);
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);
	//kfree(path);

	return 0;
}

int check_mkdir_perm(perm_info_t *info){

	//char *file, *path,*buff;
	char *file, path[BUFF_SIZE],buff[BUFF_SIZE];

	file = info->mkdir_info.dentry->d_iname;

	//path = kmalloc(strlen(get_path(info->mkdir_info.dentry->d_parent))+1,GFP_KERNEL);
	strcpy(path,get_path(info->mkdir_info.dentry->d_parent));

	dbg_print(__FUNCTION__);
	//printk("[VSENTRY]: mkdir %s\n",file);
	//printk("[VSENTRY]: in directory %s\n",path);

	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	//sprintf(buff,"[VSENTRY]: mkdir %s\nin directory %s\n",file,path);
	sprintf(buff,"mkdir %s\nin directory %s\n",file,path);	
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);
	//kfree(path);

	return 0;
}

int check_rmdir_perm(perm_info_t *info){

	//char *file, *path,*buff;
	char *file, path[BUFF_SIZE],buff[BUFF_SIZE];

	file = info->rmdir_info.dentry->d_iname;
	//path = kmalloc(strlen(get_path(info->rmdir_info.dentry->d_parent))+1,GFP_KERNEL);
	strcpy(path,get_path(info->rmdir_info.dentry->d_parent));

	dbg_print(__FUNCTION__);
	//printk("[VSENTRY]: rmdir %s\n", file);
	//printk("[VSENTRY]: from directory %s\n",path);
	
	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	//sprintf(buff,"[VSENTRY]: rmdir %s\nfrom directory %s\n",file,path);
	sprintf(buff,"rmdir %s\nfrom directory %s\n",file,path);
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);
	//kfree(path);

	return 0;
}

int check_chmod_perm(perm_info_t *info){

	//char *path,*buff;
	char path[BUFF_SIZE],buff[BUFF_SIZE];

	//path = kmalloc(strlen(get_path(info->chmod_info.path->dentry))+1,GFP_KERNEL);
	strcpy(path,get_path(info->chmod_info.path->dentry));

	dbg_print(__FUNCTION__);

	//printk("[VSENTRY]: chmod %s\n",path);

	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	//sprintf(buff, "[VSENTRY]: chmod %s\n",path);
	sprintf(buff, "chmod %s\n",path);	
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);
	//kfree(path);

	return 0;

}

int check_create_perm(perm_info_t *info){

	//char *path,*buff;
	char path[BUFF_SIZE],buff[BUFF_SIZE];

	//path = kmalloc(strlen(get_path(info->inode_create_info.dentry))+1,GFP_KERNEL);
	strcpy(path,get_path(info->inode_create_info.dentry));

	dbg_print(__FUNCTION__);

	//printk("[VSENTRY]: create %s\n",path);

	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	//sprintf(buff,"[VSENTRY]: create %s\n",path);
	sprintf(buff,"create %s\n",path);	
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);
	//kfree(path);

	return 0;
}

int check_file_open(perm_info_t *info){

	//char *path,*buff;
	char path[BUFF_SIZE],buff[BUFF_SIZE];

	//path = kmalloc(strlen(get_path(info->file_open_info.file->f_path.dentry))+1,GFP_KERNEL);
	strcpy(path,get_path(info->file_open_info.file->f_path.dentry));

	dbg_print(__FUNCTION__);

	//printk(KERN_WARNING "[VSENTRY]: file %s\n",path);

	//buff = kmalloc(BUFF_SIZE,GFP_KERNEL);
	//sprintf(buff,"[VSENTRY]: file %s\n",path);
	sprintf(buff,"file %s\n",path);	
	sr_netlink_send_up(buff, strlen(buff));

	//kfree(buff);
	//kfree(path);

	return 0;
}
/**/
static int check_perm(int syscall_type, perm_info_t *perm_info){

	int ret=0;
	//printk(KERN_WARNING "____Check Permission___::%s\n", __FUNCTION__);

	switch (syscall_type) {

		case SYSCALL_CONNECT:
			ret = check_connect_perm(perm_info);
			break;

		case SYSCALL_LINK:
			ret = check_link_perm(perm_info);
			break;

		case SYSCALL_UNLINK:
			ret = check_unlink_perm(perm_info);
			break;

		case SYSCALL_SYMLINK:
			ret = check_symlink_perm(perm_info);
			break;

		case SYSCALL_MKDIR:
			ret = check_mkdir_perm(perm_info);
			break;

		case SYSCALL_RMDIR:
			ret = check_rmdir_perm(perm_info);
			break;

		case SYSCALL_CHMOD:
			ret = check_chmod_perm(perm_info);
			break;

		case SYSCALL_CREATE:
			ret = check_create_perm(perm_info);
			break;

		case SYSCALL_OPEN:
			ret = check_file_open(perm_info);
			break;
	}

	return ret;
}

/* Hook functions begin here. */

static int vsentry_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry){

	perm_info_t perm_info;

	perm_info.link_info.old_dentry = old_dentry;
	perm_info.link_info.dir = dir;
	perm_info.link_info.new_dentry = new_dentry;

	return check_perm(SYSCALL_LINK, &perm_info);
}

static int vsentry_inode_unlink(struct inode *dir, struct dentry *dentry){

	perm_info_t perm_info;

	perm_info.unlink_info.dir = dir;
	perm_info.unlink_info.dentry = dentry;

	return check_perm(SYSCALL_UNLINK, &perm_info);
}

static int vsentry_inode_symlink(struct inode *dir, struct dentry *dentry, const char *name){

	perm_info_t perm_info;

	perm_info.symlink_info.dir = dir;
	perm_info.symlink_info.dentry = dentry;
	perm_info.symlink_info.name = name;

	return check_perm(SYSCALL_SYMLINK, &perm_info);
}

static int vsentry_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask){

	perm_info_t perm_info;

	perm_info.mkdir_info.dir = dir;
	perm_info.mkdir_info.dentry = dentry;
	perm_info.mkdir_info.mask = mask;

	return check_perm(SYSCALL_MKDIR, &perm_info);
}

static int vsentry_inode_rmdir(struct inode *dir, struct dentry *dentry){

	perm_info_t perm_info;

	perm_info.rmdir_info.dir = dir;
	perm_info.rmdir_info.dentry = dentry;

	return check_perm(SYSCALL_RMDIR, &perm_info);
}


static int vsentry_socket_connect(struct socket *sock, struct sockaddr *address, int addrlen){

	perm_info_t perm_info;

	perm_info.socket_connect_info.sock = sock;
	perm_info.socket_connect_info.address = address;
	perm_info.socket_connect_info.addrlen = addrlen;

	return check_perm(SYSCALL_CONNECT, &perm_info);

}


static int vsentry_path_chmod(struct path *path, umode_t mode){

	perm_info_t perm_info;

	perm_info.chmod_info.path = path;
	perm_info.chmod_info.mode = mode;

	return check_perm(SYSCALL_CHMOD, &perm_info);
}

static int vsentry_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode){

	perm_info_t perm_info;

	perm_info.inode_create_info.dir = dir;
	perm_info.inode_create_info.dentry = dentry;
	perm_info.inode_create_info.mode = mode;

	return check_perm(SYSCALL_CREATE, &perm_info);
}

static int vsentry_file_open(struct file *file, const struct cred *cred){
	
	perm_info_t perm_info;

	perm_info.file_open_info.file = file;
	perm_info.file_open_info.cred = cred;

	return check_perm(SYSCALL_OPEN, &perm_info);
}

static void vsentry_bprm_committing_creds(struct linux_binprm *bprm){
	
	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return ;
}

static int vsentry_path_unlink(struct path *path, struct dentry *dentry){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_path_mkdir(struct path *dir, struct dentry *dentry, umode_t mode){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_path_rmdir(struct path *dir, struct dentry *dentry){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_path_symlink(struct path *dir, struct dentry *dentry, const char *old_name){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_inode_mknod(struct inode *dir, struct dentry *dentry, umode_t mode, dev_t dev){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_path_mknod(struct path *dir, struct dentry *dentry, umode_t mode,unsigned int dev){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,struct dentry *new_dentry){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_path_rename(struct path *old_dir, struct dentry *old_dentry, struct path *new_dir,struct dentry *new_dentry){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_path_chown(struct path *old_dir,kuid_t uid,kgid_t gid){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_path_chroot(struct path *old_dir,kuid_t uid,kgid_t gid){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_inode_readlink(struct dentry *dentry){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_inode_follow_link(struct dentry *dentry, struct inode *inode, bool rcu){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_path_truncate(struct path *path){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_file_permission(struct file *file, int mask){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_file_alloc_security(struct file *file){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static void vsentry_file_free_security(struct file *file){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return ;
}

static int vsentry_file_ioctl(struct file *file, unsigned int cmd,unsigned long arg){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_mmap_addr(unsigned long addr){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}
static int vsentry_mmap_file(struct file *file, unsigned long reqport,unsigned long port,unsigned long flags){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_file_mprotect(struct vm_area_struct *vma, unsigned long reqport,unsigned long port){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}
static int vsentry_file_lock(struct file *file, unsigned int cmd){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_file_fcntl(struct file *file, unsigned int cmd,unsigned long arg){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_task_create(unsigned long clone_flags){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static void vsentry_task_free(struct task_struct *task){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return ;
}

static int vsentry_kernel_fw_from_file(struct file *file,char * buf,size_t size){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_kernel_module_request(char *kmod_name){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_kernel_module_from_file(struct file *file){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_task_fix_setuid(struct cred *new, const struct cred *old, int flags){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_task_setpgid(struct task_struct *p,pid_t pgid){

	perm_info_t perm_info;

	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_task_setnice(struct task_struct *p,int nice){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_task_setrlimit(struct task_struct *p,unsigned int resource, struct rlimit *new_rlim){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_task_movememory(struct task_struct *p){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_task_kill(struct task_struct *p,struct siginfo *info, int sig, u32 secid){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static void vsentry_task_to_inode(struct task_struct *p,struct inode *inode){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return ;
}

static int vsentry_unix_stream_connect(struct sock *sock,struct sock *other, struct sock *newsk){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_unix_may_send(struct sock *sock,struct sock *other){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_socket_create(int family, int type, int protocol, int kern){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_socket_bind(struct socket *sock, struct sockaddr *address,int addrlen){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_socket_listen(struct socket *sock,int backlog){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_socket_accept(struct socket *sock,struct socket *newsock){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_socket_sendmsg(struct socket *sock,struct msghdr *msg,int size){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_socket_recvmsg(struct socket *sock,struct msghdr *msg,int size,int flags){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_socket_shutdown(struct socket *sock,int how){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_sk_alloc_security(struct socket *sk,int family, gfp_t priority){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static void vsentry_sk_free_security(struct socket *sk){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return ;
}

static void vsentry_sk_clone_security(struct socket *sk,struct sock *newsk){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return ;
}

static int vsentry_shm_alloc_security(struct shmid_kernel *shp){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}
static void vsentry_shm_free_security(struct shmid_kernel *shp){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return ;
}
static int vsentry_shm_associate(struct shmid_kernel *shp, int shmflg){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}
static int vsentry_shm_shmctl(struct shmid_kernel *shp, int cmd){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}
static int vsentry_shm_shmat(struct shmid_kernel *shp, char __user *shmaddr,int shmflg){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_ptrace_access_check(struct task_struct *child,unsigned int mode){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}


static int vsentry_ptrace_traceme(struct task_struct *parent){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_syslog(int type){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_settime(const struct timespec64 *ts, const struct timezone *tz){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

	return 0;
}

static int vsentry_vm_enough_memory(struct mm_struct *mm, long pages){

	perm_info_t perm_info;
	
	dbg_print(__FUNCTION__);

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
	LSM_HOOK_INIT(path_chroot, vsentry_path_chroot),
	LSM_HOOK_INIT(path_truncate, vsentry_path_truncate),

	LSM_HOOK_INIT(inode_link, vsentry_inode_link),
    LSM_HOOK_INIT(inode_unlink, vsentry_inode_unlink),
    LSM_HOOK_INIT(inode_symlink, vsentry_inode_symlink),
    LSM_HOOK_INIT(inode_mkdir, vsentry_inode_mkdir),
    LSM_HOOK_INIT(inode_rmdir, vsentry_inode_rmdir),
	LSM_HOOK_INIT(inode_create, vsentry_inode_create),
	LSM_HOOK_INIT(inode_mknod, vsentry_inode_mknod),
    LSM_HOOK_INIT(inode_rename, vsentry_inode_rename),
	LSM_HOOK_INIT(inode_readlink, vsentry_inode_readlink),
	//LSM_HOOK_INIT(inode_follow_link, vsentry_inode_follow_link),
/*
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
	
	//LSM_HOOK_INIT(kernel_fw_from_file, vsentry_kernel_fw_from_file), /*not in every kern version*/
	//LSM_HOOK_INIT(kernel_module_request, vsentry_kernel_module_request),
	//LSM_HOOK_INIT(kernel_module_from_file, vsentry_kernel_module_from_file), /*not in every kern version*/

    LSM_HOOK_INIT(socket_connect, vsentry_socket_connect),
	//LSM_HOOK_INIT(socket_create, vsentry_socket_create),
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
	//LSM_HOOK_INIT(settime, vsentry_settime),
	//LSM_HOOK_INIT(vm_enough_memory, vsentry_vm_enough_memory),
	
	LSM_HOOK_INIT(bprm_committing_creds, vsentry_bprm_committing_creds), 

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

static int __init vsentry_init(void){
	
	int rc = 0;
	
	printk(KERN_INFO "[VSENTRY]: RUNNING ON VERSION %s\n",utsname()->release);

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	security_add_hooks(vsentry_hooks, ARRAY_SIZE(vsentry_hooks));
	printk(KERN_INFO "[VSENTRY]: Kernel Module Initialized!\n");
	sr_netlink_init();
	#else
	reset_security_ops();
	printk(KERN_INFO "[VSENTRY]: Kernel Module Initialized!\n");
	if (register_security (&vsentry_ops)){
		printk("[VSENTRY]: Unable to register with kernel.\n");
		rc = -EPERM;
	}
	sr_netlink_init();
	#endif

	return rc;//Non-zero return means that the module couldn't be loaded.
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
static inline void security_delete_hooks(struct security_hook_list *hooks,int count){

        int i;

        for (i = 0; i < count; i++)
                list_del_rcu(&hooks[i].list);
}
#endif

static void __exit vsentry_cleanup(void){
	
	sr_netlink_exit();	
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	security_delete_hooks(vsentry_hooks, ARRAY_SIZE(vsentry_hooks));
	#else
	reset_security_ops();
	#endif
	printk(KERN_INFO "[VSENTRY]: Cleaning up module.\n");
}

module_init(vsentry_init);
module_exit(vsentry_cleanup);
