/* file: event_mediator.c
 * purpose: this file impldispents mediation layer between platform
 * 			specific code and agnostic code (starting from dispatcher
 * 			layer). it also collects all relevant metadata for each hook
*/
#include "sr_lsm_hooks.h"
#include "dispatcher.h"
#include "event_mediator.h"
#include "sr_sal_common.h"
#include "sr_types.h"

/* Protocol families, same as address families */
const static SR_8 *protocol_family[] = {
	//"PF_UNSPEC",	
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
	//"PF_ROUTE",	
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

static SR_8 module_name[] = "[em]";

extern SR_32 sr_vsentryd_pid; //TODO: get sr_engine pid from chdrv open fops
#define HOOK_FILTER		if(hook_filter()) return 0;
/* TODO: design robust hook filter */
static SR_32 hook_filter(void)
{
	if ((sr_vsentryd_pid) == (current->pid)-1)
		return SR_TRUE;
		
	return SR_FALSE;
}

/* parsing data helper functions */
static void parse_sinaddr(const struct in_addr saddr, SR_8* buffer, SR_32 length)
{
	snprintf(buffer, length, "%d.%d.%d.%d",
		(saddr.s_addr&0xFF),
		((saddr.s_addr&0xFF00)>>8),
		((saddr.s_addr&0xFF0000)>>16),
		((saddr.s_addr&0xFF000000)>>24));
}

static SR_8 get_path(struct dentry *dentry, SR_8 *buffer, SR_32 len)
{
	SR_8 path[SR_MAX_PATH_SIZE], *path_ptr;

	path_ptr = dentry_path_raw(dentry, path, SR_MAX_PATH_SIZE);
	if (IS_ERR(path))
		return SR_ERROR;

	strncpy(buffer, path_ptr, MIN(len, 1+strlen(path_ptr)));
	return SR_SUCCESS;
}

SR_32 vsentry_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(disp.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(disp.fileinfo.filename), 1+strlen(dentry->d_iname)));
	if (SR_SUCCESS != get_path(dentry->d_parent, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath)))
		strncpy(disp.fileinfo.fullpath, "NA", 3);

	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;

#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s mkdir=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			disp.fileinfo.filename, 
			disp.fileinfo.fullpath, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_mkdir(&disp));
}

SR_32 vsentry_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred = ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER
	
	/* gather metadata */
	strncpy(disp.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(disp.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(disp.fileinfo.filename), 1+strlen(dentry->d_iname)));
	get_path(dentry, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath));

	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s unlink=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			disp.fileinfo.filename, 
			disp.fileinfo.fullpath, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_inode_unlink(&disp));
}

SR_32 vsentry_inode_symlink(struct inode *dir, struct dentry *dentry, const SR_8 *name)
{
	disp_info_t disp;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(disp.fileinfo.filename, (char *)name,
		MIN(sizeof(disp.fileinfo.filename), 1+strlen(name)));
	get_path(dentry, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath));

	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s symlink=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			disp.fileinfo.filename, 
			disp.fileinfo.fullpath, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_inode_symlink(&disp));
}


SR_32 vsentry_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	disp_info_t disp;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(disp.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(disp.fileinfo.filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath));

	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s rmdir=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			disp.fileinfo.filename, 
			disp.fileinfo.fullpath, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_rmdir(&disp));
}

SR_32 vsentry_socket_connect(struct socket *sock, struct sockaddr *address, SR_32 addrlen)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	struct sockaddr_in *ipv4;

	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	ipv4 = (struct sockaddr_in *)address;
	strncpy(disp.address_info.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.address_info.id.event_name), 1+strlen(__FUNCTION__)));
	parse_sinaddr(ipv4->sin_addr, disp.address_info.ipv4, sizeof(disp.address_info.ipv4));
	disp.address_info.port = (int)ntohs(ipv4->sin_port);	
	disp.address_info.id.gid = (int)rcred->gid.val;
	disp.address_info.id.tid = (int)rcred->uid.val;
	disp.address_info.id.pid = current->pid;

#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s socket_connect=%s, port=%d, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			disp.address_info.ipv4,
			disp.address_info.port,
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */

	/* call dispatcher */
	return (disp_socket_connect(&disp));
}


SR_32 vsentry_path_chmod(struct path *path, umode_t mode)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.fileinfo.id.event_name,__FUNCTION__,
		MIN(sizeof(disp.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	get_path(path->dentry, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath));
	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;

#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s path_chmod=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			disp.fileinfo.fullpath, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_path_chmod(&disp));
}

SR_32 vsentry_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(disp.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(disp.fileinfo.filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath));
	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s inode_create=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			disp.fileinfo.filename, 
			disp.fileinfo.fullpath,
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_inode_create(&disp));
}

//__attribute__ ((unused))
SR_32 vsentry_file_open(struct file *file, const struct cred *cred)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	get_path(file->f_path.dentry, disp.fileinfo.filename, sizeof(disp.fileinfo.filename));
	/*TODO: obtain full path */
	
	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;

#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s file_open=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			disp.fileinfo.filename, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_file_open(&disp));
}

SR_32 vsentry_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	disp_info_t disp;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.fileinfo.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.fileinfo.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(disp.fileinfo.filename, old_dentry->d_iname,
		MIN(sizeof(disp.fileinfo.filename), 1+strlen(old_dentry->d_iname)));
	get_path(new_dentry, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath));
	get_path(old_dentry, disp.fileinfo.old_path, sizeof(disp.fileinfo.old_path));

	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("%s inode_link=%s, path=%s, old path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			disp.fileinfo.filename, 
			disp.fileinfo.fullpath, 
			disp.fileinfo.old_path,
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_inode_link(&disp));
}

/*
 * @socket_create:
 *	Check permissions prior to creating a new socket.
 *	@family contains the requested protocol family.
 *	@type contains the requested communications type.
 *	@protocol contains the requested protocol.
 *	@kern set to 1 if a kernel socket.
 */
SR_32 vsentry_socket_create(SR_32 family, SR_32 type, SR_32 protocol, SR_32 kern)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.socket_info.id.event_name, __FUNCTION__,
		MIN(sizeof(disp.socket_info.id.event_name), 1+strlen(__FUNCTION__)));
	strncpy(disp.socket_info.family, protocol_family[family],
		MIN(sizeof(disp.socket_info.family), 1+strlen(protocol_family[family])));
	sprintf(disp.socket_info.type,"socket type: %d",type);
	/*TODO: modify strings to enums !! */
		
	disp.socket_info.protocol = protocol;
	disp.socket_info.kern = kern;
	
	disp.socket_info.id.gid = (int)rcred->gid.val;
	disp.socket_info.id.tid = (int)rcred->uid.val;
	disp.socket_info.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
	/*TODO: handle debug print */
#endif /* DEBUG_EVENT_MEDIATOR */

	/* call dispatcher */
	return (disp_socket_create(&disp));
}
