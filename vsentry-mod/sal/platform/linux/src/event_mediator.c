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
#include "sr_classifier.h"
#include <uapi/linux/can.h>
#include <linux/can/skb.h>

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

#ifdef DEBUG_EVENT_MEDIATOR
static SR_8 module_name[] = "em";

static SR_8 get_path(struct dentry *dentry, SR_8 *buffer, SR_32 len)
{
	SR_8 path[SR_MAX_PATH_SIZE], *path_ptr;
	
	path_ptr = dentry_path_raw(dentry, path, SR_MAX_PATH_SIZE);
	if (IS_ERR(path))
		return SR_ERROR;

	strncpy(buffer, path_ptr, MIN(len, 1+strlen(path_ptr)));
	return SR_SUCCESS;
}
#endif /* DEBUG_EVENT_MEDIATOR */

const event_name hook_event_names[MAX_HOOK] = {
	{HOOK_MKDIR,			"mkdir"},
	{HOOK_UNLINK,			"unlink"},
	{HOOK_SYMLINK,			"symlink"},
	{HOOK_RMDIR,			"rmdir"},
	{HOOK_CHMOD,			"chmod"},
	{HOOK_INODE_CREATE,		"inode_create"},
	{HOOK_FILE_OPEN,		"file_open"},
	{HOOK_INODE_LINK,		"inode_link"},
	{HOOK_INODE_LINK,		"in_connection"},
	{HOOK_SOCK_MSG_SEND,	"sock_send_msg"},
};


extern SR_32 sr_vsentryd_pid; //TODO: get sr_engine pid from chdrv open fops
#define HOOK_FILTER		if(hook_filter()) return 0;
/* TODO: design robust hook filter */
static SR_32 hook_filter(void)
{
	if ((sr_vsentryd_pid) == (current->pid)-1)
		return SR_TRUE;
		
	return SR_FALSE;
}

#ifdef DEBUG
/* parsing data helper functions */
static void parse_sinaddr(const struct in_addr saddr, SR_8* buffer, SR_32 length)
{
	snprintf(buffer, length, "%d.%d.%d.%d",
		(saddr.s_addr&0xFF),
		((saddr.s_addr&0xFF00)>>8),
		((saddr.s_addr&0xFF0000)>>16),
		((saddr.s_addr&0xFF000000)>>24));
}
#endif // DEBUG

SR_32 vsentry_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	disp.fileinfo.id.event = HOOK_MKDIR;
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_MKDIR].name);
	disp.fileinfo.id.gid = (SR_32)rcred->gid.val;
	disp.fileinfo.id.tid = (SR_32)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	SR_U8 		filename[128];
	SR_U8 		fullpath[128];
#pragma GCC diagnostic pop	
	strncpy(filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	if (SR_SUCCESS != get_path(dentry->d_parent, fullpath, sizeof(fullpath)))
		strncpy(fullpath, "NA", 3);
	
	sal_kernel_print_info("[%s:HOOK %s] parent inode=%u, file=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[HOOK_MKDIR].name,
			disp.fileinfo.parent_inode,
			filename, 
			fullpath, 
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
	disp.fileinfo.id.event = HOOK_UNLINK;
	if (dentry->d_inode)
		disp.fileinfo.current_inode = dentry->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_UNLINK].name);
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_UNLINK].name);

	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	SR_U8 		filename[128];
	SR_U8 		fullpath[128];
#pragma GCC diagnostic pop		
	strncpy(filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	get_path(dentry, fullpath, sizeof(fullpath));

	sal_kernel_print_info("[%s:HOOK %s] inode=%u, parent_inode=%u, file=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[HOOK_UNLINK].name,
			disp.fileinfo.current_inode,
			disp.fileinfo.parent_inode,
			filename, 
			fullpath, 
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
	disp.fileinfo.id.event = HOOK_SYMLINK;
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_SYMLINK].name);

	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	SR_U8 		filename[128];
	SR_U8 		fullpath[128];
#pragma GCC diagnostic pop	
	strncpy(disp.fileinfo.filename, (char *)name,
		MIN(sizeof(filename), 1+strlen(name)));
	get_path(dentry, fullpath, sizeof(fullpath));
	sal_kernel_print_info("[%s:HOOK %s] parent_inode=%u, file=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[HOOK_SYMLINK].name,
			disp.fileinfo.parent_inode,
			filename, 
			fullpath, 
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
	disp.fileinfo.id.event = HOOK_RMDIR;
	if (dentry->d_inode)
		disp.fileinfo.current_inode = dentry->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] inode in null\n", hook_event_names[HOOK_RMDIR].name);
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_RMDIR].name);
		
	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[128];
	SR_U8 		fullpath[128];
#pragma GCC diagnostic pop	
	strncpy(filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, fullpath, sizeof(fullpath));
	sal_kernel_print_info("[%s:HOOK %s] inode=%u, parent_inode=%u, file=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[HOOK_RMDIR].name,
			disp.fileinfo.current_inode,
			disp.fileinfo.parent_inode,
			filename, 
			fullpath, 
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
	
	if (sock->sk->sk_family != AF_INET) { // TODO: AF_INET6
		return 0;
	} 

	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	disp.tuple_info.id.event = HOOK_IN_CONNECTION;
	//disp.tuple_info.saddr.v4addr.s_addr = sal_packet_src_addr(skb);
	disp.tuple_info.daddr.v4addr.s_addr = ntohl(((struct sockaddr_in *)address)->sin_addr.s_addr);
	//disp.tuple_info.sport = sal_packet_src_port(skb);
	disp.tuple_info.dport = ntohs(((struct sockaddr_in *)address)->sin_port);
	disp.tuple_info.ip_proto = sock->sk->sk_protocol;

#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("vsentry_socket_connect=%lx[%d] -> %lx[%d]\n",
			(unsigned long)disp.tuple_info.saddr.v4addr.s_addr,
			disp.tuple_info.sport,
			(unsigned long)disp.tuple_info.daddr.v4addr.s_addr,
			disp.tuple_info.dport);
#endif /* DEBUG_EVENT_MEDIATOR */

	/* call dispatcher */
	if (disp_socket_connect(&disp) == SR_CLS_ACTION_ALLOW) {
		return 0;
	} else {
		return -EACCES;
	}
}

SR_32 vsentry_incoming_connection(struct sk_buff *skb)
{
	disp_info_t disp;

	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	disp.tuple_info.id.event = HOOK_IN_CONNECTION;
	disp.tuple_info.saddr.v4addr.s_addr = sal_packet_src_addr(skb);
	disp.tuple_info.daddr.v4addr.s_addr = sal_packet_dest_addr(skb);
	disp.tuple_info.sport = sal_packet_src_port(skb);
	disp.tuple_info.dport = sal_packet_dest_port(skb);
	disp.tuple_info.ip_proto = sal_packet_ip_proto(skb);

#ifdef DEBUG_EVENT_MEDIATOR
	sal_kernel_print_info("vsentry_incoming_connection=%lx[%d] -> %lx[%d]\n",
			(unsigned long)disp.tuple_info.saddr.v4addr.s_addr,
			disp.tuple_info.sport,
			(unsigned long)disp.tuple_info.daddr.v4addr.s_addr,
			disp.tuple_info.dport);
#endif /* DEBUG_EVENT_MEDIATOR */

	/* call dispatcher */
	return (disp_incoming_connection(&disp));
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
	disp.fileinfo.id.event = HOOK_CHMOD;
	if (path->dentry->d_inode)
		disp.fileinfo.current_inode = path->dentry->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] inode in null\n", hook_event_names[HOOK_CHMOD].name);
	if ((path->dentry->d_parent) && (path->dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = path->dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_CHMOD].name);
		
	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		fullpath[128];
#pragma GCC diagnostic pop	
	get_path(path->dentry, fullpath, sizeof(fullpath));

	sal_kernel_print_info("[%s:HOOK %s] inode=%u, parent_inode=%u, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[HOOK_CHMOD].name,
			disp.fileinfo.current_inode,
			disp.fileinfo.parent_inode,
			fullpath, 
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
	disp.fileinfo.id.event = HOOK_INODE_CREATE;
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_INODE_CREATE].name);
		
	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[128];
	SR_U8 		fullpath[128];
#pragma GCC diagnostic pop
	strncpy(disp.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, fullpath, sizeof(fullpath));
	sal_kernel_print_info("[%s:HOOK %s] parent_inode=%u, path=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[HOOK_INODE_CREATE].name,
			disp.fileinfo.parent_inode,
			fullpath, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.gid, 
			disp.fileinfo.id.tid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return disp_inode_create(&disp);
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
	disp.fileinfo.id.event = HOOK_FILE_OPEN;
	if (file->f_path.dentry->d_inode)
		disp.fileinfo.current_inode = file->f_path.dentry->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] inode in null\n", hook_event_names[HOOK_FILE_OPEN].name);
	if ((file->f_path.dentry->d_parent) && (file->f_path.dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = file->f_path.dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_FILE_OPEN].name);
		
	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[128];
#pragma GCC diagnostic pop
	get_path(file->f_path.dentry, filename, sizeof(filename));
	sal_kernel_print_info("[%s:HOOK %s] inode=%u, parent_inode=%u, file=%s, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[HOOK_FILE_OPEN].name,
			disp.fileinfo.current_inode,
			disp.fileinfo.parent_inode,
			filename, 
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
	disp.fileinfo.id.event = HOOK_INODE_LINK;	
	if ((new_dentry->d_parent) && (new_dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = new_dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] parent inode in null\n", hook_event_names[HOOK_INODE_LINK].name);
	if ((old_dentry->d_parent) && (old_dentry->d_parent->d_inode))
		disp.fileinfo.old_inode = old_dentry->d_parent->d_inode->i_ino;
	else
		sal_kernel_print_err("[%s] old parent inode in null\n", hook_event_names[HOOK_INODE_LINK].name);

	disp.fileinfo.id.gid = (int)rcred->gid.val;
	disp.fileinfo.id.tid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[128];
	SR_U8 		fullpath[128];
	SR_U8 		old_path[128];
#pragma GCC diagnostic pop
	strncpy(filename, old_dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(old_dentry->d_iname)));
	get_path(new_dentry, fullpath, sizeof(fullpath));
	get_path(old_dentry, old_path, sizeof(old_path));
	sal_kernel_print_info("[%s:HOOK %s] parent_inode=%u, old_parent_inode=%u, file=%s, path=%s, old_path=%s pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[HOOK_INODE_LINK].name,
			disp.fileinfo.parent_inode,
			disp.fileinfo.old_inode,
			filename,
			fullpath,
			old_path, 
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
	return 0;
	// TODO: might want to add some bookkeeping logic here
	
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
	return 0; //return (disp_socket_create(&disp));
}

/* @socket_sendmsg:
 *	Check permission before transmitting a message to another socket.
 *	@sock contains the socket structure.
 *	@msg contains the message to be transmitted.
 *	@size contains the size of message.
 *	Return 0 if permission is granted.
 */
SR_32 vsentry_socket_sendmsg(struct socket *sock,struct msghdr *msg,SR_32 size)
{
	int err;
	int i;
	struct sk_buff *skb;
	struct canfd_frame *cfd;
	const u8 family = sock->sk->sk_family;
	struct socket copy_sock = *sock;
	struct msghdr copy_msg = *msg;
	
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check hook filter */
	HOOK_FILTER
	
	/* gather metadata */
	disp.can_info.id.event = HOOK_SOCK_MSG_SEND;
	disp.can_info.id.gid = (int)rcred->gid.val;
	disp.can_info.id.tid = (int)rcred->uid.val;
	disp.can_info.id.pid = current->pid;

	switch (family) {
		case AF_CAN:
			skb = sock_alloc_send_skb(copy_sock.sk, size + sizeof(struct can_skb_priv),
						  copy_msg.msg_flags & MSG_DONTWAIT, &err);
						  
			err = memcpy_from_msg(skb_put(skb, size), &copy_msg, size);
			if (err < 0) {
				printk ("fail to copy can msg from user!\n");
				/* we cannot handle this message */
				return 0;
			}
			cfd = (struct canfd_frame *)skb->data;
			disp.can_info.msg_id = (SR_U32)cfd->can_id;
			disp.can_info.payload_len = cfd->len;
			for (i = 0; i < cfd->len; i++) {
				disp.can_info.payload[i] = cfd->data[i];
			}
			sal_debug_em("[%s:HOOK %s] family=af_can msd_id=%x payload_len=%d payload= %02x %02x %02x %02x %02x %02x %02x %02x pid=%d, gid=%d, tid=%d\n", 
						module_name,
						hook_event_names[HOOK_SOCK_MSG_SEND].name,
						disp.can_info.msg_id,
						disp.can_info.payload_len,
						disp.can_info.payload[0],
						disp.can_info.payload[1],
						disp.can_info.payload[2],
						disp.can_info.payload[3],
						disp.can_info.payload[4],
						disp.can_info.payload[5],
						disp.can_info.payload[6],
						disp.can_info.payload[7],
						disp.can_info.id.pid,
						disp.can_info.id.gid, 
						disp.can_info.id.tid);
			/* call dispatcher */
			kfree_skb(skb);
			return (disp_socket_sendmsg(&disp));
			break;
		default:
			/* we are not interested in the message */
			break;
	}
	
	return 0;
}
