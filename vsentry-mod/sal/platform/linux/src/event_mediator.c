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
#include "sr_actions_common.h"

#include <uapi/linux/can.h>
#include <linux/can/skb.h>
#include <linux/binfmts.h>
#include "sr_control.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#endif

//#define DEBUG_EVENT_MEDIATOR
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

static SR_8 get_path(struct dentry *dentry, SR_8 *buffer, SR_32 len)
{
	SR_8 path[SR_MAX_PATH_SIZE], *path_ptr;
	
	path_ptr = dentry_path_raw(dentry, path, SR_MAX_PATH_SIZE);
	if (IS_ERR(path))
		return SR_ERROR;

	if (strlen(path_ptr) > SR_MAX_PATH_SIZE) { 
		CEF_log_event(SR_CEF_CID_SYSTEM, "Get path error" , SEVERITY_HIGH, 
						"get_path path length:%d exeeds max path len(%d)", strlen(path_ptr), SR_MAX_PATH_SIZE);
		return SR_ERROR;
	}

	strncpy(buffer, path_ptr, MIN(len, 1+strlen(path_ptr)));
	return SR_SUCCESS;
}

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
	{HOOK_INODE_RENAME,		"inode_rename"},
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

#if 0 //DEBUG function
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
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error reading parent inode" , SEVERITY_HIGH, 
						"[%s] parent inode in null\n", hook_event_names[HOOK_MKDIR].name);
	disp.fileinfo.id.uid = (SR_32)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop	
	strncpy(filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	if (SR_SUCCESS != get_path(dentry->d_parent, fullpath, sizeof(fullpath)))
		strncpy(fullpath, "NA", 3);
	
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW, 
					"[HOOK %s] parent inode=%u, file=%s, path=%s, pid=%d, uid=%d\n", 
					hook_event_names[HOOK_MKDIR].name,
					disp.fileinfo.parent_inode,
					filename, 
					fullpath, 
					disp.fileinfo.id.pid,
					disp.fileinfo.id.uid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	rc =  disp_mkdir(&disp);
	if (rc == 0) {
		if (get_path(dentry, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH, 
							"File operation denied, file path it to long");
			return -EACCES;
		}
		if (!sr_cls_filter_path_is_match(disp.fileinfo.fullpath) && disp_file_created(&disp) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
							"[%s] failed disp_file_created\n", hook_event_names[HOOK_INODE_CREATE].name);
		}
	}

	return rc;
}

SR_32 vsentry_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred = ts->real_cred;		
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER
	
	/* gather metadata */
	if (dentry->d_inode)
		disp.fileinfo.current_inode = dentry->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] parent inode in null\n", hook_event_names[HOOK_UNLINK].name);
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] parent inode in null\n", hook_event_names[HOOK_UNLINK].name);

	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop		
	strncpy(filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	get_path(dentry, fullpath, sizeof(fullpath));

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW, 
					"[HOOK %s] inode=%u, parent_inode=%u, file=%s, path=%s, pid=%d, uid=%d\n", 
					hook_event_names[HOOK_UNLINK].name,
					disp.fileinfo.current_inode,
					disp.fileinfo.parent_inode,
					filename, 
					fullpath, 
					disp.fileinfo.id.pid,
					disp.fileinfo.id.uid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	rc = disp_inode_unlink(&disp);
	if (rc == 0) {
		if (disp.fileinfo.current_inode)
			disp_inode_remove(disp.fileinfo.current_inode);
	}

	return rc;
}

int vsentry_inode_rename(struct inode *old_dir, struct dentry *old_dentry, struct inode *new_dir,struct dentry *new_dentry)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred = ts->real_cred;		
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER
	
	/* gather metadata */
	if (old_dentry->d_inode)
	    disp.fileinfo.old_inode = old_dentry->d_inode->i_ino;
	if (new_dentry->d_inode)
	    disp.fileinfo.current_inode = new_dentry->d_inode->i_ino;
	if (old_dir)
           disp.fileinfo.old_parent_inode = old_dir->i_ino;
	if (new_dir)
           disp.fileinfo.parent_inode = new_dir->i_ino;

	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_WRITE | SR_FILEOPS_READ;

#ifdef DEBUG_EVENT_MEDIATOR
        CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
						"[HOOK %s] old inode=%d, new inode=%d, pid=%d, uid=%d\n",
                        hook_event_names[HOOK_INODE_RENAME].name,
                        old_dentry->d_inode ? old_dentry->d_inode->i_ino : -1,
                        new_dentry->d_inode ? new_dentry->d_inode->i_ino : -1,
                        disp.fileinfo.parent_inode,
                        disp.fileinfo.id.pid,
                        disp.fileinfo.id.uid);
#endif /* DEBUG_EVENT_MEDIATOR */

	/* 
	mv existing_file1 exsiting_file2 - The inode of file2, which is new dentry id remoed, its rules shuld be removed.
	The inode of file1 is retained, so as its rules. its rules should be removed as well since 
	the file has a new name now. For the new name the relevent rules are created.
	*/
	rc = disp_inode_rename(&disp);
	if (rc == 0) {
		if (get_path(new_dentry, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "Error" , SEVERITY_HIGH, "File operation denied, file path it to long");
			return -EACCES;
		}
		if (disp.fileinfo.current_inode)
			disp_inode_remove(disp.fileinfo.current_inode);
		if (disp.fileinfo.old_inode)
			disp_inode_remove(disp.fileinfo.old_inode);
		if(!sr_cls_filter_path_is_match(disp.fileinfo.fullpath) && disp_file_created(&disp) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
							"[%s] failed disp_file_created\n", hook_event_names[HOOK_INODE_RENAME].name);
 		}
	}

       return rc;
}

SR_32 vsentry_inode_symlink(struct inode *dir, struct dentry *dentry, const SR_8 *name)
{
	disp_info_t disp;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] parent inode in null\n", hook_event_names[HOOK_SYMLINK].name);

	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop	
	strncpy(disp.fileinfo.filename, (char *)name,
		MIN(sizeof(filename), 1+strlen(name)));
	get_path(dentry, fullpath, sizeof(fullpath));
		CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
				"[HOOK %s] parent_inode=%u, file=%s, path=%s, pid=%d, uid=%d\n", 
				hook_event_names[HOOK_SYMLINK].name,
				disp.fileinfo.parent_inode,
				filename, 
				fullpath, 
				disp.fileinfo.id.pid,
				disp.fileinfo.id.uid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_inode_symlink(&disp));
}

SR_32 vsentry_inode_rmdir(struct inode *dir, struct dentry *dentry)
{
	SR_32 rc;
	disp_info_t disp;
	
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if (dentry->d_inode)
		disp.fileinfo.current_inode = dentry->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] inode in null\n", hook_event_names[HOOK_RMDIR].name);
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] parent inode in null\n", hook_event_names[HOOK_RMDIR].name);
		
	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop	
	strncpy(filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, fullpath, sizeof(fullpath));
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
					"[HOOK %s] inode=%u, parent_inode=%u, file=%s, path=%s, pid=%d, uid=%d\n", 
					hook_event_names[HOOK_RMDIR].name,
					disp.fileinfo.current_inode,
					disp.fileinfo.parent_inode,
					filename, 
					fullpath, 
					disp.fileinfo.id.pid,
					disp.fileinfo.id.uid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	rc = disp_rmdir(&disp);
	if (rc == 0) {
		if (disp.fileinfo.current_inode)
			disp_inode_remove(disp.fileinfo.current_inode);
	}

	return rc;
}

SR_32 vsentry_socket_connect(struct socket *sock, struct sockaddr *address, SR_32 addrlen)
{
	disp_info_t disp;
        struct task_struct *ts = current;
        const struct cred *rcred= ts->real_cred;
	
	if (sock->sk->sk_family != AF_INET) { // TODO: AF_INET6
		return 0;
	} 

	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	disp.tuple_info.id.uid = (int)rcred->uid.val;
	disp.tuple_info.id.pid = current->pid;
	disp.tuple_info.saddr.v4addr.s_addr = 0;
	disp.tuple_info.sport = 0;
	disp.tuple_info.id.pid = current->pid;

	disp.tuple_info.daddr.v4addr.s_addr = ntohl(((struct sockaddr_in *)address)->sin_addr.s_addr);
	disp.tuple_info.dport = ntohs(((struct sockaddr_in *)address)->sin_port);
	disp.tuple_info.ip_proto = sock->sk->sk_protocol;

#ifdef DEBUG_EVENT_MEDIATOR
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
					"vsentry_socket_connect=%lx[%d] -> %lx[%d]\n",
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
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	disp.tuple_info.id.uid = UID_ANY;
	disp.tuple_info.saddr.v4addr.s_addr = sal_packet_src_addr(skb);
	disp.tuple_info.daddr.v4addr.s_addr = sal_packet_dest_addr(skb);
	disp.tuple_info.sport = sal_packet_src_port(skb);
	disp.tuple_info.dport = sal_packet_dest_port(skb);
	disp.tuple_info.ip_proto = sal_packet_ip_proto(skb);

//#ifdef DEBUG_EVENT_MEDIATOR
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
					"vsentry_incoming_connection=%lx[%d] -> %lx[%d]\n",
					(unsigned long)disp.tuple_info.saddr.v4addr.s_addr,
					disp.tuple_info.sport,
					(unsigned long)disp.tuple_info.daddr.v4addr.s_addr,
					disp.tuple_info.dport);
//#endif /* DEBUG_EVENT_MEDIATOR */

	/* call dispatcher */
	return (disp_incoming_connection(&disp));
}


SR_32 vsentry_path_chmod(struct path *path, umode_t mode)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if (path->dentry->d_inode)
		disp.fileinfo.current_inode = path->dentry->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] inode in null\n", hook_event_names[HOOK_CHMOD].name);
	disp.fileinfo.parent_inode = 0;
		
	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop	
	get_path(path->dentry, fullpath, sizeof(fullpath));
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
					"[HOOK %s] inode=%u, parent_inode=%u, path=%s, pid=%d, uid=%d\n", 
					hook_event_names[HOOK_CHMOD].name,
					disp.fileinfo.current_inode,
					disp.fileinfo.parent_inode,
					fullpath, 
					disp.fileinfo.id.pid,
					disp.fileinfo.id.uid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	return (disp_path_chmod(&disp));
}

SR_32 vsentry_inode_create(struct inode *dir, struct dentry *dentry, umode_t mode)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if ((dentry->d_parent) && (dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] parent inode in null\n", hook_event_names[HOOK_INODE_CREATE].name);
		
	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop
	strncpy(disp.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, fullpath, sizeof(fullpath));
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
					"[HOOK %s] parent_inode=%u, path=%s, pid=%d, uid=%d\n", 
					hook_event_names[HOOK_INODE_CREATE].name,
					disp.fileinfo.parent_inode,
					fullpath, 
					disp.fileinfo.id.pid,
					disp.fileinfo.id.uid);
#endif /* DEBUG_EVENT_MEDIATOR */
	
	/* call dispatcher */
	rc = disp_inode_create(&disp);
	if (rc == 0) {
		if (get_path(dentry, disp.fileinfo.fullpath, sizeof(disp.fileinfo.fullpath)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "Error" , SEVERITY_HIGH, "File operation denied, file path it to long");
			return -EACCES;
		}
		if (!sr_cls_filter_path_is_match(disp.fileinfo.fullpath) && disp_file_created(&disp) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "Error" , SEVERITY_HIGH, 
							"[%s] failed disp_file_created\n", hook_event_names[HOOK_INODE_CREATE].name);
		}
	}
	return rc;
}

//__attribute__ ((unused))
SR_32 vsentry_file_open(struct file *file, const struct cred *cred)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if (file->f_path.dentry->d_inode)
		disp.fileinfo.current_inode = file->f_path.dentry->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] inode in null\n", hook_event_names[HOOK_FILE_OPEN].name);
	disp.fileinfo.parent_inode = 0;
		
	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	if (file->f_mode & FMODE_WRITE)
		disp.fileinfo.fileop |= SR_FILEOPS_WRITE;
	if (file->f_mode & FMODE_READ)
		disp.fileinfo.fileop |= SR_FILEOPS_READ;
	if (file->f_mode & FMODE_EXEC)
		disp.fileinfo.fileop |= SR_FILEOPS_EXEC;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop
	get_path(file->f_path.dentry, filename, sizeof(filename));
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
					"[HOOK %s] inode=%u, parent_inode=%u, file=%s, pid=%d, uid=%d\n", 
					hook_event_names[HOOK_FILE_OPEN].name,
					disp.fileinfo.current_inode,
					disp.fileinfo.parent_inode,
					filename, 
					disp.fileinfo.id.pid,
					disp.fileinfo.id.uid);
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
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if ((new_dentry->d_parent) && (new_dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = new_dentry->d_parent->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] parent inode in null\n", hook_event_names[HOOK_INODE_LINK].name);
	if ((old_dentry->d_parent) && (old_dentry->d_parent->d_inode))
		disp.fileinfo.old_parent_inode = old_dentry->d_parent->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
						"[%s] old parent inode in null\n", hook_event_names[HOOK_INODE_LINK].name);
	if (old_dentry->d_inode)
		disp.fileinfo.old_inode = old_dentry->d_inode->i_ino;

	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_WRITE | SR_FILEOPS_READ;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
	SR_U8 		old_path[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop
	strncpy(filename, old_dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(old_dentry->d_iname)));
	get_path(new_dentry, fullpath, sizeof(fullpath));
	get_path(old_dentry, old_path, sizeof(old_path));
	CEF_log_event(SR_CEF_CID_SYSTEM, "Event Mediator" , SEVERITY_LOW,
					"[HOOK %s] parent_inode=%u, old_parent_inode=%u, file=%s, path=%s, old_path=%s pid=%d, uid=%d\n", 
					hook_event_names[HOOK_INODE_LINK].name,
					disp.fileinfo.parent_inode,
					disp.fileinfo.old_inode,
					filename,
					fullpath,
					old_path, 
					disp.fileinfo.id.pid,
					disp.fileinfo.id.uid);
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
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	strncpy(disp.socket_info.family, protocol_family[family],
		MIN(sizeof(disp.socket_info.family), 1+strlen(protocol_family[family])));
	sprintf(disp.socket_info.type,"socket type: %d",type); //TODO: remove it!!!
	/*TODO: modify strings to enums !! */
		
	disp.socket_info.protocol = protocol;
	disp.socket_info.kern = kern;
	
	disp.socket_info.id.uid = (int)rcred->uid.val;
	disp.socket_info.id.pid = current->pid;
	
#ifdef DEBUG_EVENT_MEDIATOR
	/*TODO: handle debug print */
#endif /* DEBUG_EVENT_MEDIATOR */

	/* call dispatcher */
	return 0; //return (disp_socket_create(&disp));
}

#ifdef CONFIG_STAT_ANALYSIS
/*
 * @inet_conn_established
   relevant only for trhe server.
 */
void vsentry_inet_conn_established(struct sock *sk, struct sk_buff *skb)
{
	sr_connection_data_t con = {};
	SR_U32 rc;

	con.con_id.saddr.v4addr = ntohl(sk->sk_rcv_saddr);
 	con.con_id.daddr.v4addr = ntohl(sk->sk_daddr);
	con.con_id.ip_proto = 6;
 	con.con_id.sport = ntohs(sk->sk_num);
    con.con_id.dport = ntohs(sk->sk_dport);

	if ((rc = sr_stat_connection_insert(&con, SR_CONNECTION_NONBLOCKING | SR_CONNECTION_ATOMIC)) != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
								"ERROR failed sr_stat_connection_insert\n");
                return;
	}
}

int vsentry_inet_conn_request(struct sock *sk, struct sk_buff *skb, struct request_sock *req)
{
	sr_connection_data_t con = {};
	struct tcphdr *tcphdr = (struct tcphdr *) skb_transport_header(skb);
	SR_U32 rc;

	if (skb) {
		struct iphdr *ipp = (struct iphdr *)skb_network_header(skb);
		con.con_id.saddr.v4addr = ntohl(ipp->daddr);
		con.con_id.daddr.v4addr = ntohl(ipp->saddr);
        con.con_id.ip_proto = 6;
        con.con_id.sport = ntohs(tcphdr->dest);
        con.con_id.dport = ntohs(tcphdr->source);
		if ((rc = sr_stat_connection_insert(&con, SR_CONNECTION_NONBLOCKING | SR_CONNECTION_ATOMIC)) != SR_SUCCESS) {
               		CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
									"ERROR failed sr_stat_connection_insert\n");
			return 0;
        }
	}

	return 0;
}
#endif

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
#ifdef CONFIG_STAT_ANALYSIS
	sr_connection_data_t con = {}, *conp;
	SR_U32 rc;
#endif
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER
	
	switch (family) {
		case AF_CAN:
			disp.can_info.id.uid = (int)rcred->uid.val;
			disp.can_info.id.pid = current->pid;
			skb = sock_alloc_send_skb(copy_sock.sk, size + sizeof(struct can_skb_priv),
						  copy_msg.msg_flags & MSG_DONTWAIT, &err);
						  
			err = memcpy_from_msg(skb_put(skb, size), &copy_msg, size);
			if (err < 0) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
								"fail to copy can msg from user!\n");
				/* we cannot handle this message */
				return 0;
			}
			cfd = (struct canfd_frame *)skb->data;
			disp.can_info.msg_id = (SR_U32)cfd->can_id;
			disp.can_info.payload_len = cfd->len;
			for (i = 0; i < cfd->len; i++) {
				disp.can_info.payload[i] = cfd->data[i];
			}
			/* TODO: remove it!!! this is only for the demo purposes */
                        /*if (cfd->len > 7 && disp.can_info.payload[1] == 0 && 
                        	disp.can_info.payload[2] == 0 && 
                        	disp.can_info.payload[3] == 0 && 
                        	disp.can_info.payload[4] == 0 && 
                        	disp.can_info.payload[5] == 0 && 
                        	disp.can_info.payload[6] == 0) {
							return 0;
                        }*/
			CEF_log_debug(SR_CEF_CID_SYSTEM, "Event Mediator" , SEVERITY_LOW,
							"[HOOK %s] family=af_can msd_id=%x payload_len=%d payload= %02x %02x %02x %02x %02x %02x %02x %02x pid=%d, uid=%d\n", 
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
							disp.fileinfo.id.pid,
							disp.fileinfo.id.uid);

			/* call dispatcher */
			kfree_skb(skb);
			return (disp_socket_sendmsg(&disp));
			break;
		case AF_INET:
			if (!sock->sk)
				return 0;
#ifdef CONFIG_STAT_ANALYSIS
			con.con_id.saddr.v4addr = ntohl(sock->sk->sk_rcv_saddr);
			con.con_id.daddr.v4addr = ntohl(sock->sk->sk_daddr);
			con.con_id.ip_proto = sock->sk->sk_protocol;
			/* Strange : sk_num is host order, sk_dport is network oredr WTF? */
			con.con_id.sport = sock->sk->sk_num;
			con.con_id.dport = ntohs(sock->sk->sk_dport);
			con.pid = current->tgid;

			if ((conp = sr_stat_connection_lookup(&con.con_id))) {
				if ((rc = sr_stat_connection_update_counters(conp, current->tgid, 0, 0, size, 1)) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
											"ERROR failed sr_stat_connection_update_counters\n");
                			return 0;
				}
			} else {
				con.tx_bytes = size;
				con.tx_msgs = 1;
        			if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
                			CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
											"ERROR failed sr_stat_connection_insert\n");
                			return 0;
        			}
			}
#endif

			/* Hook is relevant only for UDP */
			if (sock->sk->sk_protocol != IPPROTO_UDP)
				return 0;
			/* gather metadata */
			disp.tuple_info.id.uid = (int)rcred->uid.val;
			disp.tuple_info.id.pid = current->pid;
			disp.tuple_info.saddr.v4addr.s_addr = ntohl(sock->sk->sk_rcv_saddr);
			disp.tuple_info.daddr.v4addr.s_addr = ntohl(sock->sk->sk_daddr);
   			disp.tuple_info.dport = sock->sk->sk_num;
			disp.tuple_info.sport = ntohs(sock->sk->sk_dport);
			disp.tuple_info.ip_proto = sock->sk->sk_protocol;
			disp.tuple_info.size = size;
#ifdef DEBUG_EVENT_MEDIATOR
        		CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
								"vsentry_socket_connect=%lx[%d] -> %lx[%d]\n",
                        		(unsigned long)disp.tuple_info.saddr.v4addr.s_addr,
                        		disp.tuple_info.sport,
                        		(unsigned long)disp.tuple_info.daddr.v4addr.s_addr,
                        		disp.tuple_info.dport);
#endif /* DEBUG_EVENT_MEDIATOR */

			/* call dispatcher */
			if (disp_ipv4_sendmsg(&disp) == SR_CLS_ACTION_ALLOW) {
				return 0;
			} else {
				return -EACCES;
			}
			break;
		default:
			/* we are not interested in the message */
			break;
	}
	
	return 0;
}

/* @socket_recvmsg:
 *      Check permission before receiving a message from a socket.
 *      @sock contains the socket structure.
 *      @msg contains the message structure.
 *      @size contains the size of message structure.
 *      @flags contains the operational flags.
 *      Return 0 if permission is granted.
 */
int vsentry_socket_recvmsg(struct socket *sock,struct msghdr *msg,int size,int flags)
{
	const u8 family = sock->sk->sk_family;
#ifdef CONFIG_STAT_ANALYSIS
	sr_connection_data_t *conp, con = {};
#endif
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;		

	switch (family) {
		case AF_INET:
#ifdef CONFIG_STAT_ANALYSIS
			if (sock->sk->sk_protocol == IPPROTO_TCP && sock->sk->sk_rcv_saddr && sock->sk->sk_daddr) {
				con.con_id.ip_proto = sock->sk->sk_protocol;
        			con.con_id.saddr.v4addr = ntohl(sock->sk->sk_rcv_saddr);
        			con.con_id.daddr.v4addr = ntohl(sock->sk->sk_daddr);
				/* Strange : sk_num is host order, sk_dport is network oredr WTF? */
        			con.con_id.sport = sock->sk->sk_num;
        			con.con_id.dport = ntohs(sock->sk->sk_dport);
				con.pid = current->tgid;

				if ((conp = sr_stat_connection_lookup(&con.con_id))) {
					/* update pid */
					conp->pid = current->tgid;
				} else {
					/* Create a connection */
					if (sr_stat_connection_insert(&con, 0) != SR_SUCCESS) {
						CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
										"ERROR failed sr_stat_connection_insert\n");
						return 0;
        			}
				}
				return 0;
			}
#endif

			disp.tuple_info.id.uid = (int)rcred->uid.val;
			disp.tuple_info.id.pid = current->pid;
       			disp.tuple_info.daddr.v4addr.s_addr = ntohl(sock->sk->sk_rcv_saddr); // This is the local address
			disp.tuple_info.saddr.v4addr.s_addr = ntohl(sock->sk->sk_daddr); // This is the forighen address
 			/* sk_dport is network orderm sk_num is host order, WTF??? */
       			disp.tuple_info.sport = ntohs(sock->sk->sk_dport);
       			disp.tuple_info.dport = sock->sk->sk_num;
       			disp.tuple_info.ip_proto = sock->sk->sk_protocol;
				disp.tuple_info.size = size;

#ifdef CONFIG_STAT_ANALYSIS
			sr_stat_port_update(disp.tuple_info.sport, current->tgid);
#endif
				
#ifdef DEBUG_EVENT_MEDIATOR
        		CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
								"vsentry_socket_connect=%lx[%d] -> %lx[%d]\n",
                        		(unsigned long)disp.tuple_info.saddr.v4addr.s_addr,
                        		disp.tuple_info.sport,
                        		(unsigned long)disp.tuple_info.daddr.v4addr.s_addr,
                        		disp.tuple_info.dport);
#endif /* DEBUG_EVENT_MEDIATOR */

			/* call dispatcher */
			if (disp_ipv4_recvmsg(&disp) == SR_CLS_ACTION_ALLOW) {
				return 0;
			} else {
				return -EACCES;
			}
			break;
		default:
			/* we are not interested in the message */
			break;
         }

	return 0;
}

SR_32 vsentry_bprm_check_security(struct linux_binprm *bprm)
{
	disp_info_t disp;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	if (bprm->file->f_inode) //redundent check?
		disp.fileinfo.current_inode = bprm->file->f_inode->i_ino;
		
	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->pid;
	disp.fileinfo.fileop = SR_FILEOPS_EXEC; // open requires exec access
    
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic pop
	CEF_log_event(SR_CEF_CID_SYSTEM, "Info" , SEVERITY_LOW,
			"[HOOK %s] inode=%u, file=%s, pid=%d, uid=%d\n", 
			hook_event_names[HOOK_BINPERM].name,
			disp.fileinfo.current_inode,
			bprm->filename, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.uid);
#endif     
    return (disp_file_exec(&disp));
}

void vsentry_task_free(struct task_struct *task)
{
	if (!task)
		return;
	sr_cls_process_del(task->pid);
// It is a problem to send process die message since its intefiere with rate tracking.
#if 0  
	sr_stat_analysis_report_porcess_die(task->pid);
#endif
}

