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
#include <linux/time.h>
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#endif
#include "sr_cls_sk_process.h"
#include "sr_event_collector.h"
#include "sr_sal_common.h"

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
	if (IS_ERR(path_ptr))
		return SR_ERROR;

	if (strlen(path_ptr) > SR_MAX_PATH_SIZE) { 
		CEF_log_event(SR_CEF_CID_SYSTEM, "Get path error" , SEVERITY_HIGH, 
						"get_path path length:%d exeeds max path len(%d)", strlen(path_ptr), SR_MAX_PATH_SIZE);
		return SR_ERROR;
	}

	strncpy(buffer, path_ptr, MIN(len, 1+strlen(path_ptr)));
	return SR_SUCCESS;
}

static SR_32 sr_get_full_path(struct file * file, char *file_full_path, SR_U32 max_len)
{
	SR_32 mount_point_length = 0;
	struct path path;

	if (!file)
		return SR_ERROR;

	memset(file_full_path, 0, max_len);

	path = file->f_path;
	/* inc reference counter */
	if (unlikely(!dget(file->f_path.dentry)))
		return SR_ERROR;

	if (follow_up(&path)) {
		/* if foolow_up succeed, it dec the reference counter */
		get_path(path.dentry, file_full_path, max_len);
		if (memcmp(file_full_path, "/usr", 4) == 0) {
			memset(file_full_path, 0, 4);
		} else {
			mount_point_length = strlen(file_full_path);
			if (mount_point_length == 1) {
				// The mount point is only slash, remove it.
				file_full_path[0] = 0;
				mount_point_length = 0;
			}
		}
	} else {
		/* dec the reference counter */
		dput(file->f_path.dentry);
	}

	if (get_path(file->f_path.dentry, file_full_path + mount_point_length, max_len - mount_point_length) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_FILE, "file operation drop", SEVERITY_HIGH,
				"%s=file path is too long (more then %d bytes)", REASON, SR_MAX_PATH_SIZE);
	    return SR_ERROR;
	}

	return SR_SUCCESS;
}

SR_32 get_process_name(SR_U32 pid, char *exec, SR_U32 max_len)
{
	struct pid *pid_struct;
	struct task_struct *task;
	struct mm_struct *mm;
	SR_32 rc = SR_SUCCESS;

	pid_struct = find_get_pid(pid);
	task = pid_task(pid_struct, PIDTYPE_PID);
	if (!task)
		return SR_ERROR;

	mm = get_task_mm(task);
	if (!mm)
		return SR_ERROR;

	down_read(&mm->mmap_sem);
	rc = sr_get_full_path(mm->exe_file, exec, max_len);
	up_read(&mm->mmap_sem);
	mmput(mm);

	return rc;
}

static const event_name hook_event_names[MAX_HOOK] = {
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

const event_name *event_mediator_hooks_event_names(void)
{
	return hook_event_names;
}

#define HOOK_FILTER		if(hook_filter()) return 0;
/* TODO: design robust hook filter */
static SR_32 hook_filter(void)
{
	//TODO: get sr_engine pid from chdrv open fops
	if ((!in_interrupt()) && ((vsentry_get_pid()) == (current->tgid))) {
		return SR_TRUE;
	}
	// if kernel thread invoked this hook
	/*if ((current->flags & PF_KTHREAD) || !current->mm || !current->mm->exe_file) {
		printk("kthread\n");
		return SR_TRUE;
	}*/

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

static void update_process_info (identifier *id, struct sock *sk, struct task_struct *ts)
{
	sk_process_item_t *process_info_p;
	struct task_struct *task = current;

	if (sk) {
		/* we have sk info, i.e. socket based hook called us */
		if ((process_info_p = sr_cls_sk_process_hash_get(sk))) {
			id->pid = process_info_p->process_info.pid;
			id->uid = process_info_p->process_info.uid;
			if (get_collector_state() == SR_TRUE) {
				/* we are in learn mode, resolve exec fullpath */
				strncpy(id->exec, process_info_p->process_info.exec, SR_MAX_PATH_SIZE);
			}
		} else {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM, "failed to get from hash sk %p", REASON, sk);
		}
	} else if (in_interrupt()) {
		/* we are in interrupt context and we don't have sk info. this should not happen */
		id->pid = 0;
		id->uid = 0;
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM, "%s=failed to get process info within interrupt context", REASON);
	} else {
		/* not socket based hook called us */
		const struct cred *rcred;

		if (ts)
			task = ts;

		rcred = task->real_cred;

		id->pid = task->tgid;
		id->uid = (int)rcred->uid.val;
		if (get_collector_state() == SR_TRUE) {
			/* we are in learn mode, resolve exec fullpath */
			if ((get_process_name(id->pid, id->exec, SR_MAX_PATH_SIZE)) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM, "%s=failed to get process name for pid %d ", REASON, id->pid);
			}
		}
	}
}

SR_32 vsentry_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	disp_info_t disp;
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE
	
	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if ((dentry->d_parent) && (dentry->d_parent->d_inode)){
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
		disp.fileinfo.parent_info = dentry->d_parent;
	}else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error" , SEVERITY_HIGH,
						"%s=[%s] parent inode is null", REASON, hook_event_names[HOOK_MKDIR].name);
	update_process_info(&disp.fileinfo.id, NULL, NULL);
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
	
	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW, 
					"[HOOK %s] parent inode=%u, file=%s, path=%s, pid=%d, uid=%d",
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
							"File operation denied, file path it too long");
			return -EACCES;
		}
		if (!sr_cls_filter_path_is_match(disp.fileinfo.fullpath) && disp_file_created(&disp) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "Error", SEVERITY_HIGH,
							"[%s] failed disp_file_created", hook_event_names[HOOK_INODE_CREATE].name);
		}
	}

	return rc;
}

SR_32 vsentry_inode_unlink(struct inode *dir, struct dentry *dentry)
{
	disp_info_t disp;
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
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] parent inode in null", REASON, hook_event_names[HOOK_UNLINK].name);
	if ((dentry->d_parent) && (dentry->d_parent->d_inode)){
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
		disp.fileinfo.parent_info = dentry->d_parent;
	}else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] parent inode in null", REASON, hook_event_names[HOOK_UNLINK].name);

	update_process_info(&disp.fileinfo.id, NULL, NULL);
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

	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW, 
					"[HOOK %s] inode=%u, parent_inode=%u, file=%s, path=%s, pid=%d, uid=%d",
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
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER
	
	/* gather metadata */
	if (old_dentry->d_inode){
	    disp.fileinfo.old_inode = old_dentry->d_inode->i_ino;
		disp.fileinfo.parent_info = old_dentry->d_parent;
	}if (new_dentry->d_inode)
	    disp.fileinfo.current_inode = new_dentry->d_inode->i_ino;
	if (old_dir)
           disp.fileinfo.old_parent_inode = old_dir->i_ino;
	if (new_dir)
           disp.fileinfo.parent_inode = new_dir->i_ino;

	update_process_info(&disp.fileinfo.id, NULL, NULL);
	disp.fileinfo.fileop = SR_FILEOPS_WRITE | SR_FILEOPS_READ;

#ifdef DEBUG_EVENT_MEDIATOR
        CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
						"[HOOK %s] old inode=%d, new inode=%d, pid=%d, uid=%d",
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
			CEF_log_event(SR_CEF_CID_SYSTEM, "error" , SEVERITY_HIGH, "%s=file operation denied - file path it to long", REASON);
			return -EACCES;
		}
		if (disp.fileinfo.current_inode)
			disp_inode_remove(disp.fileinfo.current_inode);
		if (disp.fileinfo.old_inode)
			disp_inode_remove(disp.fileinfo.old_inode);
		if(!sr_cls_filter_path_is_match(disp.fileinfo.fullpath) && disp_file_created(&disp) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"%s=[%s] failed disp_file_created", REASON, hook_event_names[HOOK_INODE_RENAME].name);
 		}
	}

       return rc;
}

SR_32 vsentry_inode_symlink(struct inode *dir, struct dentry *dentry, const SR_8 *name)
{
	disp_info_t disp;

	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if ((dentry->d_parent) && (dentry->d_parent->d_inode)){
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
		disp.fileinfo.parent_info = dentry->d_parent;
	}else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] parent inode in null", REASON, hook_event_names[HOOK_SYMLINK].name);

	update_process_info(&disp.fileinfo.id, NULL, NULL);
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"

	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop	
	strncpy(disp.fileinfo.filename, (char *)name,
		MIN(sizeof(filename), 1+strlen(name)));
	get_path(dentry, fullpath, sizeof(fullpath));
		CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
				"[HOOK %s] parent_inode=%u, file=%s, path=%s, pid=%d, uid=%d",
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

	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if (dentry->d_inode)
		disp.fileinfo.current_inode = dentry->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] inode in null", REASON, hook_event_names[HOOK_RMDIR].name);
	if ((dentry->d_parent) && (dentry->d_parent->d_inode)){
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
		disp.fileinfo.parent_info = dentry->d_parent;
	}else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] parent inode in null", REASON, hook_event_names[HOOK_RMDIR].name);
		
	update_process_info(&disp.fileinfo.id, NULL, NULL);
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop	
	strncpy(filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, fullpath, sizeof(fullpath));
	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
					"[HOOK %s] inode=%u, parent_inode=%u, file=%s, path=%s, pid=%d, uid=%d",
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
	disp_info_t disp = {};
	
	if (sock->sk->sk_family != AF_INET) { // TODO: AF_INET6
		return 0;
	} 

	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	disp.tuple_info.saddr.v4addr.s_addr = 0;
	disp.tuple_info.sport = 0;

	disp.tuple_info.daddr.v4addr.s_addr = ntohl(((struct sockaddr_in *)address)->sin_addr.s_addr);
	disp.tuple_info.dport = ntohs(((struct sockaddr_in *)address)->sin_port);
	disp.tuple_info.ip_proto = sock->sk->sk_protocol;
	update_process_info(&disp.tuple_info.id, sock->sk, NULL);

#ifdef DEBUG_EVENT_MEDIATOR
	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
					"vsentry_socket_connect=%lx[%d] -> %lx[%d]",
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
	disp_info_t disp = {};

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
	//update_process_info(&disp.tuple_info.id, skb->sk, NULL);

//#ifdef DEBUG_EVENT_MEDIATOR
	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
					"vsentry_incoming_connection=%lx[%d] -> %lx[%d]",
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
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if (path->dentry->d_inode)
		disp.fileinfo.current_inode = path->dentry->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] inode is null", REASON, hook_event_names[HOOK_CHMOD].name);
						
	if ((path->dentry->d_parent) && (path->dentry->d_parent->d_inode)){
		disp.fileinfo.parent_inode = path->dentry->d_parent->d_inode->i_ino;
		disp.fileinfo.parent_info = path->dentry->d_parent;	
	}else						
		disp.fileinfo.parent_inode = 0;
		
	update_process_info(&disp.fileinfo.id, NULL, NULL);
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop	
	get_path(path->dentry, fullpath, sizeof(fullpath));
	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
					"[HOOK %s] inode=%u, parent_inode=%u, path=%s, pid=%d, uid=%d",
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
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if ((dentry->d_parent) && (dentry->d_parent->d_inode)){
		disp.fileinfo.parent_inode = dentry->d_parent->d_inode->i_ino;
		disp.fileinfo.parent_info = dentry->d_parent;
	}else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] parent inode is null", REASON, hook_event_names[HOOK_INODE_CREATE].name);
		
	update_process_info(&disp.fileinfo.id, NULL, NULL);
	disp.fileinfo.fileop = SR_FILEOPS_WRITE;
	
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[SR_MAX_PATH_SIZE];
	SR_U8 		fullpath[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop
	strncpy(disp.fileinfo.filename, dentry->d_iname,
		MIN(sizeof(filename), 1+strlen(dentry->d_iname)));
	get_path(dentry->d_parent, fullpath, sizeof(fullpath));
	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
					"[HOOK %s] parent_inode=%u, path=%s, pid=%d, uid=%d",
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
			CEF_log_event(SR_CEF_CID_SYSTEM, "error" , SEVERITY_HIGH, "%s=get path failed - file path it to long", REASON);
			return 0;
		}
		if (!sr_cls_filter_path_is_match(disp.fileinfo.fullpath) && disp_file_created(&disp) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error" , SEVERITY_HIGH, 
							"%s=[%s] failed disp_file_created", REASON, hook_event_names[HOOK_INODE_CREATE].name);
		}
	}
	return rc;
}

//__attribute__ ((unused))
static SR_32 vsentry_file_open_task(struct file *file, const struct cred *credv, struct task_struct *ts)
{
	disp_info_t disp;
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));

	/* gather metadata */
	if (file->f_path.dentry->d_inode)
		disp.fileinfo.current_inode = file->f_path.dentry->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] inode in null", REASON, hook_event_names[HOOK_FILE_OPEN].name);
	if ((file->f_path.dentry->d_parent) && (file->f_path.dentry->d_parent->d_inode)){
		disp.fileinfo.parent_inode = file->f_path.dentry->d_parent->d_inode->i_ino;
		disp.fileinfo.parent_info = file->f_path.dentry->d_parent;
	}else
		disp.fileinfo.parent_inode = 0;

	update_process_info(&disp.fileinfo.id, NULL, ts);
	/* A File is opned to read or write, not to exec */
	if (file->f_mode & FMODE_WRITE)
		disp.fileinfo.fileop |= SR_FILEOPS_WRITE;
	if (file->f_mode & FMODE_READ)
		disp.fileinfo.fileop |= SR_FILEOPS_READ;

#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
	SR_U8 		filename[SR_MAX_PATH_SIZE];
#pragma GCC diagnostic pop
	get_path(file->f_path.dentry, filename, sizeof(filename));
	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
					"[HOOK %s] inode=%u, parent_inode=%u, file=%s, pid=%d, uid=%d",
					hook_event_names[HOOK_FILE_OPEN].name,
					disp.fileinfo.current_inode,
					disp.fileinfo.parent_inode,
					filename, 
					disp.fileinfo.id.pid,
					disp.fileinfo.id.uid);
#endif /* DEBUG_EVENT_MEDIATOR */

	disp.fileinfo.dev_type = DEV_TYPE_UNKOWN;
	if (file->f_path.dentry->d_inode && file->f_path.dentry->d_inode->i_sb) { 
		if (!strcmp(file->f_path.dentry->d_inode->i_sb->s_id, "proc"))
				disp.fileinfo.dev_type = DEV_TYPE_PROC;
		else if(!strcmp(file->f_path.dentry->d_inode->i_sb->s_id, "devtmpfs"))
				disp.fileinfo.dev_type = DEV_TYPE_DEV;
		else if(!strcmp(file->f_path.dentry->d_inode->i_sb->s_id, "sysfs"))
				disp.fileinfo.dev_type = DEV_TYPE_SYS;
		else if(!strcmp(file->f_path.dentry->d_inode->i_sb->s_id, "tmpfs"))
				disp.fileinfo.dev_type = DEV_TYPE_TMP;
	}

	/* call dispatcher */
	rc = disp_file_open(&disp);

	if (rc == 0) {
		if(get_collector_state() == SR_TRUE){
			if (sr_get_full_path(file, disp.fileinfo.fullpath, SR_MAX_PATH_SIZE) != SR_SUCCESS)
				return rc;
			if ((rc = get_process_name(disp.fileinfo.id.pid, disp.fileinfo.id.exec, SR_MAX_PATH_SIZE)) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=failed get process name for file open pid %d ", REASON, disp.can_info.id.pid);
				return rc;
			}
			disp_file_open_report(&disp);
		}
	}

	return rc;
}

SR_32 vsentry_file_open(struct file *file, const struct cred *credv)
{
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	return vsentry_file_open_task(file, credv, current);
}

SR_32 vsentry_inode_link(struct dentry *old_dentry, struct inode *dir, struct dentry *new_dentry)
{
	disp_info_t disp;

	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	/* gather metadata */
	if ((new_dentry->d_parent) && (new_dentry->d_parent->d_inode))
		disp.fileinfo.parent_inode = new_dentry->d_parent->d_inode->i_ino;
	else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] parent inode in null", REASON, hook_event_names[HOOK_INODE_LINK].name);
						
	if ((old_dentry->d_parent) && (old_dentry->d_parent->d_inode)){
		disp.fileinfo.old_parent_inode = old_dentry->d_parent->d_inode->i_ino;
		disp.fileinfo.parent_info = old_dentry->d_parent;		
	}else
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=[%s] old parent inode in null", REASON, hook_event_names[HOOK_INODE_LINK].name);
	if (old_dentry->d_inode)
		disp.fileinfo.old_inode = old_dentry->d_inode->i_ino;

	update_process_info(&disp.fileinfo.id, NULL, NULL);
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
					"[HOOK %s] parent_inode=%u, old_parent_inode=%u, file=%s, path=%s, old_path=%s pid=%d, uid=%d",
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
	disp_info_t disp = {};
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
	
	/* here we cannot use sk based update as it is not created yet */
	update_process_info(&disp.socket_info.id, NULL, NULL);

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
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"%s=failed sr_stat_connection_insert", REASON);
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
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed sr_stat_connection_insert", REASON);
			return 0;
        }
	}

	return 0;
}
#endif

struct raw_sock {
        struct sock sk;
        int bound;
        int ifindex;
};

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
#ifdef CONFIG_CAN_ML
	struct timeval tv;
#endif /* CONFIG_CAN_ML */
	disp_info_t disp = {};
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	//CHECK_STATE

	/* check hook filter */
	HOOK_FILTER
	
	switch (family) {
		case AF_CAN:
			do_gettimeofday(&tv);
			disp.can_info.ts = ((tv.tv_sec * 1000000) + tv.tv_usec);

			if (sock->sk) {
				struct raw_sock *ro = (struct raw_sock *)sock->sk;
				disp.can_info.if_id = ro->ifindex;
			}
			update_process_info(&disp.can_info.id, sock->sk, NULL);
			skb = sock_alloc_send_skb(copy_sock.sk, size + sizeof(struct can_skb_priv),
						  copy_msg.msg_flags & MSG_DONTWAIT, &err);
			if (!skb) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
									"%s=fail to allocate skb for can message", REASON);
				/* we cannot handle this message */
				return 0;
			}

			err = memcpy_from_msg(skb_put(skb, size), &copy_msg, size);
			if (err < 0) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								"%s=fail to copy can msg from user", REASON);
				/* we cannot handle this message */
				kfree_skb(skb);
				return 0;
			}
			cfd = (struct canfd_frame *)skb->data;
			disp.can_info.msg_id = ((SR_U32)cfd->can_id) & 0x1fffffff;
			disp.can_info.payload_len = cfd->len;
			disp.can_info.dir = SR_CAN_OUT;
			for (i = 0; i < cfd->len; i++) {
				disp.can_info.payload[i] = cfd->data[i];
			}
			CEF_log_debug(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
							"%s=[HOOK %s] family=af_can msd_id=%x payload_len=%d payload= %02x %02x %02x %02x %02x %02x %02x %02x pid=%d, uid=%d", MESSAGE,
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
			kfree_skb(skb);
			/* we are checking state here to deliver the can msg to can_ml even when vsentry is disbaled */
			CHECK_STATE
			/* call dispatcher */
			return (disp_socket_sendmsg(&disp));
			break;
		case AF_INET:
			CHECK_STATE
			if (!sock->sk)
				return 0;
			if (sr_cls_process_add(current->tgid, SR_FALSE) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=error adding process", REASON);
			}
#ifdef CONFIG_STAT_ANALYSIS
			con.con_id.saddr.v4addr = ntohl(sock->sk->sk_rcv_saddr);
			con.con_id.daddr.v4addr = ntohl(sock->sk->sk_daddr);
			con.con_id.ip_proto = sock->sk->sk_protocol;
			/* Strange : sk_num is host order, sk_dport is network oredr WTF? */
			con.con_id.sport = sock->sk->sk_num;
			con.con_id.dport = ntohs(sock->sk->sk_dport);
			con.pid = current->tgid;
			con.is_outgoing = SR_TRUE;

			if ((conp = sr_stat_connection_lookup(&con.con_id))) {
				if ((rc = sr_stat_connection_update_counters(conp, current->tgid, 0, 0, size, 1)) != SR_SUCCESS) {
					CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"%s=failed sr_stat_connection_update_counters", REASON);
					return 0;
				}
			} else {
				con.tx_bytes = size;
				con.tx_msgs = 1;
        			if ((rc = sr_stat_connection_insert(&con, 0)) != SR_SUCCESS) {
						CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"%s=failed sr_stat_connection_insert", REASON);
						return 0;
        			}
			}
#endif

			/* Hook is relevant only for UDP */
			if (sock->sk->sk_protocol != IPPROTO_UDP)
				return 0;
			/* this code is probably redundant */
			//process_info.pid = current->tgid;
			//process_info.uid = (int)rcred->uid.val;
			//if (sr_cls_sk_process_hash_update(sock->sk, &process_info) != SR_SUCCESS) {
				//CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
								//"failed sr_cls_sk_process_hash_update");
                //return 0;
			//}

#ifdef DEBUG_EVENT_MEDIATOR
        		CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
								"vsentry_socket_connect=%lx[%d] -> %lx[%d]",
                        		(unsigned long)disp.tuple_info.saddr.v4addr.s_addr,
                        		disp.tuple_info.sport,
                        		(unsigned long)disp.tuple_info.daddr.v4addr.s_addr,
                        		disp.tuple_info.dport);
#endif /* DEBUG_EVENT_MEDIATOR */

			break;
		default:
			/* we are not interested in the message */
			break;
	}
	
	return 0;
}

int vsentry_socket_sock_rcv_skb(struct sock *sk, struct sk_buff *skb)
{
	int i;
	struct canfd_frame *cfd;
	disp_info_t disp;
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	memset(&disp, 0, sizeof(disp_info_t));	
	
	switch (sk->sk_family) {
		
		case PF_CAN:
			cfd = (struct canfd_frame *)skb->data;
			disp.can_info.msg_id = ((SR_U32)cfd->can_id) & 0x1fffffff;
			disp.can_info.payload_len = cfd->len;
			disp.can_info.dir = SR_CAN_IN;
			disp.can_info.if_id = skb->dev->ifindex;
			update_process_info(&disp.can_info.id, sk, NULL);

			for (i = 0; i < cfd->len; i++) {
				disp.can_info.payload[i] = cfd->data[i];
			}
			return (disp_can_recvmsg(&disp));
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
// XXX TODO temporary remove support from uid since clasification is done in netfilter.
#if 0
	const struct cred *rcred= ts->real_cred;		
#endif

	if (sr_cls_process_add(current->tgid, SR_FALSE) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=error adding process", REASON);
	}

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
						CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
										"%s=failed sr_stat_connection_insert", REASON);
						return 0;
					}
				}
				return 0;
			}
#endif

#ifdef CONFIG_STAT_ANALYSIS
			sr_stat_port_update(sock->sk->sk_num, current->tgid); // This is the local port
#endif
				
#ifdef DEBUG_EVENT_MEDIATOR
        		CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
								"vsentry_socket_connect=%lx[%d] -> %lx[%d]",
                        		(unsigned long)disp.tuple_info.saddr.v4addr.s_addr,
                        		disp.tuple_info.sport,
                        		(unsigned long)disp.tuple_info.daddr.v4addr.s_addr,
                        		disp.tuple_info.dport);
#endif /* DEBUG_EVENT_MEDIATOR */

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
	SR_32 rc;
	
	memset(&disp, 0, sizeof(disp_info_t));
	
	/* check vsentry state */
	CHECK_STATE

	/* check hook filter */
	HOOK_FILTER

	if (bprm->file->f_inode) //redundent check?
		disp.fileinfo.current_inode = bprm->file->f_inode->i_ino;
		
	disp.fileinfo.id.uid = (int)rcred->uid.val;
	disp.fileinfo.id.pid = current->tgid;
	disp.fileinfo.fileop = SR_FILEOPS_EXEC; // open requires exec access
    
#ifdef DEBUG_EVENT_MEDIATOR
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic pop
	CEF_log_event(SR_CEF_CID_SYSTEM, "info" , SEVERITY_LOW,
			"[HOOK %s] inode=%u, file=%s, pid=%d, uid=%d",
			hook_event_names[HOOK_BINPERM].name,
			disp.fileinfo.current_inode,
			bprm->filename, 
			disp.fileinfo.id.pid,
			disp.fileinfo.id.uid);
#endif     
    
	rc =  disp_file_exec(&disp);
	if (rc == 0 && get_collector_state() == SR_TRUE) {
		if (sr_get_full_path(bprm->file, disp.fileinfo.fullpath, SR_MAX_PATH_SIZE) != SR_SUCCESS)
			return rc;

		if ((rc = get_process_name(disp.fileinfo.id.pid, disp.fileinfo.id.exec, SR_MAX_PATH_SIZE)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=failed get process name for file open pid %d ", REASON, disp.can_info.id.pid);
			return rc;
		}

		disp_file_exe_report(&disp);
	}

	return rc;
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

void vsentry_sk_free_security(struct sock *sk)
{
	sk_process_item_t *process_info_p;

	if (!sk) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM,"%s=trying to free null security sk", REASON);
		return;
	}

	if ((sk->sk_family != AF_CAN) && (sk->sk_family != AF_INET)) {
		/* we are looking only for ip and can events */
		return;
	}

	if ((process_info_p = sr_cls_sk_process_hash_get(sk))) {
		//CEF_log_event(SR_FORENSIC_NETWORK, "info", SEVERITY_LOW,
		//	"%s=socket deleted sk %p pid %d uid %d exec %s", MESSAGE, sk, process_info_p->process_info.pid, process_info_p->process_info.uid, process_info_p->process_info.exec);
		sr_cls_sk_process_hash_delete(sk);
	} else {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM,
			"%s=failed to delete security sk %p", REASON, sk);
	}
}

int vsentry_sk_alloc_security(struct sock *sk, int family, gfp_t priority)
{
	sk_process_info_t process_info;
	struct task_struct *ts = current;
	const struct cred *rcred= ts->real_cred;

	if (in_interrupt())
		return 0;

	if (!sk) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM,"%s=trying to allocate null security sk", REASON);
		return 0;
	}

	if ((family != AF_CAN) && (family != AF_INET)) {
		/* we are looking only for ip and can events */
		return 0;
	}

	process_info.pid = current->tgid;
	process_info.uid = (int)rcred->uid.val;
	if ((get_process_name(process_info.pid, process_info.exec, SR_MAX_PATH_SIZE)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM, 
			"%s=failed get process name at sk allocation for pid %d", REASON, process_info.pid);
		return 0;
	}

	if (sr_cls_sk_process_hash_update(sk, &process_info) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM,
			"%s=failed to update process info for pid %d uid %d exec %s", REASON, process_info.pid, process_info.uid, process_info.exec);
	} /*else {
		//CEF_log_event(SR_FORENSIC_NETWORK, "info", SEVERITY_LOW,
		//	"%s=new security sk created sk %p pid %d uid %d exec %s", MESSAGE, sk, process_info.pid, process_info.uid, process_info.exec);
	}*/
	return 0;
}

int vsentry_can_driver_security(SR_U32 msg_id, SR_BOOL is_dir_in, int can_dev_id, int minor)
{
	disp_info_t disp = {};

	disp.can_info.msg_id = msg_id & 0x1fffffff;
	disp.can_info.payload_len = 0;
	disp.can_info.dir = is_dir_in ? SR_CAN_IN : SR_CAN_OUT;
	disp.can_info.if_id = can_dev_id;
	disp.can_info.dev_id = minor;
	disp.can_info.id.pid = current->tgid;
	if (get_process_name(disp.can_info.id.pid, disp.can_info.id.exec, SR_MAX_PATH_SIZE) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, "%s=failed get process pid:%d ", REASON, current->tgid);
	}
	if (is_dir_in)
		return disp_can_recvmsg(&disp);
	return disp_socket_sendmsg(&disp);
}

static void vsentry_extract_process_resources(struct task_struct *task)
{
	struct files_struct *files = task->files;
	struct fdtable *fdt = rcu_dereference_raw(files->fdt);
	unsigned int i, j = 0;

	for (;;) {
		unsigned long set;
		i = j * BITS_PER_LONG;

		if (i >= fdt->max_fds)
			break;

		set = fdt->open_fds[j++];
		while (set) {
			if (set & 1) {
				struct file *file = fdt->fd[i];

				if (file) {
					if ( !(file->f_inode->i_mode & S_IFMT) || S_ISFIFO(file->f_inode->i_mode))
						goto to_next_file;

					if (S_ISSOCK(file->f_inode->i_mode)) {
						/* check if this file is net socket */
						SR_32 err = 0;
						struct socket *sock = sock_from_file(file, &err);

						if (!err && sock) {
							if (sock->sk->sk_family == AF_CAN || sock->sk->sk_family == AF_INET) {
								sk_process_info_t process_info;
        							const struct cred *rcred= task->real_cred;

								process_info.pid = task->tgid;
								process_info.uid = (int)rcred->uid.val;
        
								if ((get_process_name(process_info.pid, process_info.exec, SR_MAX_PATH_SIZE)) != SR_SUCCESS) {
									CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM,
										"%s=failed get process name at sk allocation for pid:%d ",
										REASON, process_info.pid);
								}

								if (sr_cls_sk_process_hash_update(sock->sk, &process_info) != SR_SUCCESS) {
									CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_MEDIUM,
										"failed to update process info for pid %d uid %d", process_info.pid, process_info.uid);
								}
							}
						}
					} else {
						vsentry_file_open_task(file, NULL, task);
					}
				}
			}
to_next_file:
			i++;
			set >>= 1;
		}
	}
}

void vsentry_init_process_db(void)
{
	struct task_struct *leader, *child;
	disp_info_t disp;

	memset(&disp, 0, sizeof(disp_info_t));

	rcu_read_lock();

	for_each_process(leader) {
		for_each_thread(leader, child) {
			if ((child->flags & PF_KTHREAD) || !child->mm || !child->mm->exe_file)
				continue;

			/* map used files/socket to prog */
			vsentry_extract_process_resources(child);
		}
	}

	rcu_read_unlock();
}
