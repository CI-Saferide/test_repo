/* file: event_mediator.c
 * purpose: this file implements mediation layer between platform
 * 			specific code and agnostic code (starting from dispatcher
 * 			layer). it also collects all relevant metadata for each hook
*/
#include "sr_lsm_hooks.h"
#include "dispatcher.h"
#include "event_mediator.h"
#include "sr_sal_common.h"

extern int sr_vsentryd_pid;

/*implement filter for our sr-engine */
static int hook_filter(void)
{
	/*if the statement is true in means the SYS_CALL invoked by sr-engine */
	if ((sr_vsentryd_pid) == (current->pid)-1)
		return SR_TRUE;
		
	return SR_FALSE;
}

/*parsing data helper functions*/
static void parse_sinaddr(const struct in_addr saddr, char* buffer, int length)
{
	snprintf(buffer, length, "%d.%d.%d.%d",
		(saddr.s_addr&0xFF),
		((saddr.s_addr&0xFF00)>>8),
		((saddr.s_addr&0xFF0000)>>16),
		((saddr.s_addr&0xFF000000)>>24));
}

static char* get_path(struct dentry *dentry, char *buffer, int len)
{
	char path[SR_disp_MAX_PATH_SIZE], *path_ptr;

	path_ptr = dentry_path_raw(dentry, path, SR_disp_MAX_PATH_SIZE);
	if (IS_ERR(path))
		return NULL;

	memcpy(buffer, path_ptr, MIN(len, 1+strlen(path_ptr)));

	return buffer;
}

int vsentry_inode_mkdir(struct inode *dir, struct dentry *dentry, umode_t mask)
{
	disp_info_t em = {0};//as for "event mediator"
	
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
	//return (disp_mkdir(&em));
	printk("mkdir=%s, path=%s, pid=%d, gid=%d, tid=%d\n", 
			em.fileinfo.filename, 
			em.fileinfo.fullpath, 
			em.fileinfo.id.pid,
			em.fileinfo.id.gid, 
			em.fileinfo.id.tid);
	return 0;
}
