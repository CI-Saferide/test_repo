/* file: dispatcher.c
 * purpose: this file implements general API for the events comming
 *          from event mediator (which is platform specific)
*/
#include "dispatcher.h"
#include "sr_msg.h"
#include "sr_sal_common.h"
#include "sr_classifier.h"

#ifdef DEBUG_DISPATCHER
static SR_8 module_name[] = "dispatcher"; /* module_name used only when DEBUG_DISPATCHER is enabled */
extern const event_name hook_event_names[MAX_HOOK];
#endif /* DEBUG_DISPATCHER */

/*
 * GENERAL FILE TODO -
 * 
 * change all CEF messages to less heavier structure (without strings
 * where posibble) and create the CEF message only in user space??
 */ 

CEF_payload* cef_init(SR_8* event_name,enum severity sev,enum dev_event_class_ID	class)
{
	struct CEF_payload *payload = (struct CEF_payload*)sr_get_msg(MOD2LOG_BUF, sizeof(struct CEF_payload));

	if (!payload) {
		return NULL;
	}
	payload->cef_version = CEF_VERSION;
	payload->dev_version = VSENTRY_VERSION;
	payload->class = class;		
	payload->sev = sev;		
	sal_strcpy(payload->dev_vendor,PRODUCT_VENDOR);
	sal_strcpy(payload->dev_product,MODULE_NAME);
	sal_strcpy(payload->name,event_name);
	
	return payload;
}

SR_BOOL disp_mkdir(disp_info_t* info)
{
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;
}

SR_BOOL disp_rmdir(disp_info_t* info)
{
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;
}

SR_BOOL disp_inode_create(disp_info_t* info)
{
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;
}

SR_BOOL disp_path_chmod(disp_info_t* info)
{
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;
}

SR_BOOL disp_file_open(disp_info_t* info)
{
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name,
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;
}

SR_BOOL disp_inode_link(disp_info_t* info)
{
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, old_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.old_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;
}

SR_BOOL disp_inode_unlink(disp_info_t* info)
{
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;
}

SR_BOOL disp_inode_symlink(disp_info_t* info){	
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;	
}

SR_BOOL disp_socket_connect(disp_info_t* info)
{
	enum dev_event_class_ID	class = NETWORK;
	enum severity sev = WARNING;
	struct CEF_payload *payload = cef_init((char*)__FUNCTION__,sev,class);

	if (!payload)
		return 0;

	/* create event message */
			
#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("%s %s\n", module_name, payload->extension);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	/* call classifier */
	return 0;
}

SR_32 disp_incoming_connection(disp_info_t* info)
{
	sal_kernel_print_info("disp_incoming_connection: Entry\n");

	return sr_classifier_network(info);
}

SR_BOOL disp_socket_create(disp_info_t* info)
{
	SR_BOOL		classifier_rc = 1;
	
	/* call classifier */
	classifier_rc = 0;
	
	enum dev_event_class_ID	class = NETWORK;
	enum severity sev = WARNING;
	struct CEF_payload *payload = cef_init((char*)__FUNCTION__,sev,class);

	if (!payload)
		return 0;

	/* create event message */

#ifdef DEBUG_DISPATCHER
	sal_kernel_print_info("[%s:HOOK %s] inode=%lu, parent_inode=%lu, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->fileinfo.id.event].name,
			info->fileinfo.current_inode,
			info->fileinfo.parent_inode,
			info->fileinfo.id.pid,
			info->fileinfo.id.gid,
			info->fileinfo.id.tid);
#endif /* DEBUG_DISPATCHER */

	/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	
	return classifier_rc;	
}
