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

SR_32 disp_mkdir(disp_info_t* info)
{
	printk("Dispatcher: Entered %s\n", __FUNCTION__);
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_rmdir(disp_info_t* info)
{
	printk("Dispatcher: Entered %s\n", __FUNCTION__);
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_inode_create(disp_info_t* info)
{
	printk("Dispatcher: Entered %s\n", __FUNCTION__);
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_path_chmod(disp_info_t* info)
{
	printk("Dispatcher: Entered %s\n", __FUNCTION__);
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_file_open(disp_info_t* info)
{
	printk("Dispatcher: Entered %s\n", __FUNCTION__);
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_inode_link(disp_info_t* info)
{
	printk("Dispatcher: Entered %s\n", __FUNCTION__);
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_inode_unlink(disp_info_t* info)
{
	printk("Dispatcher: Entered %s\n", __FUNCTION__);
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_inode_symlink(disp_info_t* info)
{	
	printk("Dispatcher: Entered %s\n", __FUNCTION__);
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

// TODO: might not have full 5-tuple at this stage !?!?!?
SR_32 disp_socket_connect(disp_info_t* info)
{
	return (sr_classifier_network(info));
}

SR_32 disp_incoming_connection(disp_info_t* info)
{
	//sal_kernel_print_info("disp_incoming_connection: Entry\n");

	return sr_classifier_network(info);
}

// TODO: might not have full 5-tuple at this stage !?!?!?
SR_32 disp_socket_create(disp_info_t* info)
{
	printk("Called function %s [DISABLED]\n", __FUNCTION__);
	//sr_classifier_network(info);
	return SR_CLS_ACTION_ALLOW;
}
