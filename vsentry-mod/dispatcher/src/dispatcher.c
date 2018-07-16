/* file: dispatcher.c
 * purpose: this file implements general API for the events comming
 *          from event mediator (which is platform specific)
*/
#include "dispatcher.h"
#include "sr_msg.h"
#include "sr_sal_common.h"
#include "sr_classifier.h"
#include "sr_event_collector.h"
#include "event_mediator.h"

#ifdef CONFIG_CAN_ML
#include "ml_can.h"
#include "sr_ml.h"
#endif /* CONFIG_CAN_ML */

#ifdef DEBUG_DISPATCHER
static SR_8 module_name[] = "dispatcher"; /* module_name used only when DEBUG_DISPATCHER is enabled */
#endif /* DEBUG_DISPATCHER */

/*
 * GENERAL FILE TODO -
 * 
 * change all CEF messages to less heavier structure (without strings
 * where posibble) and create the CEF message only in user space??
 */ 

CEF_payload* cef_init(SR_8* event_name,enum SR_CEF_SEVERITY sev,enum SR_CEF_CLASS_ID	class)
{
	struct CEF_payload *payload = (struct CEF_payload*)sr_get_msg(MOD2LOG_BUF, sizeof(struct CEF_payload));

	if (!payload) {
		return NULL;
	}
	payload->class = class;		
	payload->sev = sev;		
	sal_strcpy(payload->name,event_name);
	
	return payload;
}

SR_32 disp_mkdir(disp_info_t* info)
{
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_rmdir(disp_info_t* info)
{
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_inode_create(disp_info_t* info)
{
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_path_chmod(disp_info_t* info)
{
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_file_open(disp_info_t* info)
{
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_inode_link(disp_info_t* info)
{	
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_inode_unlink(disp_info_t* info)
{
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

void disp_inode_remove(SR_U32 inode)
{
	return sr_cls_inode_remove(inode);
}

SR_32 disp_inode_rename(disp_info_t* info)
{
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

SR_32 disp_inode_symlink(disp_info_t* info)
{	
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}

// TODO: might not have full 5-tuple at this stage !?!?!?
SR_32 disp_socket_connect(disp_info_t* info)
{
	struct sr_ec_new_connection_t sample_data;

	sample_data.pid = info->tuple_info.id.pid;
	sample_data.uid = info->tuple_info.id.uid;
	sample_data.remote_addr.v4addr = info->tuple_info.daddr.v4addr.s_addr;
	sample_data.source_addr.v4addr = info->tuple_info.saddr.v4addr.s_addr; //TODO: source is still 0 in most cases
	sample_data.ip_proto = info->tuple_info.ip_proto;
	sample_data.dport = info->tuple_info.dport;
	sample_data.sport = info->tuple_info.sport;
	sr_ec_send_event(MOD2STAT_BUF, SR_EVENT_STATS_NEW_CONNECTION, &sample_data);
	return (sr_classifier_network(info));
}

SR_32 disp_file_created(disp_info_t* info)
{
	struct sr_ec_file_t file_data;

	if (*(info->fileinfo.fullpath)) {
		strncpy(file_data.name, info->fileinfo.fullpath, SR_MAX_PATH_SIZE);
		sr_ec_send_event(MOD2ENG_BUF, SR_EVENT_FILE_CREATED, &file_data);
	}
	return SR_SUCCESS;
}

static SR_32 disp_file_learn_report(disp_info_t* info, sr_ec_wl_type_t wl_type)
{
	struct sr_ec_file_wl_t file_wl_data;

	file_wl_data.wl_type = wl_type;
	strncpy(file_wl_data.file, info->fileinfo.fullpath, SR_MAX_PATH_SIZE); 
	file_wl_data.pid = info->fileinfo.id.pid; 
	file_wl_data.fileop = info->fileinfo.fileop;
	sr_ec_send_event(MOD2STAT_BUF, SR_EVENT_STATS_FILE_WL, &file_wl_data);

	return SR_SUCCESS;
}

SR_32 disp_file_open_report(disp_info_t* info)
{
	return disp_file_learn_report(info, SR_EC_WL_FILE_OPEN);
}

SR_32 disp_file_exe_report(disp_info_t* info)
{
	return disp_file_learn_report(info, SR_EC_WL_FILE_EXE);
}

SR_32 disp_ipv4_sendmsg(disp_info_t* info)
{
	return (sr_classifier_network(info));
}

SR_32 disp_ipv4_recvmsg(disp_info_t* info)
{
	return (sr_classifier_network(info));
}

SR_32 disp_incoming_connection(disp_info_t* info)
{
	return sr_classifier_network(info);
}

// TODO: might not have full 5-tuple at this stage !?!?!?
SR_32 disp_socket_create(disp_info_t* info)
{
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"Called function %s [DISABLED]\n", __FUNCTION__);
	//sr_classifier_network(info);
	return SR_CLS_ACTION_ALLOW;
}

SR_32 disp_socket_sendmsg(disp_info_t* info)
{
	SR_32		classifier_rc = -EACCES;
	SR_U8		ml_rc = SR_ML_ALLOW;
	const event_name *hook_event_names;
	struct sr_ec_can_t can_data; // event collector data for white list
	
	if(get_collector_state() == SR_TRUE){
		can_data.pid = info->tuple_info.id.pid;
		can_data.msg_id = info->can_info.msg_id;
		can_data.dir = SR_CAN_OUT;
		sr_ec_send_event(MOD2STAT_BUF, SR_EVENT_STATS_CANBUS, &can_data);
	}
	/* call classifier */
	classifier_rc = sr_classifier_canbus(info);
#ifdef CONFIG_CAN_ML
	if (get_can_ml_state() == SR_TRUE)
		ml_rc = test_can_msg(info);
#endif /* CONFIG_CAN_ML */

	hook_event_names = event_mediator_hooks_event_names();

	/* create event message */

#ifdef DEBUG_DISPATCHER
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"[%s:HOOK %s] family=af_can, msd_id=%x, payload_len=%d, payload= %02x %02x %02x %02x %02x %02x %02x %02x, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->can_info.id.event].name,
			info->can_info.msg_id,
			info->can_info.payload_len,
			info->can_info.payload[0],
			info->can_info.payload[1],
			info->can_info.payload[2],
			info->can_info.payload[3],
			info->can_info.payload[4],
			info->can_info.payload[5],
			info->can_info.payload[6],
			info->can_info.payload[7],
			info->can_info.id.pid,
			info->can_info.id.gid,
			info->can_info.id.tid);
#endif /* DEBUG_DISPATCHER */

#ifdef CONFIG_CAN_ML
	if ((classifier_rc == SR_CLS_ACTION_ALLOW) && (ml_rc == SR_ML_ALLOW))
#else
	if (classifier_rc == SR_CLS_ACTION_ALLOW)
#endif /* CONFIG_CAN_ML */
		return 0;
	else
		return -EACCES;	
}

SR_32 disp_can_recvmsg(disp_info_t* info)
{
	SR_32		classifier_rc = -EACCES;
	const event_name *hook_event_names;
	struct sr_ec_can_t can_data; // event collector data for white list
	
	if(get_collector_state() == SR_TRUE){
		can_data.pid = info->tuple_info.id.pid;
		can_data.msg_id = info->can_info.msg_id;
		can_data.dir = SR_CAN_IN;
		sr_ec_send_event(MOD2STAT_BUF, SR_EVENT_STATS_CANBUS, &can_data);
	}
	hook_event_names = event_mediator_hooks_event_names();

	/* call classifier */
	//classifier_rc = 0;
	
	classifier_rc = sr_classifier_canbus(info);
	
	#ifdef DEBUG_DISPATCHER
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"[%s:HOOK %s] family=af_can, msd_id=%x, payload_len=%d, payload= %02x %02x %02x %02x %02x %02x %02x %02x, pid=%d, gid=%d, tid=%d\n", 
			module_name, 
			hook_event_names[info->can_info.id.event].name,
			info->can_info.msg_id,
			info->can_info.payload_len,
			info->can_info.payload[0],
			info->can_info.payload[1],
			info->can_info.payload[2],
			info->can_info.payload[3],
			info->can_info.payload[4],
			info->can_info.payload[5],
			info->can_info.payload[6],
			info->can_info.payload[7],
			info->can_info.id.pid,
			info->can_info.id.gid,
			info->can_info.id.tid);
#endif /* DEBUG_DISPATCHER */

		/* send event message to user space */
	//sr_send_msg(MOD2LOG_BUF, sizeof(CEF_payload));
	if (classifier_rc == SR_CLS_ACTION_ALLOW) {
		return 0;
	} else {
		return -EACCES;
	}	
}

SR_32 disp_file_exec(disp_info_t* info)
{
	if (unlikely(sr_classifier_file(info) == SR_CLS_ACTION_DROP)) {
		return -EACCES;
	} else {
		return 0;
	}
}
