#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_actions_common.h"
#include "sr_cls_sk_process.h"
#include "sr_cls_housekeeping.h"
#include "sr_cls_conn_obj.h"
#include "sr_control.h"
#ifdef UNIT_TEST
#include "sr_cls_test.h"
#endif

static cls_file_mem_optimization_t dparent_flag = CLS_FILE_MEM_OPT_ALL_FILES;
static SR_BOOL is_def; /* global variable for all default rules */

SR_32 sr_classifier_init(void)
{
	sr_cls_network_init();
	sr_cls_fs_init();
	sr_cls_port_init();		
	sr_cls_canid_init();
	sr_cls_rules_init();
	sr_cls_uid_init();
	sr_cls_exec_file_init();
	sr_cls_process_init();
	sr_cls_sk_process_hash_init();
	sr_conn_obj_init();
	sr_cls_housekeeping_init();

#ifdef UNIT_TEST
	sr_cls_test_runall();
#endif

	return 0;
}

void sr_classifier_uninit(void)
{
	sr_cls_housekeeping_uninit();
	sr_conn_obj_uninit();
	sr_cls_sk_process_hash_uninit();
	sr_cls_network_uninit();
	sr_cls_fs_uninit();
	sr_cls_port_uninit();
	sr_cls_canid_uninit();	
	sr_cls_exec_file_uninit();
	sr_cls_process_uninit();
	sr_cls_uid_uninit();
}

void sr_classifier_empty_tables(SR_BOOL is_lock)
{
	sr_cls_exec_file_empty_table(is_lock);
	sr_cls_fs_empty_table(is_lock);
	sr_cls_canid_empty_table(is_lock);
	sr_cls_port_empty_table(is_lock);
	sr_cls_uid_empty_table(is_lock);
	sr_cls_network_uninit();
	sr_cls_network_init();
}

void sr_classifier_set_dparent_flags(cls_file_mem_optimization_t i_dparent_flag)
{
	dparent_flag = i_dparent_flag;
}

SR_U32 find_next_rule (bit_array *ba)
{
	if (is_def) {
		is_def = SR_FALSE;
		return (SR_CLS_DEFAULT_RULE);
	} else
		return(sal_ffs_and_clear_array (ba));
}

///////////////////////////////////////////////////////////////////////////
/////// Actual classifiers entry points
///////////////////////////////////////////////////////////////////////////
// Network events classifier
SR_32 sr_classifier_network(disp_info_t* info)
{
	bit_array *ptr;
	SR_16 rule = SR_CLS_NO_MATCH;
	SR_U16 action;
	bit_array ba_res;
	SR_U16 def_action = SR_CLS_ACTION_ALLOW; /* if we don't have default rule from user, then we just allow the packet */
	struct config_params_t *config_params;
	
#ifdef ROOT_CLS_IGNORE
	if (!info->tuple_info.id.uid) return SR_CLS_ACTION_ALLOW; /* no classification for root user (debug only) */
#endif

	/* Local only traffic os allowed */
	if (cr_cls_is_ip_address_local(info->tuple_info.saddr.v4addr) &&
			cr_cls_is_ip_address_local(info->tuple_info.daddr.v4addr)) {
		return SR_CLS_ACTION_ALLOW;
 	}

	is_def = SR_FALSE;
	memset(&ba_res, 0, sizeof(bit_array));
	config_params = sr_control_config_params();
	// Match 5-tuple
	// Src IP	
	if (cr_cls_is_ip_address_local(info->tuple_info.saddr.v4addr))
		sal_or_op_arrays(src_cls_network_local_src(), src_cls_network_any_src(), &ba_res);
	else {
		ptr = sr_cls_match_ip(htonl(info->tuple_info.saddr.v4addr.s_addr), SR_DIR_SRC);
		if (ptr) {
			sal_or_op_arrays(ptr, src_cls_network_any_src(), &ba_res);
		} else { // take only src/any
			sal_or_self_op_arrays(&ba_res, src_cls_network_any_src());
		}
	}
	
	if (array_is_clear(ba_res)) {	
		goto defaultConf;			
	}else{
		// IP Proto	
		//should support all protocols classifications not just TCP\UDP
		ptr = sr_cls_match_protocol(info->tuple_info.ip_proto);
		if (ptr) {
			sal_and_self_op_two_arrays(&ba_res, ptr, src_cls_proto_any());
		} else { // take only proto/any
			sal_and_self_op_arrays(&ba_res, src_cls_proto_any());
		}
		if (array_is_clear(ba_res)) {
			goto defaultConf;	
		}
		//check if the incomming disp info is TCP\UDP for checking the ports or skipp this check
		if(info->tuple_info.ip_proto == IPPROTO_TCP || info->tuple_info.ip_proto == IPPROTO_UDP){
			// Src Port
			ptr = sr_cls_match_port(info->tuple_info.sport, SR_DIR_SRC, info->tuple_info.ip_proto);
			if (ptr) {
				sal_and_self_op_two_arrays(&ba_res, ptr, src_cls_port_any_src());
			} else { // take only dst/any
				sal_and_self_op_arrays(&ba_res, src_cls_port_any_src());
			}
			if (array_is_clear(ba_res)) {
				goto defaultConf;	
			}
			// Dst Port
			ptr = sr_cls_match_port(info->tuple_info.dport, SR_DIR_DST, info->tuple_info.ip_proto);
			if (ptr) {
				sal_and_self_op_two_arrays(&ba_res, ptr, src_cls_port_any_dst());
			} else { // take only dst/any
				sal_and_self_op_arrays(&ba_res, src_cls_port_any_dst());
			}
			if (array_is_clear(ba_res)) {
				goto defaultConf;
			}
		}
		// Dst IP 
		if (cr_cls_is_ip_address_local(info->tuple_info.daddr.v4addr)) 
			sal_and_self_op_two_arrays(&ba_res, src_cls_network_local_dst(), src_cls_network_any_dst());
		else {
			ptr = sr_cls_match_ip(htonl(info->tuple_info.daddr.v4addr.s_addr), SR_DIR_DST);
			if (ptr) {
				sal_and_self_op_two_arrays(&ba_res, ptr, src_cls_network_any_dst());
			} else { // take only dst/any
				sal_and_self_op_arrays(&ba_res, src_cls_network_any_dst());
			}
		}
		if (array_is_clear(ba_res)) {
			goto defaultConf;
		}
		
		if (info->tuple_info.id.pid) {  // Zero PID is an indication that we are not in process context
			// UID
			if (info->tuple_info.id.uid != UID_ANY) {
				ptr = sr_cls_match_uid(SR_NET_RULES, info->tuple_info.id.uid);
			} else {
				ptr = NULL;
			}
			if (ptr) {
				sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_uid_any(SR_NET_RULES));
			} else { // take only dst/any
				sal_and_self_op_arrays(&ba_res, sr_cls_uid_any(SR_NET_RULES));
			}
			if (array_is_clear(ba_res)) {
				goto defaultConf;
			}
			//PID
			ptr = sr_cls_process_match(SR_NET_RULES, info->tuple_info.id.pid);
			if (ptr) {
				sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_exec_file_any(SR_NET_RULES));
			} else { // take only dst/any
				sal_and_self_op_arrays(&ba_res, sr_cls_exec_file_any(SR_NET_RULES));
			}
		}
		
	}
	
	goto result; // skip the default check...
	
defaultConf:
	is_def = SR_TRUE;
	if(config_params->def_net_action)
		def_action = config_params->def_net_action;

result:	
	while ((rule = find_next_rule (&ba_res)) != SR_CLS_NO_MATCH) {
		if (SR_CLS_DEFAULT_RULE == rule) {
			action = def_action;
		} else {
			action = sr_cls_network_rule_match(rule, info->tuple_info.size);
		}
		if (action & SR_CLS_ACTION_LOG) {
			
			char ext[256],sip[16],dip[16], actionstring[16];
			SR_U32 sip_t, dip_t;
			sip_t = info->tuple_info.saddr.v4addr.s_addr;
			dip_t = info->tuple_info.daddr.v4addr.s_addr;
			
			if (action & SR_CLS_ACTION_DROP) 
				sprintf(actionstring, "drop");
			else
				sprintf(actionstring, "allow");
			
			sprintf(sip, "%d.%d.%d.%d", (sip_t&0xff000000)>>24, (sip_t&0x00ff0000)>>16, (sip_t&0xff00)>> 8, sip_t&0xff);
			sprintf(dip, "%d.%d.%d.%d", (dip_t&0xff000000)>>24, (dip_t&0x00ff0000)>>16, (dip_t&0xff00)>> 8, dip_t&0xff);
			sprintf(ext, "%s=%d%s %s=%s %s=%s %s=%s %s=%d %s=%s %s=%d",
				RULE_NUM_KEY,rule, rule == SR_CLS_DEFAULT_RULE ? "(default)" : "",
				DEVICE_ACTION,actionstring,
				TRANSPORT_PROTOCOL,info->tuple_info.ip_proto == IPPROTO_TCP?"tcp":"udp",
				DEVICE_SRC_IP,sip,
				DEVICE_SRC_PORT,info->tuple_info.sport,
				DEVICE_DEST_IP,dip,
				DEVICE_DEST_PORT,info->tuple_info.dport);
			if (action & SR_CLS_ACTION_DROP) {
				CEF_log_event(SR_CEF_CID_NETWORK, "connection drop" , SEVERITY_HIGH, ext);
				return SR_CLS_ACTION_DROP;
			} else {
				CEF_log_event(SR_CEF_CID_NETWORK, "connection allow" , SEVERITY_LOW, ext);
				return SR_CLS_ACTION_ALLOW;
			}
		}
		if (action & SR_CLS_ACTION_DROP) return SR_CLS_ACTION_DROP;
		if (action & SR_CLS_ACTION_ALLOW) return SR_CLS_ACTION_ALLOW;
	}

	return SR_CLS_ACTION_ALLOW;
}


SR_32 sr_classifier_file(disp_info_t* info)
{
	disp_info_t* tmp_info;
	bit_array *ptr = NULL, ba_res;
	SR_16 rule = SR_CLS_NO_MATCH;
	SR_U16 action;
	SR_U16 def_action = SR_CLS_ACTION_ALLOW; /* if we don't have default rule from user, then we just allow the packet */
	int st;
	struct config_params_t *config_params;

#ifdef ROOT_CLS_IGNORE
	if (!info->tuple_info.id.uid) return SR_CLS_ACTION_ALLOW; /* no classification for root user (debug only) */
#endif

	is_def = SR_FALSE;
	memset(&ba_res, 0, sizeof(bit_array));
	config_params = sr_control_config_params();	
	tmp_info = info;

	sal_or_self_op_arrays(&ba_res, sr_cls_file_any());
	
	if (info->fileinfo.current_inode != INODE_ANY) {
		ptr = sr_cls_file_find(info->fileinfo.current_inode);
		if (ptr) {
			sal_or_self_op_arrays(&ba_res, ptr);
		}
	}
	if (info->fileinfo.old_inode != INODE_ANY) {
		ptr = sr_cls_file_find(info->fileinfo.old_inode);
		if (ptr) {
			sal_or_self_op_arrays(&ba_res, ptr);
		}
	}

check_parent:

	if (tmp_info->fileinfo.parent_inode != INODE_ANY) {
		ptr = sr_cls_file_find(tmp_info->fileinfo.parent_inode);
		if (ptr) {
			sal_or_self_op_arrays(&ba_res, ptr);
		}else if(dparent_flag == CLS_FILE_MEM_OPT_ONLY_DIR){		
			if(tmp_info->fileinfo.parent_info){ //safty check if the "parent_info" ptr is null for some reason...
				tmp_info=(disp_info_t*)sal_get_parent_dir(tmp_info);
				if(tmp_info){// check if we in ROOT "/" directory cuz info will be null
					tmp_info->fileinfo.parent_inode = tmp_info->fileinfo.parent_directory_inode;		
					goto check_parent;
				} else {
					switch (info->fileinfo.dev_type) {
						case DEV_TYPE_PROC:
							if ((ptr = sr_cls_file_find(SR_PROC_INODE)))
								sal_or_self_op_arrays(&ba_res, ptr);
							break;
						case DEV_TYPE_SYS:
							if ((ptr = sr_cls_file_find(SR_SYS_INODE)))
								sal_or_self_op_arrays(&ba_res, ptr);
							break;
						default:
							break;
					}
				}
			}		
		}
	}
	
	tmp_info = info; // restore the info to previous state
	
check_old_parent:

	if (tmp_info->fileinfo.old_parent_inode != INODE_ANY) {
		ptr = sr_cls_file_find(tmp_info->fileinfo.old_parent_inode);
		if (ptr) {
			sal_or_self_op_arrays(&ba_res, ptr);
		}else if(dparent_flag == CLS_FILE_MEM_OPT_ONLY_DIR){		
			if(tmp_info->fileinfo.parent_info){ //safty check if the "parent_info" ptr is null for some reason...
				tmp_info=(disp_info_t*)sal_get_parent_dir(tmp_info);
				if(tmp_info){
					tmp_info->fileinfo.old_parent_inode = tmp_info->fileinfo.parent_directory_inode;
					goto check_old_parent;
				}
			}		
		}
	}
	
	if (array_is_clear(ba_res)) {
		goto defaultConf;
	}else{

		// UID
		if (info->tuple_info.id.uid != UID_ANY) {
			ptr = sr_cls_match_uid(SR_FILE_RULES, info->tuple_info.id.uid);
		} else {
			ptr = NULL;
		}
		if (ptr) {
			sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_uid_any(SR_FILE_RULES));
		} else { // take only dst/any
			sal_and_self_op_arrays(&ba_res, sr_cls_uid_any(SR_FILE_RULES));
		}
		if (array_is_clear(ba_res)) {
			goto defaultConf;
		}

		// PID
		if ((st = sr_cls_process_add(info->fileinfo.id.pid, SR_FALSE)) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=cls-file: error adding process",REASON);
		}
		ptr = sr_cls_process_match(SR_FILE_RULES, info->fileinfo.id.pid);
		if (ptr) {
		   sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_exec_file_any(SR_FILE_RULES));
		} else { // take only dst/any
		   sal_and_self_op_arrays(&ba_res, sr_cls_exec_file_any(SR_FILE_RULES));
		}
		if (array_is_clear(ba_res)) {
			goto defaultConf;
		}
	}
	
	goto result; // skip the default check...
	
defaultConf:
	is_def = SR_TRUE;
	if(config_params->def_file_action)
		def_action = config_params->def_file_action;	
	
result:	
	while ((rule = find_next_rule (&ba_res)) != SR_CLS_NO_MATCH) {
		if (SR_CLS_DEFAULT_RULE == rule) {
			action = def_action;
		} else {
			action = sr_cls_file_rule_match(info->fileinfo.fileop, rule);
		}
		if (action & SR_CLS_ACTION_LOG) {
			char ext[64];
			
			sprintf(ext, "%s=%d%s %s=%u %s=%s",
				RULE_NUM_KEY,rule, rule == SR_CLS_DEFAULT_RULE ? "(default)" : "", 
				INODE_NUMBER,info->fileinfo.parent_inode?info->fileinfo.parent_inode:info->fileinfo.current_inode,
				FILE_PERMISSION,(info->fileinfo.fileop&SR_FILEOPS_WRITE)?"write":(info->fileinfo.fileop&SR_FILEOPS_READ)?"read":"execute"); 
			
			if (action & SR_CLS_ACTION_DROP)
				CEF_log_event(SR_CEF_CID_FILE, "file operation drop" , SEVERITY_HIGH, ext);
			else
				CEF_log_event(SR_CEF_CID_FILE, "file operation allow" , SEVERITY_LOW, ext);
		}
		if (action & SR_CLS_ACTION_DROP) {
			return SR_CLS_ACTION_DROP;
		}
		if (action & SR_CLS_ACTION_ALLOW) {
			return SR_CLS_ACTION_ALLOW;
		}
	}

	return SR_CLS_ACTION_ALLOW;
}

// CAN-BUS events classifier
SR_32 sr_classifier_canbus(disp_info_t* info)
{
	bit_array *ptr, ba_res;
	SR_16 rule = SR_CLS_NO_MATCH;
	SR_U16 action;
	SR_U16 def_action = SR_CLS_ACTION_ALLOW; /* if we don't have default rule from user, then we just allow the packet */
	int st;
	struct config_params_t *config_params;
	SR_32 can_if_id;
	
#ifdef ROOT_CLS_IGNORE
	if (!info->tuple_info.id.uid) return SR_CLS_ACTION_ALLOW; /* no classification for root user (debug only) */
#endif

	if (sr_cls_canid_get_if_id(info->can_info.if_id, info->can_info.dev_id, &can_if_id) != SR_SUCCESS) {
		printk("ERROR invalid if_id:%d \n", info->can_info.if_id);
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=cls-can: invalid if id %d", info->can_info.if_id, REASON);
		return SR_CLS_ACTION_ALLOW;
	}
	
	is_def = SR_FALSE;
	config_params = sr_control_config_params();
	memset(&ba_res, 0, sizeof(bit_array));
	
	ptr = sr_cls_match_canid(info->can_info.msg_id,(info->can_info.dir==SR_CAN_OUT)?SR_CAN_OUT:SR_CAN_IN, can_if_id);
	if (ptr) {
		sal_or_op_arrays(ptr,(info->can_info.dir==SR_CAN_OUT)?src_cls_out_canid_any(can_if_id):src_cls_in_canid_any(can_if_id), &ba_res);
	} else { // take only inbound/any
		sal_or_self_op_arrays(&ba_res, (info->can_info.dir==SR_CAN_OUT)?src_cls_out_canid_any(can_if_id):src_cls_in_canid_any(can_if_id));
	}
	
	if (array_is_clear(ba_res)) {
		goto defaultConf;
	}else{
	
		if (info->can_info.id.pid) { 
			if ((st = sr_cls_process_add(info->can_info.id.pid, in_interrupt() != 0)) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=cls-can: error adding process",
					REASON);
			}
			ptr = sr_cls_process_match(SR_CAN_RULES, info->can_info.id.pid);
			if (ptr) {
				sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_exec_file_any(SR_CAN_RULES));
			} else { // take only dst/any
				sal_and_self_op_arrays(&ba_res, sr_cls_exec_file_any(SR_CAN_RULES));
			}
		}
		// UID
		if (info->tuple_info.id.uid != UID_ANY) {
			ptr = sr_cls_match_uid(SR_CAN_RULES, info->tuple_info.id.uid);
		} else {
			ptr = NULL;
		}
		if (ptr) {
			sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_uid_any(SR_CAN_RULES));
		} else { 
			sal_and_self_op_arrays(&ba_res, sr_cls_uid_any(SR_CAN_RULES));
		}
		if (array_is_clear(ba_res)) {
			goto defaultConf;
		}
	}

	goto result; // skip the default check...
	
defaultConf:
	is_def = SR_TRUE;
	if(config_params->def_can_action)
		def_action = config_params->def_can_action;	

result:
	while ((rule = find_next_rule (&ba_res)) != SR_CLS_NO_MATCH) {
		if (SR_CLS_DEFAULT_RULE == rule) {
			action = def_action;
		} else {
			action = sr_cls_can_rule_match(rule);
		}		
		if (action & SR_CLS_ACTION_LOG) {
			char actionstring[16], msg[64];
			SR_U8 severity;
			if (action & SR_CLS_ACTION_DROP) {
				sprintf(actionstring, "drop");
				strncpy(msg, "can message drop", 64);
				severity = SEVERITY_HIGH;
			} else if (action & SR_CLS_ACTION_ALLOW) {
				sprintf(actionstring, "allow");
				strncpy(msg, "can message allow", 64);
				severity = SEVERITY_LOW;
			} else {
				sprintf(actionstring, "log-only"); // TBD: when adding more terminal actions
				strncpy(msg, "can message log", 64);
				severity = SEVERITY_LOW;
			}

			CEF_log_event(SR_CEF_CID_CAN, msg , severity, 
				"%s=%d%s %s=%s %s=%x %s=%s %s=%s(%d)",
				RULE_NUM_KEY,rule,rule == SR_CLS_DEFAULT_RULE ? "(default)" : "",
				DEVICE_ACTION,actionstring,
				CAN_MSG_ID,info->can_info.msg_id,
				DEVICE_DIRECTION,info->can_info.dir == SR_CAN_OUT?"out":"in",
				IF_ID, sr_cls_canid_get_interface_name(can_if_id) ?: "" , info->can_info.if_id); /* "0" for inbound or "1" for outbound*/
		}
		if (action & SR_CLS_ACTION_DROP)
			return SR_CLS_ACTION_DROP;
	}

	return SR_CLS_ACTION_ALLOW;
}
