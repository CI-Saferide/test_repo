#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_actions_common.h"
#include "sr_cls_sk_process.h"

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

#ifdef UNIT_TEST
	sr_cls_network_ut();
	sr_cls_port_ut();
	sr_cls_canid_ut();
#endif
	sr_cls_sl_process_hash_ut();

	return 0;
}

void sr_classifier_uninit(void)
{
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

///////////////////////////////////////////////////////////////////////////
/////// Actual classifiers entry points
///////////////////////////////////////////////////////////////////////////
// Network events classifier
SR_32 sr_classifier_network(disp_info_t* info)
{
	bit_array *ptr;
	SR_16 rule;
	SR_U16 action;
	bit_array ba_res;

	memset(&ba_res, 0, sizeof(bit_array));

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
		return SR_CLS_ACTION_ALLOW;
	}
	// Dst Port
	ptr = sr_cls_match_port(info->tuple_info.dport, SR_DIR_DST, info->tuple_info.ip_proto);
	if (ptr) {
		sal_and_self_op_two_arrays(&ba_res, ptr, src_cls_port_any_dst());
	} else { // take only dst/any
		sal_and_self_op_arrays(&ba_res, src_cls_port_any_dst());
	}
	if (array_is_clear(ba_res)) {
		return SR_CLS_ACTION_ALLOW;
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
		return SR_CLS_ACTION_ALLOW;
	}
	// Src Port
	ptr = sr_cls_match_port(info->tuple_info.sport, SR_DIR_SRC, info->tuple_info.ip_proto);
	if (ptr) {
		sal_and_self_op_two_arrays(&ba_res, ptr, src_cls_port_any_src());
	} else { // take only dst/any
		sal_and_self_op_arrays(&ba_res, src_cls_port_any_src());
	}
	if (array_is_clear(ba_res)) {
		return SR_CLS_ACTION_ALLOW;
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
			return SR_CLS_ACTION_ALLOW;
		}
		//PID
		ptr = sr_cls_process_match(SR_NET_RULES, info->tuple_info.id.pid);
		if (ptr) {
			sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_exec_file_any(SR_NET_RULES));
		} else { // take only dst/any
			sal_and_self_op_arrays(&ba_res, sr_cls_exec_file_any(SR_NET_RULES));
		}
	}
	// IP Proto - TODO

	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		action = sr_cls_network_rule_match(rule, info->tuple_info.size);
		if (action & SR_CLS_ACTION_LOG) {
			char ext[256],sip[16],dip[16], actionstring[16];
			SR_U32 sip_t, dip_t;
			sip_t = info->tuple_info.saddr.v4addr.s_addr;
			dip_t = info->tuple_info.daddr.v4addr.s_addr;
			
			sprintf(actionstring, "Allow");
			sprintf(sip, "%02d.%02d.%02d.%02d", (sip_t&0xff000000)>>24, (sip_t&0x00ff0000)>>16, (sip_t&0xff00)>> 8, sip_t&0xff);
			sprintf(dip, "%02d.%02d.%02d.%02d", (dip_t&0xff000000)>>24, (dip_t&0x00ff0000)>>16, (dip_t&0xff00)>> 8, dip_t&0xff);
			sprintf(ext, "RuleNumber=%d Action=%s proto=%s sip=%s sport=%d dip=%s dport=%d", rule, actionstring, info->tuple_info.ip_proto == IPPROTO_TCP?"TCP":"UDP", sip, info->tuple_info.sport, dip, info->tuple_info.dport); 
			if (action & SR_CLS_ACTION_DROP) {
				CEF_log_event(SR_CEF_CID_NETWORK, "Connection drop" , SEVERITY_HIGH, ext);
			} else {
				CEF_log_event(SR_CEF_CID_NETWORK, "Connection allow" , SEVERITY_LOW, ext);
			}
		}
		if (action & SR_CLS_ACTION_DROP)
			return SR_CLS_ACTION_DROP;
	}

	return SR_CLS_ACTION_ALLOW;
}


SR_32 sr_classifier_file(disp_info_t* info)
{
	bit_array *ptr = NULL, ba_res;
	SR_16 rule;
	SR_U16 action;
	int st;

	if (!info->tuple_info.id.uid) return SR_CLS_ACTION_ALLOW; // Don't mess up root access
	memset(&ba_res, 0, sizeof(bit_array));

	sal_or_self_op_arrays(&ba_res, sr_cls_file_any());
	if (info->fileinfo.current_inode != INODE_ANY) {
		ptr = sr_cls_file_find(info->fileinfo.current_inode);
		if (ptr) {
			sal_or_self_op_arrays(&ba_res, ptr);
		}
        }
	if (info->fileinfo.parent_inode != INODE_ANY) {
		ptr = sr_cls_file_find(info->fileinfo.parent_inode);
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
	if (info->fileinfo.old_parent_inode != INODE_ANY) {
		ptr = sr_cls_file_find(info->fileinfo.old_parent_inode);
		if (ptr) {
			sal_or_self_op_arrays(&ba_res, ptr);
		}
	}
	if (array_is_clear(ba_res)) {
		return SR_CLS_ACTION_ALLOW;
	}

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
		return SR_CLS_ACTION_ALLOW;
	}

	// PID
	if ((st = sr_cls_process_add(info->fileinfo.id.pid)) != SR_SUCCESS) {
	    CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
						"error adding process \n");
	}
	ptr = sr_cls_process_match(SR_FILE_RULES, info->fileinfo.id.pid);
	if (ptr) {
	   sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_exec_file_any(SR_FILE_RULES));
	} else { // take only dst/any
	   sal_and_self_op_arrays(&ba_res, sr_cls_exec_file_any(SR_FILE_RULES));
	}
	if (array_is_clear(ba_res)) {
		return SR_CLS_ACTION_ALLOW;
	}

	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		action = sr_cls_file_rule_match(info->fileinfo.fileop, rule);
		if (action & SR_CLS_ACTION_LOG) {
			char ext[64];
			sprintf(ext, "RuleNumber=%d inode=%d Operation=%s", rule, info->fileinfo.parent_inode?info->fileinfo.parent_inode:info->fileinfo.current_inode,(info->fileinfo.fileop&SR_FILEOPS_WRITE)?"Write":(info->fileinfo.fileop&SR_FILEOPS_READ)?"Read":"Execute"); 
			if (action & SR_CLS_ACTION_DROP)
				CEF_log_event(SR_CEF_CID_FILE, "File operation drop" , SEVERITY_HIGH, ext);
			else
				CEF_log_event(SR_CEF_CID_FILE, "File operation allow" , SEVERITY_LOW, ext);
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
	SR_16 rule;
	SR_U16 action;
	int st;
	
	memset(&ba_res, 0, sizeof(bit_array));
	
	ptr = sr_cls_match_canid(info->can_info.msg_id,(info->can_info.dir==SR_CAN_OUT)?SR_CAN_OUT:SR_CAN_IN);
	if (ptr) {
		sal_or_op_arrays(ptr,(info->can_info.dir==SR_CAN_OUT)?src_cls_out_canid_any():src_cls_in_canid_any(), &ba_res);
	} else { // take only inbound/any
		sal_or_self_op_arrays(&ba_res, (info->can_info.dir==SR_CAN_OUT)?src_cls_out_canid_any():src_cls_in_canid_any());
	}
	

	if (info->can_info.id.pid) { 
	    if ((st = sr_cls_process_add(info->can_info.id.pid)) != SR_SUCCESS) {
	        CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"error adding process \n");
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
		return SR_CLS_ACTION_ALLOW;
	}

	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		action = sr_cls_can_rule_match(rule);
		if (action & SR_CLS_ACTION_LOG) {
			char actionstring[16], msg[64];
			SR_U8 severity;
			if (action & SR_CLS_ACTION_DROP) {
				sprintf(actionstring, "Drop");
				strncpy(msg, "CAN message drop", 64);
				severity = SEVERITY_HIGH;
			} else if (action & SR_CLS_ACTION_ALLOW) {
				sprintf(actionstring, "Allow");
				strncpy(msg, "CAN message allow", 64);
				severity = SEVERITY_LOW;
			} else {
				sprintf(actionstring, "log-only"); // TBD: when adding more terminal actions
				strncpy(msg, "CAN message log", 64);
				severity = SEVERITY_LOW;
			}

			CEF_log_event(SR_CEF_CID_CAN, msg , severity, 
							"RuleNumber=%d Action=%s CanID=%x %s", rule, actionstring, info->can_info.msg_id
							, info->can_info.dir == SR_CAN_OUT?"OUT":"IN");
		}
		if (action & SR_CLS_ACTION_DROP)
			return SR_CLS_ACTION_DROP;
	}
	return SR_CLS_ACTION_ALLOW;
}
