#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"
#include "sr_actions_common.h"

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

//#ifdef UNIT_TEST
	//sr_cls_network_ut();
	//sr_cls_port_ut();
	//sr_cls_canid_ut();
//#endif

	sr_cls_network_ut();

	return 0;
}

void sr_classifier_uninit(void)
{
	sr_cls_network_uninit();
	sr_cls_fs_uninit();
	sr_cls_port_uninit();
	sr_cls_canid_uninit();	
	sr_cls_exec_file_uninit();
	sr_cls_process_uninit();
	sr_cls_uid_uninit();
}

void sr_classifier_empty_tables(void)
{
	sr_cls_exec_file_empty_table();
	sr_cls_fs_empty_table();
	sr_cls_canid_empty_table();
	sr_cls_port_empty_table();
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
	ptr = sr_cls_match_ip(htonl(info->tuple_info.saddr.v4addr.s_addr), SR_DIR_SRC);
	if (ptr) {
		sal_or_op_arrays(ptr, src_cls_network_any_src(), &ba_res);
	} else { // take only src/any
		sal_or_self_op_arrays(&ba_res, src_cls_network_any_src());
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
	ptr = sr_cls_match_ip(htonl(info->tuple_info.daddr.v4addr.s_addr), SR_DIR_DST);
	if (ptr) {
		sal_and_self_op_two_arrays(&ba_res, ptr, src_cls_network_any_dst());
	} else { // take only dst/any
		sal_and_self_op_arrays(&ba_res, src_cls_network_any_dst());
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
	// UID
#if 0
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
#endif
	// PID
/* XXX Currently in network classifier process match is not done. 
   Netfiler which runs on buttomhalf context is not associated with a process descriptor, 
   therefore a match a packet level can not be done. 
   Another place to handle incomming packets at process context is not found yet. */
#if 0
	if (info->tuple_info.id.pid) { 
	    if ((st = sr_cls_process_add(info->tuple_info.id.pid)) != SR_SUCCESS) {
	        sal_printf("*** Error add process \n");
	    }
	    ptr = sr_cls_process_match(SR_NET_RULES, info->tuple_info.id.pid);
	    if (ptr) {
	       sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_exec_file_any(SR_NET_RULES));
	    } else { // take only dst/any
	       sal_and_self_op_arrays(&ba_res, sr_cls_exec_file_any(SR_NET_RULES));
	    }
	}
#endif
	// IP Proto - TODO

	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		action = sr_cls_network_rule_match(rule);
                sal_printf("sr_classifier_network: Matched Rule #%d, action is %d\n", rule, action);
		if (action & SR_CLS_ACTION_DROP) {
			sal_printf("sr_classifier_network: Rule drop\n");
			return SR_CLS_ACTION_DROP;
		}
	}

	return SR_CLS_ACTION_ALLOW;
}


SR_32 sr_classifier_file(disp_info_t* info)
{
	bit_array *ptr, ba_res;
	SR_16 rule;
	SR_U16 action;
	int st;

	if (!info->tuple_info.id.uid) return SR_CLS_ACTION_ALLOW; // Don't mess up root access
	memset(&ba_res, 0, sizeof(bit_array));

        if (info->fileinfo.parent_inode) { // create within a directory - match parent only
                ptr = sr_cls_file_find(info->fileinfo.parent_inode);
        } else {
                ptr = sr_cls_file_find(info->fileinfo.current_inode);
        }
	if (ptr) {
		sal_or_op_arrays(ptr, sr_cls_file_any(), &ba_res);
	} else { // take only src/any
		sal_or_self_op_arrays(&ba_res, sr_cls_file_any());
	}
	if (array_is_clear(ba_res)) {
		return SR_CLS_ACTION_ALLOW;
	}

/* XXX UID should be fixed. The UID values are not updated in rules or any bitmaps */
#if 0
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
#endif

	// PID
	if ((st = sr_cls_process_add(info->fileinfo.id.pid)) != SR_SUCCESS) {
	    sal_printf("*** Error add process \n");
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
		sal_printf("sr_classifier_file: Matched Rule #%d, action is %d\n", rule, action);
		if (action & SR_CLS_ACTION_DROP) {
			sal_printf("sr_classifier_file: Rule drop\n");
			return SR_CLS_ACTION_DROP;
		}
		if (action & SR_CLS_ACTION_ALLOW) {
			sal_printf("sr_classifier_file: Rule allow\n");
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

	ptr = sr_cls_match_canid(info->can_info.msg_id);

	if (!ptr) {
		//sal_kernel_print_alert("sr_classifier_canID: No matching rule!\n");
		return SR_CLS_ACTION_ALLOW;
	}
	memcpy(&ba_res, ptr, sizeof(bit_array)); // Perform arbitration

	if (info->can_info.id.pid) { 
	    if ((st = sr_cls_process_add(info->can_info.id.pid)) != SR_SUCCESS) {
	        sal_printf("*** Error add process \n");
	    }
	    ptr = sr_cls_process_match(SR_CAN_RULES, info->can_info.id.pid);
	    if (ptr) {
	        sal_and_self_op_two_arrays(&ba_res, ptr, sr_cls_exec_file_any(SR_CAN_RULES));
	    } else { // take only dst/any
	        sal_and_self_op_arrays(&ba_res, sr_cls_exec_file_any(SR_CAN_RULES));
	    }
	}

	while ((rule = sal_ffs_and_clear_array (&ba_res)) != -1) {
		action = sr_cls_can_rule_match(rule);
                sal_printf("sr_classifier_canID: Matched Rule #%d, action is %d\n", rule, action);
		if (action & SR_CLS_ACTION_DROP) {
			sal_printf("sr_classifier_canID: Rule drop\n");
			return SR_CLS_ACTION_DROP;
		}
	}
	return SR_CLS_ACTION_ALLOW;
}
