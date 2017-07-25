
#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "sr_cls_network_common.h"

SR_32 sr_classifier_init(void)
{
	sr_cls_network_init();
	sr_cls_fs_init();
	
	sr_cls_port_init();		
	sr_cls_canid_init();
	
	sr_cls_rules_init();
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
	// IP Proto - TODO
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
	bit_array *ba_inode, ba_res;
	SR_16 rule;
	SR_U16 action;

        if (info->fileinfo.parent_inode) { // create within a directory - match parent only
                ba_inode = sr_cls_file_find(info->fileinfo.parent_inode);
        } else {
                ba_inode = sr_cls_file_find(info->fileinfo.current_inode);
        }

	if (!ba_inode) {
		//sal_kernel_print_alert("sr_classifier_file: No matching rule!\n");
		return SR_CLS_ACTION_NOOP;
	}
	memcpy(&ba_res, ba_inode, sizeof(bit_array)); // Perform arbitration

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
	bit_array *ba_canid, ba_res;
	SR_16 rule;
	SR_U16 action;

	ba_canid = sr_cls_match_canid(info->can_info.msg_id);

	if (!ba_canid) {
		//sal_kernel_print_alert("sr_classifier_canID: No matching rule!\n");
		return SR_CLS_ACTION_ALLOW;
	}
	memcpy(&ba_res, ba_canid, sizeof(bit_array)); // Perform arbitration

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
