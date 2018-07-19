/* file: sal_debugfs.h
 * purpose: this file used as a getter/setter to the debugfs variables
*/

#ifndef DEBUGFS_CLS_IPV4_H
#define DEBUGFS_CLS_IPV4_H

#include "sr_types.h"
#include "sr_cls_network_common.h"
#include "sr_radix.h"

size_t dump_ipv4_table(char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call);
size_t dump_ipv4_rule(SR_16 rule, char __user *user_buf, size_t count, loff_t *ppos);
size_t dump_ipv4_tree(SR_U8 dir, char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call);
size_t dump_ipv4_ip(SR_32 ip, char __user *user_buf, size_t count, loff_t *ppos);

struct debugfs_network_ent_t
{
	SR_8 actionstring[32],uid_buff[32],inode_buff[16];
	SR_U16 uid,action;
	SR_U32 rule,inode;
	SR_8 src_ipv4[16],dst_ipv4[16],proto[16],binary[SR_MAX_PATH];
	SR_32 s_port,d_port;
	SR_U8 src_netmask_len, dst_netmask_len; // mask length in bits
	SR_U8 src_flag,dst_flag; 	// because the way the cls info stored in the tables 
								// you need an indicator to iterate in a chaned hash.
};

#endif /* DEBUGFS_CLS_IPV4_H*/