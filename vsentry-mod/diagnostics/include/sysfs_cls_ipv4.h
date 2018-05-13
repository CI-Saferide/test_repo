/* file: sal_sysfs.h
 * purpose: this file used as a getter/setter to the sysfs variables
*/

#ifndef SYSFS_CLS_IPV4_H
#define SYSFS_CLS_IPV4_H

#include "sr_types.h"
#include "sr_cls_network_common.h"
#include "sr_radix.h"

void set_sysfs_ipv4(unsigned char * buff);
unsigned char* get_sysfs_ipv4(void);
void dump_ipv4_table(void);
void dump_ipv4_rule(SR_16 rule);

struct sysfs_network_ent_t 
{
	SR_8 actionstring[16],uid_buff[16],inode_buff[16];
	SR_U16 uid,action;
	SR_U32 rule,inode;
	SR_8 src_ipv4[16],src_netmask[16], dst_ipv4[16],dst_netmask[16],proto[16],binary[SR_MAX_PATH];
	SR_32 s_port,d_port;
	SR_U8 src_flag,dst_flag; 	// because the way the cls info stored in the tables 
								// you need an indicator to iterate in a chaned hash.
};

#endif /* SYSFS_CLS_IPV4_H*/
