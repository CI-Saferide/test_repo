/* file: sal_sysfs.h
 * purpose: this file used as a getter/setter to the sysfs variables
*/

#ifndef SYSFS_CLS_CAN_H
#define SYSFS_CLS_CAN_H

#include "sr_types.h"
#include "sr_cls_canid.h"
#include "sr_cls_canbus_common.h"

size_t dump_can_table(char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call);
size_t dump_can_rule(SR_16 rule,char __user *user_buf, size_t count, loff_t *ppos);

struct sysfs_can_ent_t 
{
	SR_8 dir[5],actionstring[16],uid_buff[16],inode_buff[16],canid_buff[16];
	SR_U16 uid,action;
	SR_U32 rule,inode;
	SR_32 canid;

};

#endif /* SYSFS_CLS_CAN_H*/
