/* file: sal_debugfs.h
 * purpose: this file used as a getter/setter to the debugfs variables
*/

#ifndef DEBUGFS_CLS_FILE_H
#define DEBUGFS_CLS_FILE_H

#include "sr_types.h"
#include "sr_cls_file.h"
#include "sr_cls_file_common.h"

size_t dump_file_table(char __user *user_buf, size_t count, loff_t *ppos, SR_U8 first_call);
size_t dump_file_rule(SR_16 rule,char __user *user_buf, size_t count, loff_t *ppos);

struct debugfs_file_ent_t
{
	SR_8 actionstring[32],uid_buff[32],inode_buff[16],inode_exe_buff[16];
	SR_U16 rule,uid,action,file_ops;
	SR_U32 inode,inode_exe;
	SR_8 perm_string[4];
};

#endif /* DEBUGFS_CLS_FILE_H*/
