/* file: sal_sysfs.h
 * purpose: this file used as a getter/setter to the sysfs variables
*/

#ifndef SYSFS_CLS_FILE_H
#define SYSFS_CLS_FILE_H

#include "sr_types.h"
#include "sr_cls_file.h"
#include "sr_cls_file_common.h"

void set_sysfs_file(unsigned char * buff);
unsigned char* get_sysfs_file(void);
void dump_file_table(void);
void dump_file_rule(SR_16 rule);

struct sysfs_file_ent_t 
{
	SR_8 actionstring[16],uid_buff[16],inode_buff[16],inode_exe_buff[16];
	SR_U16 rule,uid,action,file_ops;
	SR_U32 inode,inode_exe;
	SR_8 perm_string[4];
};

#endif /* SYSFS_CLS_FILE_H*/
