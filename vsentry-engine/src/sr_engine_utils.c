#include "sr_engine_utils.h"
#include "sr_types.h"
#include "sr_sal_common.h"
#include "sr_cls_uid_common.h"
#include "sr_cls_file_common.h"

SR_32 sr_get_inode(char *file_name, SR_U32 *inode)
{
	struct stat buf = {};

	*inode = INODE_ANY;
	if (*file_name != '*') {
	    if(lstat(file_name, &buf)) { // Error
	       CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to get inode for file %s",REASON,
			file_name);
	       return SR_ERROR;
	    }
	    *inode = buf.st_ino;
	}

	return SR_SUCCESS;
}

SR_32 sr_get_uid(char *user) 
{
	if (!user || *user == '*')
		return UID_ANY;
	return sal_get_uid(user);
}

/* It is the resposibity of the calling function to allocate anough memort for persmissions buffer */
void sr_get_file_perm_from_bits(SR_U8 file_op, char *permissions)
{
	int i = 0;

	memset(permissions, 0, 4);
	if (file_op & SR_FILEOPS_READ)
		permissions[i++] = 'r';
	if (file_op & SR_FILEOPS_WRITE)
		permissions[i++] = 'w';
	if (file_op & SR_FILEOPS_EXEC)
		permissions[i++] = 'x';
}
