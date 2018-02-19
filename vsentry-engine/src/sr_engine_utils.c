#include "sr_engine_utils.h"
#include "sr_types.h"
#include "sr_sal_common.h"
#include "sr_cls_uid_common.h"
#include "sr_cls_file_common.h"

SR_32 sr_get_inode(char *file_name, int is_dir, SR_U32 *inode)
{
	struct stat buf;

	if (*file_name != '*') {
	    if(lstat(file_name, &buf)) { // Error
	       CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"failed to get inode for file :%s:\n", file_name);
	       return SR_ERROR;
	    }
	    if (is_dir && S_ISDIR(buf.st_mode)) {
	       CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"directory cannot be added as execution file\n");
	       return SR_ERROR;
	    }
	    *inode = buf.st_ino;
	} else {
	    *inode = INODE_ANY;
 	}

	return SR_SUCCESS;
}


SR_32 sr_get_uid(char *user) 
{
	if (!user || *user == '*')
		return UID_ANY;
	return sal_get_uid(user);
}
