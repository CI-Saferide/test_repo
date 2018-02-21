#ifndef SR_ENGINE_UTILS
#define SR_ENGINE_UTILS

#include "sr_types.h"

SR_32 sr_get_inode(char *file_name, /*@out@*/ SR_U32 *inode);
SR_32 sr_get_uid(char *uid);

#endif /* SR_ENGINE_UTILS */
