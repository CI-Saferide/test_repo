/* file: multiplexer.c
 * purpose: this file offers general API (to upper layers)
 *          for the LSM hooks, to enable general system operations
 *          hooks registration
*/
#include "sr_netlink.h"
#include "multiplexer.h"

int mpx_mkdir(fileinfo* info)
{
	printk (KERN_INFO "mkdir hook called. filename = %s, path = %s, gid = %ld, tid = %ld\n", 
			info->filename, info->fullpath, info->gid, info->tid);
	return 0;
}
