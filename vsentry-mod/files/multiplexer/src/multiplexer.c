/* file: multiplexer.c
 * purpose: this file offers general API (to upper layers)
 *          for the LSM hooks, to enable general system operations
 *          hooks registration
*/
#include "multiplexer.h"
#include "sal_linux.h"

int mpx_mkdir(fileinfo* info)
{
	int i=0;
	char buff[256];

	
	sprintf(buff,"[%d]mkdir hook called. filename = %s, path = %s, gid = %ld, tid = %ld\n",i, 
			info->filename, info->fullpath, info->gid, info->tid);
	sal_socket_tx_msg(0,buff, strlen(buff));	

	
	//sal_kernel_print_info ("mkdir hook called. filename = %s, path = %s, gid = %ld, tid = %ld\n", 
	//		info->filename, info->fullpath, info->gid, info->tid);
	return 0;
}
