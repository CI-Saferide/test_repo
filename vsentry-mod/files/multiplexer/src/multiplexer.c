/* file: multiplexer.c
 * purpose: this file offers general API (to upper layers)
 *          for the LSM hooks, to enable general system operations
 *          hooks registration
*/
#include "multiplexer.h"
#include "sal_linux.h"

int mpx_mkdir(fileinfo* info)
{
	struct CEF_payload payload;
	
	payload.cef_version		= 1;		
	sprintf(payload.dev_vendor,"SafeRide");
	sprintf(payload.dev_product,"vSentry");		
	payload.sev 			= EIGHT;
	payload.module			= LSM;
	payload.class 			= FS;
	sprintf(payload.extension,"mkdir hook called. filename = %s, path = %s,pid = %ld, gid = %ld, tid = %ld\n", 
			info->filename, info->fullpath, info->pid,info->gid, info->tid);
	payload.extension_size	= strlen(payload.extension);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	

	return 0;
}

