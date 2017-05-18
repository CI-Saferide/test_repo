/* file: multiplexer.c
 * purpose: this file offers general API (to upper layers)
 *          for the LSM hooks, to enable general system operations
 *          hooks registration
*/
#include "multiplexer.h"
#include "sal_linux.h"

/*
typedef struct CEF_payload
{   
    float						cef_version;
    char						dev_vendor[32];
    char						dev_product[32];
    float						dev_version;			
	enum dev_event_class_ID		class;
	char						name[32];
    enum severity				sev;
    char 						extension[256]; 
}CEF_payload;

*/

int mpx_mkdir(fileinfo* info)
{
	struct CEF_payload payload = { .cef_version = CEF_VERSION,
								   .dev_version = VSENTRY_VERSION };
		
	strcpy(payload.dev_vendor,PRODUCT_VENDOR);
	strcpy(payload.dev_product,MODULE_NAME);
	payload.class 			= FS;		
	payload.sev 			= NOTICE;
	strcpy(payload.name,"mkdir_syscall_invoked");
	sprintf(payload.extension,
			"file = %s, path = %s, pid = %ld, gid = %ld, tid = %ld", 
			info->filename, info->fullpath, info->pid,info->gid, info->tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	

	return 0;
}

