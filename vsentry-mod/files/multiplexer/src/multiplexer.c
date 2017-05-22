/* file: multiplexer.c
 * purpose: this file offers general API (to upper layers)
 *          for the LSM hooks, to enable general system operations
 *          hooks registration
*/
#include "multiplexer.h"
#include "sal_linux.h"

CEF_payload cef_init(char* event_name,enum severity sev,enum dev_event_class_ID	class)
{
	struct CEF_payload payload = { .cef_version = CEF_VERSION,
								   .dev_version = VSENTRY_VERSION };
	payload.class = class;		
	payload.sev = sev;		
	strcpy(payload.dev_vendor,PRODUCT_VENDOR);
	strcpy(payload.dev_product,MODULE_NAME);
	strcpy(payload.name,event_name);
	
	return payload;
}

int mpx_mkdir(mpx_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);
	
	sprintf(payload.extension,
			"dir = %s, path = %s, pid = %ld, gid = %ld, tid = %ld", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	

	return 0;
}

int mpx_rmdir(mpx_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sprintf(payload.extension,
			"dir = %s, path = %s, pid = %ld, gid = %ld, tid = %ld", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	

	return 0;
}

int mpx_sk_connect(mpx_info_t* info)
{
	enum dev_event_class_ID	class = NETWORK;
	enum severity sev = WARNING;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sprintf(payload.extension,
			"IP:PORT = %s:%d, pid = %ld, gid = %ld, tid = %ld", 
			info->sock_info.ipv4, 
			info->sock_info.port, 
			info->sock_info.id.pid,
			info->sock_info.id.gid, 
			info->sock_info.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));
	return 0;
}

