/* file: multiplexer.c
 * purpose: this file offers general API (to upper layers)
 *          for the LSM hooks, to enable general system operations
 *          hooks registration
*/
#include "multiplexer.h"
#include "sal_linux.h" //big change

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
			"dir=%s, path=%s, pid=%d, gid=%d, tid=%d", 
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
			"dir=%s, path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	
	return 0;
}

int mpx_inode_create(mpx_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sprintf(payload.extension,
			"dir=%s, path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	
	return 0;
}

int mpx_path_chmod(mpx_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = WARNING;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sprintf(payload.extension,
			"path=%s, pid=%d, gid=%d, tid=%d",  
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	
	return 0;
}

int mpx_file_open(mpx_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sprintf(payload.extension,
			"file=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	
	return 0;
}

int mpx_inode_link(mpx_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sprintf(payload.extension,
			"file=%s, new path=%s, old path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.old_path, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	
	return 0;
}

int mpx_inode_unlink(mpx_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sprintf(payload.extension,
			"file=%s, from path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath,  
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	
	return 0;
}

int mpx_inode_symlink(mpx_info_t* info){
	
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sprintf(payload.extension,
			"file=%s, from path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath,  
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));	
	return 0;	
}

int mpx_socket_connect(mpx_info_t* info)
{
	enum dev_event_class_ID	class = NETWORK;
	enum severity sev = WARNING;
	struct CEF_payload payload = cef_init(info->address_info.id.event_name,sev,class);

	sprintf(payload.extension,
			"IP:PORT=%s:%d, tpid=%d, gid=%d, tid=%d", 
			info->address_info.ipv4, 
			info->address_info.port, 
			info->address_info.id.pid,
			info->address_info.id.gid, 
			info->address_info.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));
	return 0;
}

int mpx_socket_create(mpx_info_t* info){
	enum dev_event_class_ID	class = NETWORK;
	enum severity sev = WARNING;
	struct CEF_payload payload = cef_init(info->address_info.id.event_name,sev,class);

	sprintf(payload.extension,
			"family:%s, type:%s, protocol:%d, kern:%d, pid=%d, gid=%d, tid=%d", 
			info->socket_info.family, 
			info->socket_info.type,
			info->socket_info.protocol,
			info->socket_info.kern,   
			info->socket_info.id.pid,
			info->socket_info.id.gid, 
			info->socket_info.id.tid);
			
	sal_socket_tx_msg(0,payload, sizeof(CEF_payload));
	return 0;	
}
