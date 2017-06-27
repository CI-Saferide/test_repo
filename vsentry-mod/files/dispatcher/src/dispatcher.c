/* file: dispatcher.c
 * purpose: this file offers general API (to upper layers)
 *          for the LSM hooks, to enable general system operations
 *          hooks registration
*/
#include "dispatcher.h"
#include "sr_msg.h"
#include "sr_sal_common.h"

CEF_payload cef_init(char* event_name,enum severity sev,enum dev_event_class_ID	class)
{
	struct CEF_payload payload = { .cef_version = CEF_VERSION,
								   .dev_version = VSENTRY_VERSION };
	payload.class = class;		
	payload.sev = sev;		
	sal_strcpy(payload.dev_vendor,PRODUCT_VENDOR);
	sal_strcpy(payload.dev_product,MODULE_NAME);
	sal_strcpy(payload.name,event_name);
	
	return payload;
}

int disp_mkdir(disp_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);
	
	sal_sprintf(payload.extension,
			"mkdir=%s, path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	printk ("mkdir called\n");
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));
	return 0;
}

int disp_rmdir(disp_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"rmdir=%s, path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));
	return 0;
}

int disp_inode_create(disp_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"create dir=%s, path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));
	return 0;
}

int disp_path_chmod(disp_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = WARNING;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"path=%s, pid=%d, gid=%d, tid=%d",  
			info->fileinfo.fullpath, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));	
	return 0;
}

int disp_file_open(disp_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"file=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));	
	return 0;
}

int disp_inode_link(disp_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"file=%s, new path=%s, old path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath, 
			info->fileinfo.old_path, 
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));	
	return 0;
}

int disp_inode_unlink(disp_info_t* info)
{
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"file=%s, from path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath,  
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));	
	return 0;
}

int disp_inode_symlink(disp_info_t* info){
	
	enum dev_event_class_ID	class = FS;
	enum severity sev = NOTICE;
	struct CEF_payload payload = cef_init(info->fileinfo.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"file=%s, from path=%s, pid=%d, gid=%d, tid=%d", 
			info->fileinfo.filename, 
			info->fileinfo.fullpath,  
			info->fileinfo.id.pid,
			info->fileinfo.id.gid, 
			info->fileinfo.id.tid);
			
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));	
	return 0;	
}

int disp_socket_connect(disp_info_t* info)
{
	enum dev_event_class_ID	class = NETWORK;
	enum severity sev = WARNING;
	struct CEF_payload payload = cef_init(info->address_info.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"IP:PORT=%s:%d, tpid=%d, gid=%d, tid=%d", 
			info->address_info.ipv4, 
			info->address_info.port, 
			info->address_info.id.pid,
			info->address_info.id.gid, 
			info->address_info.id.tid);
			
	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));
	return 0;
}

int disp_socket_create(disp_info_t* info){
	enum dev_event_class_ID	class = NETWORK;
	enum severity sev = WARNING;
	struct CEF_payload payload = cef_init(info->address_info.id.event_name,sev,class);

	sal_sprintf(payload.extension,
			"family:%s, type:%s, protocol:%d, kern:%d, pid=%d, gid=%d, tid=%d", 
			info->socket_info.family, 
			info->socket_info.type,
			info->socket_info.protocol,
			info->socket_info.kern,   
			info->socket_info.id.pid,
			info->socket_info.id.gid, 
			info->socket_info.id.tid);

	sr_send_msg(LOG_BUF, (unsigned char*)&payload, sizeof(CEF_payload));		
	return 0;	
}
