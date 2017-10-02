#include "sr_sal_common.h"
#include "sr_cls_file_common.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_msg_dispatch.h"
#include "sr_engine_utils.h"
#include "sr_file_hash.h"
#include "sr_cls_rules_control.h"

#define NUM_OF_LSTAT_ITERS 3

//#include "sr_cls_file.h"

// filename: path of file/dir to add rule to
// rulenum: index of rule to be added
// treetop: 1 for the first call, 0 for recursive calls further down.
int sr_cls_file_add_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U8 treetop)
{
	struct stat buf;
	sr_file_msg_cls_t *msg;
	SR_U32 exec_inode;
	SR_32  uid;
        int st;

	if(lstat(filename, &buf)) { // Error
		perror("lstat");
		return SR_ERROR;
	}

	if ((st = sr_get_inode(exec, 0, &exec_inode)) != SR_SUCCESS) {
	    sal_printf("Error: %s failed getting inode \n", __FUNCTION__);
	    return st;
	}

	uid = sr_get_uid(user);

	if (S_ISREG(buf.st_mode)) {
		if ((buf.st_nlink > 1) && (treetop)) {
			sal_printf("Error: Cannot add classification rules for hard links\n");
			return SR_ERROR;
		}
		// sr_cls_inode_add_rule(buf.st_ino, rulenum)
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_ADD_RULE;
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.inode1=buf.st_ino;
			msg->sub_msg.exec_inode= exec_inode;
			msg->sub_msg.uid= uid;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
	}
	if (S_ISDIR(buf.st_mode))  {
		// first update the directory itself
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_ADD_RULE;
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.inode1=buf.st_ino;
			msg->sub_msg.exec_inode=exec_inode;
			msg->sub_msg.uid=uid;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
		// Now iterate subtree
		DIR * dir;
		long name_max;
		struct dirent * buf, * de;

		if ((dir = opendir(filename))
				&& (name_max = pathconf(filename, _PC_NAME_MAX)) > 0
				&& (buf = (struct dirent *)malloc(
					offsetof(struct dirent, d_name) + name_max + 1)))
		{
			char fullpath[SR_MAX_PATH];

			while (readdir_r(dir, buf, &de) == 0 && de)
			{
				if ((!strcmp(de->d_name, ".")) || (!strcmp(de->d_name, "..")))
					continue;
				snprintf(fullpath, SR_MAX_PATH, "%s/%s", filename, de->d_name);
				sr_cls_file_add_rule(fullpath, exec, user, rulenum, 0);
			}
		}
	}
	if (S_ISLNK(buf.st_mode))  {
		// first update the link itself
		// sr_cls_inode_add_rule(buf.st_ino, rulenum)
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_ADD_RULE;
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.inode1=buf.st_ino;
			msg->sub_msg.exec_inode=exec_inode;
			msg->sub_msg.uid=uid;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
		//TODO: Do I need to update the destination file as well ???
		//Can use realpath() to resolve target filename.
		//I believe we should not modify the target file in this case.
	}
	return SR_SUCCESS;
}

// filename: path of file/dir to add rule to
// rulenum: index of rule to be added
// treetop: 1 for the first call, 0 for recursive calls further down.
int sr_cls_file_del_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U8 treetop)
{
	struct stat buf;
	sr_file_msg_cls_t *msg;
	SR_U32 exec_inode;
	SR_32  uid;
        int st;

	if(lstat(filename, &buf)) { // Error
		return SR_ERROR;
	}

	if ((st = sr_get_inode(exec, 0, &exec_inode)) != SR_SUCCESS) {
	    sal_printf("Error: %s failed getting inode \n", __FUNCTION__);
	   return st;
	}

	uid = sr_get_uid(user);

	if (S_ISREG(buf.st_mode)) {
		if ((buf.st_nlink > 1) && (treetop)) {
			printf("Error: Cannot del classification rules for hard links\n");
			return SR_ERROR;
		}
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_DEL_RULE;
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.inode1=buf.st_ino;
			msg->sub_msg.exec_inode=exec_inode;
			msg->sub_msg.uid=uid;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
	}
	if (S_ISDIR(buf.st_mode))  {
		// first update the directory itself
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_DEL_RULE;
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.inode1=buf.st_ino;
			msg->sub_msg.exec_inode=exec_inode;
			msg->sub_msg.uid=uid;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
		// Now iterate subtree
		DIR * dir;
		long name_max;
		struct dirent * buf, * de;

		if ((dir = opendir(filename))
				&& (name_max = pathconf(filename, _PC_NAME_MAX)) > 0
				&& (buf = (struct dirent *)malloc(
						offsetof(struct dirent, d_name) + name_max + 1)))
		{
			char fullpath[SR_MAX_PATH];

			while (readdir_r(dir, buf, &de) == 0 && de)
			{
				if ((!strcmp(de->d_name, ".")) || (!strcmp(de->d_name, "..")))
					continue;
				snprintf(fullpath, SR_MAX_PATH, "%s/%s", filename, de->d_name);
				sr_cls_file_del_rule(fullpath, exec, user, rulenum, 0);
			}
		}
	}
	if (S_ISLNK(buf.st_mode))  {
		// first update the link itself
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_DEL_RULE;
			msg->sub_msg.rulenum = rulenum;
			msg->sub_msg.inode1=buf.st_ino;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
		//Can use realpath() to resolve target filename.
		//I believe we should not modify the target file in this case.
	}
	return SR_SUCCESS;
}

static SR_U32 sr_event_process_rule(char *filename, char *exec, char *user, SR_U32 rulenum, SR_U16 actions, SR_8 file_ops)
{
        sr_cls_file_add_rule(filename, exec, user, rulenum, 1);
        sr_cls_rule_add(SR_FILE_RULES, rulenum, actions, file_ops, /* file_rule_tuple.max_rate */ 0, /* file_rule.rate_action */ 0 ,
                         /* file_ruole.action.log_target */ 0 , /* file_rule.tuple.action.email_id */ 0 , /* file_rule.tuple.action.phone_id */ 0 , /* file_rule.action.skip_rulenum */ 0);

        return SR_SUCCESS;
}

// This function should be invoked upon file creation. 
// It will need to check if file has roules associated with it or 
// parent directory has rules associated with it and inherit accordingly
int sr_cls_file_create(char *filename)
{ 
	struct stat buf,buf2;
	char parentdir[SR_MAX_PATH];
	sr_file_msg_cls_t *msg;
	int rc, i;
	SR_BOOL is_file_found = SR_FALSE;

	for (i = 0; i < NUM_OF_LSTAT_ITERS; i++) {
		usleep(20000);
		if (lstat(filename, &buf) == 0) { 
			is_file_found = SR_TRUE;
			break;
		}
	}
	if (!is_file_found) {
		sal_printf("Error %s: lstat failed, file:%s \n", __FUNCTION__, filename);
		return SR_ERROR;
	}

	if ((rc = sr_file_hash_exec_for_file(filename, sr_event_process_rule)) != SR_SUCCESS) {
		sal_printf("Error %s: sr_file_hash_exec_for_file failed, file:%s \n", __FUNCTION__, filename);
		return rc;
	}

	if ((S_ISREG(buf.st_mode)) || (S_ISDIR(buf.st_mode))) {
		char *pTmp = strrchr(filename, '/');
		if (!pTmp)
			return SR_ERROR;
		strncpy(parentdir, filename, pTmp-filename);
		parentdir[pTmp-filename] = 0;
		if (lstat(parentdir, &buf2)) {
			return SR_ERROR;
		}
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_INHERIT;
			msg->sub_msg.inode1=buf2.st_ino;
			msg->sub_msg.inode2=buf.st_ino;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
	}
	
	return SR_SUCCESS;
}
// This function should be invoked upon file deletion. 
// It will need to check if there's an entry and remove it
void sr_cls_file_delete(char *filename)
{ 
	struct stat buf;
	sr_file_msg_cls_t *msg;

	if(lstat(filename, &buf)) { // Error
		return;
	}
	if ((S_ISREG(buf.st_mode)) && (buf.st_nlink == 1)) {
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_REMOVE;
			msg->sub_msg.inode1=buf.st_ino;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
	}
	if (S_ISDIR(buf.st_mode)) {
		// sr_cls_inode_remove(buf.st_mode)
		msg = (sr_file_msg_cls_t*)sr_get_msg(ENG2MOD_BUF, ENG2MOD_MSG_MAX_SIZE);
		if (msg) {
			msg->msg_type = SR_MSG_TYPE_CLS_FILE;
			msg->sub_msg.msg_type = SR_CLS_INODE_REMOVE;
			msg->sub_msg.inode1=buf.st_ino;
			sr_send_msg(ENG2MOD_BUF, sizeof(msg));
		}
		// Now iterate subtree
		DIR * dir;
		long name_max;
		struct dirent * buf, * de;

		if ((dir = opendir(filename))
				&& (name_max = pathconf(filename, _PC_NAME_MAX)) > 0
				&& (buf = (struct dirent *)malloc(
						offsetof(struct dirent, d_name) + name_max + 1)))
		{
			char fullpath[SR_MAX_PATH];

			while (readdir_r(dir, buf, &de) == 0 && de)
			{
				if ((!strcmp(de->d_name, ".")) || (!strcmp(de->d_name, "..")))
					continue;
				snprintf(fullpath, SR_MAX_PATH, "%s/%s", filename, de->d_name);
				sr_cls_file_delete(fullpath);
			}
		}
	}
}


void sr_cls_control_ut(void)
{
	sr_cls_file_add_rule("/home/hilik/Desktop/git/vsentry/", "ls", "*", 10, 1);
	sr_cls_file_create("/usr/lib/shotwell");
	return ;
}
