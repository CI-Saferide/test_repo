#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>
#include "sal_linux.h"
#include "sr_cls_file.h"

extern int main_sock_fd;

//#include "sr_cls_file.h"
//#include "sr_hash.h"

// filename: path of file/dir to add rule to
// rulenum: index of rule to be added
// treetop: 1 for the first call, 0 for recursive calls further down.
int sr_cls_file_add_rule(char *filename, SR_U32 rulenum, SR_U8 treetop)
{
	char *sr_msg;
	struct stat buf;
	int retval;
	if(lstat(filename, &buf)) { // Error
		return SR_ERROR;
	}
	if (S_ISREG(buf.st_mode)) {
		if ((buf.st_nlink > 1) && (treetop)) {
			printf("Error: Cannot add classification rules for hard links\n");
			return SR_ERROR;
		}
		// sr_cls_inode_add_rule(buf.st_ino, rulenum)
		sr_msg = "Call sr_cls_inode_add_rule!";
		sal_sendmsg(sr_msg, strlen(sr_msg));
	}
	if (S_ISDIR(buf.st_mode))  {
		// first update the directory itself
		// sr_cls_inode_add_rule(buf.st_ino, rulenum)
		sr_msg = "Call sr_cls_inode_add_rule!";
		sal_sendmsg(sr_msg, strlen(sr_msg));
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
				retval = sr_cls_file_add_rule(fullpath, rulenum, 0);
			}
		}
	}
	if (S_ISLNK(buf.st_mode))  {
		// first update the link itself
		// sr_cls_inode_add_rule(buf.st_ino, rulenum)
		sr_msg = "Call sr_cls_inode_add_rule!";
		sal_sendmsg(sr_msg, strlen(sr_msg));
		//TODO: Do I need to update the destination file as well ???
		//Can use realpath() to resolve target filename.
		//I believe we should not modify the target file in this case.
	}
	return SR_SUCCESS;
}

// filename: path of file/dir to add rule to
// rulenum: index of rule to be added
// treetop: 1 for the first call, 0 for recursive calls further down.
int sr_cls_file_del_rule(char *filename, SR_U32 rulenum, SR_U8 treetop)
{
	char *sr_msg;
	struct stat buf;
	int retval;
	if(lstat(filename, &buf)) { // Error
		return SR_ERROR;
	}
	if (S_ISREG(buf.st_mode)) {
		if ((buf.st_nlink > 1) && (treetop)) {
			printf("Error: Cannot del classification rules for hard links\n");
			return SR_ERROR;
		}
		// sr_cls_inode_del_rule(buf.st_ino, rulenum)
		sr_msg = "Call sr_cls_inode_del_rule!";
		sal_sendmsg(sr_msg, strlen(sr_msg));
	}
	if (S_ISDIR(buf.st_mode))  {
		// first update the directory itself
		// sr_cls_inode_del_rule(buf.st_ino, rulenum)
		sr_msg = "Call sr_cls_inode_del_rule!";
		sal_sendmsg(sr_msg, strlen(sr_msg));
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
				retval = sr_cls_file_add_rule(fullpath, rulenum, 0);
			}
		}
	}
	if (S_ISLNK(buf.st_mode))  {
		// first update the link itself
		// sr_cls_inode_del_rule(buf.st_ino, rulenum)
		sr_msg = "Call sr_cls_inode_del_rule!";
		sal_sendmsg(sr_msg, strlen(sr_msg));
		//Can use realpath() to resolve target filename.
		//I believe we should not modify the target file in this case.
	}
	return SR_SUCCESS;
}

// This function should be invoked upon file creation. 
// It will need to check if parent directory has rules associated with it and inherit accordingly
int sr_cls_file_create(char *filename)
{ 
	char *sr_msg;
	struct stat buf,buf2;
	char parentdir[SR_MAX_PATH];
	struct sr_hash_ent_t *parent, *fileent;
	struct sr_cls_msg msg;

	int retval;
	if(lstat(filename, &buf)) { // Error
		return SR_ERROR;
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
		// sr_cls_inode_inherit(buf2.st_ino, buf.st_mode)
		sr_msg = "Call sr_cls_inode_inherit!";
		msg.msg_type = SR_CLS_INODE_INHERIT;
		msg.rulenum=456;
		msg.inode1=buf.st_mode;
		msg.inode2=buf.st_mode;
		//sal_sendmsg((char *)&msg, sizeof(struct sr_cls_msg));
		sal_sendmsg(sr_msg, strlen(sr_msg));
	}
	
	return;
}
// This function should be invoked upon file deletion. 
// It will need to check if there's an entry and remove it
void sr_cls_file_delete(char *filename)
{ 
	char *sr_msg;
	struct stat buf;
	struct sr_hash_ent_t *fileent;

	int retval;
	if(lstat(filename, &buf)) { // Error
		return;
	}
	if ((S_ISREG(buf.st_mode)) && (buf.st_nlink == 1)) {
		// sr_cls_inode_remove(buf.st_mode)
		sr_msg = "Call sr_cls_inode_remove!";
		sal_sendmsg(sr_msg, strlen(sr_msg));
	}
	if (S_ISDIR(buf.st_mode)) {
		// sr_cls_inode_remove(buf.st_mode)
		sr_msg = "Call sr_cls_inode_remove!";
		sal_sendmsg(sr_msg, strlen(sr_msg));
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
	sr_cls_file_add_rule("~/Desktop/git/vsentry/", 10, 1);
	sr_cls_file_create("/usr/lib/shotwell");
	return ;
}
