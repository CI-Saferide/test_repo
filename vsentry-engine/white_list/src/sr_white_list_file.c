#include "sr_types.h"
#include "sr_white_list.h"
#include "sr_white_list_file.h"
#include "engine_sal.h"
#include <string.h>
#include "sr_cls.h"
#include "sr_cls_file_control.h"
#include "sr_actions_common.h"
#include "sr_cls_rules_control.h"
#include "sysrepo_mng.h"
#include "sr_config_parse.h"
#include "sr_engine_main.h"
#include "sr_control.h"
#include "sr_cls_wl_common.h"
#include "sr_engine_utils.h"

static SR_32 rule_id; 
static sysrepo_mng_handler_t sysrepo_handler;
static char *home_dir;

typedef struct wl_learn_file_item {
        char file[SR_MAX_PATH_SIZE];
        struct wl_learn_file_item *next;
} wl_learn_file_item_t;

#define CHECK_DIR(dir_name) \
	if (!memcmp(new_file, dir_name, strlen(dir_name))) { \
		strcpy(new_file, dir_name); \
		return new_file; \
	}

static char *get_file_to_learn(char *file, char *new_file)
{
	char *p, *help;

	strcpy(new_file, file);

	CHECK_DIR("/tmp")
	CHECK_DIR("/var/spool")
	CHECK_DIR("/var/cache")
	CHECK_DIR("/var/log")
	CHECK_DIR("/usr/share/dbus-1")
	if (home_dir)
		CHECK_DIR(home_dir)

    // If file is /proc/pid learn the whole /proc
	if (!memcmp(file, "/proc/", 5)) {
		help = strdup(file);
		p = strtok(help, "/");
		p = strtok(NULL, "/"); // The number
		if (p && sal_is_string_numeric(p))
			strcpy(new_file, "/proc");
		free(help);
	}

	return new_file;
}

SR_32 sr_white_list_file_init(void)
{
	char *home = sal_get_home_user();
	
	if (home)
		home_dir = strdup(home);

	return SR_SUCCESS;
}

void sr_white_list_file_uninit(void)
{
	if (home_dir)
		free(home_dir);
}

/* For each binary there will be at maximum 3 rules. One for each premision. The file will be tuples, the rule number
	is staring from 3k - up to 4k !!! */ 

SR_32 sr_white_list_file_wl(struct sr_ec_file_wl_t *file_wl_info)
{
	sr_white_list_item_t *white_list_item;
	char exec[SR_MAX_PATH_SIZE], *file_to_learn, new_file[SR_MAX_PATH_SIZE];
	sr_white_list_file_t **iter;

	if (sr_white_list_get_mode() != SR_WL_MODE_LEARN)
		return SR_SUCCESS;

	if (!sal_is_valid_file_name(file_wl_info->file)) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=invalid file :%s ",REASON, file_wl_info->file);
			printf("=====Invalid file name :%s \n", file_wl_info->file);
			return SR_ERROR;
	}

	switch (file_wl_info->wl_type) {
	case SR_EC_WL_FILE_OPEN:
		if (sal_get_process_name(file_wl_info->pid, exec, SR_MAX_PATH_SIZE) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to learn program name for white list file, pid:%d file :%s",REASON, file_wl_info->pid, file_wl_info->file);
			return SR_ERROR;
		}
		// The file to learn might be changed.
		file_to_learn = get_file_to_learn(file_wl_info->file, new_file);
		break;
	case SR_EC_WL_FILE_EXE:
		/* In file execute event it is not possible to learn pid. This pid is the pid of the executed file.*/
		strcpy(new_file, file_wl_info->file);
		strcpy(exec, "*");
		break;
	default:
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
							"%s=Invalid wl type :%d file :%s",REASON, file_wl_info->wl_type, file_wl_info->file);
		return SR_ERROR;
	}

	if (!(white_list_item = sr_white_list_hash_get(exec))) {
		if (sr_white_list_hash_insert(exec, &white_list_item) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=file white list insert failed, pid:%d file :%s",REASON, file_wl_info->pid, file_wl_info->file);
			return SR_ERROR;
		}
	}

	for (iter = &(white_list_item->white_list_file); 
		*iter && strcmp((*iter)->file, file_to_learn); iter = &((*iter)->next));
	/* If no such file and fileop then insert */
	if (!*iter) { 
		SR_Zalloc(*iter, sr_white_list_file_t *, sizeof(sr_white_list_file_t));
		if (!*iter) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to allocate memory for white list file, pid:%d file :%s",REASON, file_wl_info->pid, file_wl_info->file);
			return SR_ERROR;
		}
		strncpy((*iter)->file, file_to_learn, SR_MAX_PATH_SIZE);
	}
	(*iter)->fileop |= file_wl_info->fileop;

	return SR_SUCCESS;
}

void sr_white_list_file_print(sr_white_list_file_t *white_list_file)
{
	sr_white_list_file_t *iter;
	char permissions[4];

	for (iter = white_list_file; iter; iter = iter->next) {
		sr_get_file_perm_from_bits(iter->fileop, permissions);
		CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
                	        "%s=file leaned : file:%s file op:%x ", MESSAGE,  iter->file, iter->fileop);
		printf("file:%s: fileop:%x \n", iter->file, iter->fileop);
	}
}

void sr_white_list_file_cleanup(sr_white_list_file_t *white_list_file)
{
	sr_white_list_file_t *iter, *help;

	for (iter = white_list_file; iter;) {
		help = iter;
		iter = iter->next;
		SR_Free(help);
	}
}

static wl_learn_file_item_t *learn_files_list;

static SR_32 wl_file_count_cb(void *hash_data, void *data)
{
	sr_white_list_item_t *wl_item = (sr_white_list_item_t *)hash_data;
	sr_white_list_file_t *iter;
	wl_learn_file_item_t *learn_file_iter, *new_item;

	if (!hash_data)
		return SR_ERROR;

	for (iter = wl_item->white_list_file; iter; iter = iter->next) {
		for (learn_file_iter = learn_files_list; learn_file_iter && strcmp(iter->file, learn_file_iter->file); learn_file_iter = learn_file_iter->next);
		if (learn_file_iter) // If file exists
			continue;  
		SR_Zalloc(new_item, wl_learn_file_item_t *, sizeof(wl_learn_file_item_t));
		if (!new_item) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to allocate memory for white list file update",REASON);
			return SR_ERROR;
		}
		new_item->next = learn_files_list;
		strcpy(new_item->file, iter->file);
		learn_files_list = new_item;
	}

	return SR_SUCCESS;
}

static void count_files(char *filename, SR_U32 *count)
{
	struct stat buf = {};
	DIR * dir = NULL;
	struct dirent * dir_buf = NULL, *de;
	long name_max;

	if (lstat(filename, &buf))
		return;

	(*count)++;

	if (!S_ISDIR(buf.st_mode))
		return;

	if ((dir = opendir(filename))
		&& (name_max = pathconf(filename, _PC_NAME_MAX)) > 0
		&& (dir_buf = (struct dirent *)malloc(
		offsetof(struct dirent, d_name) + name_max + 1))) {
			char fullpath[SR_MAX_PATH];

			while (readdir_r(dir, dir_buf, &de) == 0 && de) {
				if ((!strcmp(de->d_name, ".")) || (!strcmp(de->d_name, "..")))
					continue;
				snprintf(fullpath, SR_MAX_PATH, "%s/%s", filename, de->d_name);
				count_files(fullpath, count);
			}
			if (dir_buf)
				free(dir_buf);
	}
	if (dir)
		closedir(dir);
}

static SR_32 sr_white_list_count_files(SR_U32 *counter)
{
	wl_learn_file_item_t *iter, *help;
	
	*counter = 0;

	if (sr_white_list_hash_exec_for_all(wl_file_count_cb) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to count white list files",REASON);
		return SR_ERROR;
	}
	
	for (iter = learn_files_list; iter; iter = iter->next) {
		count_files(iter->file, counter);
	}

	// Delete the list
	for (iter = learn_files_list; iter;) {
		help = iter;
		iter = iter->next;
		SR_Free(help);
	}
	learn_files_list = NULL;

	return SR_SUCCESS;
}

static SR_32 sr_white_list_calculate_mem_optimization(cls_file_mem_optimization_t *mem_opt)
{
	SR_U32 files_counter;
	struct config_params_t *config_params;
	SR_U64 free_memory;

	config_params = sr_config_get_param();
	if (sal_get_memory(NULL, &free_memory) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to get free memory, memory optimization cannot continue", REASON);
		return SR_ERROR;
	}
	if (sr_white_list_count_files(&files_counter) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to count white list total files", REASON);
		return SR_ERROR;
	}

	*mem_opt = (files_counter * CLS_UNIT_SIZE > free_memory * config_params->file_cls_mem_optimize / 100) ? CLS_FILE_MEM_OPT_ONLY_DIR : CLS_FILE_MEM_OPT_ALL_FILES ;
#ifdef DEBUG
	printf("DEBUG CALCULATE MEM OPT Counter :%d  mem_port:%d mem_opt:%d !!!\n", files_counter, config_params->file_cls_mem_optimize, *mem_opt);
#endif

	return SR_SUCCESS;
}

#ifdef DEBUG
FILE *f_app;
#endif
static void write_file_rule(char *file_name, char *exec, SR_U8 file_op, SR_32 *rule_id, SR_32 *op_rule, SR_32 *op_tuple)
{
	if (*op_rule == -1) 
		*op_rule = (*rule_id)++;
#ifdef DEBUG
	fprintf(f_app, "rule:%d tuple:%d exec:%s file:%s perm:%d \n", *op_rule, *op_tuple, exec, file_name, file_op);
#endif
	//printf("rule:%d tuple:%d exec:%s file:%s perm:%d \n", *op_rule, *op_tuple, exec, file_name, file_op);
	if (sys_repo_mng_create_file_rule(&sysrepo_handler, *op_rule, *op_tuple, file_name, exec, "*", WHITE_LIST_ACTION, file_op) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=fail to create file rule in persistent db. rule id:%d",
				REASON, *rule_id);
	}
	(*op_tuple)++;
}

static SR_32 file_apply_cb(void *hash_data, void *data)
{
	sr_white_list_item_t *wl_item = (sr_white_list_item_t *)hash_data;
	sr_white_list_file_t *iter;
	SR_32 r_rule = -1, w_rule = -1, x_rule = -1;
	SR_32 r_tuple = 0, w_tuple = 0, x_tuple = 0;

	if (!hash_data)
		return SR_ERROR;

#ifdef DEBUG
	fprintf(f_app, "------------- Exec:%s \n", wl_item->exec);
#endif
	//printf("-XXXXXXXXXXXXXxxx ------------ Exec:%s \n", wl_item->exec);
	for (iter = wl_item->white_list_file; iter; iter = iter->next) {
		if (rule_id > SR_FILE_WL_END_RULE_NO) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=white list file learn rule exeeds list boundary. file:%s exec:%s",
					REASON, iter->file, wl_item->exec);
			continue; /* we do not break since we want to have log per any rule that we cannot accomodate in the persistent storage */
		}

		if (iter->fileop & SR_FILEOPS_READ) {
			write_file_rule(iter->file, wl_item->exec, SR_FILEOPS_READ, &rule_id, &r_rule, &r_tuple);
		}
		if (iter->fileop & SR_FILEOPS_WRITE) {
			write_file_rule(iter->file, wl_item->exec, SR_FILEOPS_WRITE, &rule_id, &w_rule, &w_tuple);
		}
		if (iter->fileop & SR_FILEOPS_EXEC) {
			write_file_rule(iter->file, wl_item->exec, SR_FILEOPS_EXEC, &rule_id, &x_rule, &x_tuple);
		}
	}

	return SR_SUCCESS;
}

static SR_32 wl_file_delete_cb(void *hash_data, void *data)
{
	// TODO : delete rulues.

	return SR_SUCCESS;
}

SR_32 sr_white_list_file_apply(SR_BOOL is_apply)
{
	SR_32 rc;
	cls_file_mem_optimization_t mem_opt;
	char str_mem_opt[10];

	if (sr_white_list_calculate_mem_optimization(&mem_opt)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=file whitelist: fail to calculate memory optimization",REASON);
		return SR_ERROR;
	}
	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
			"%s=memory optimization calculated :%s", MESSAGE, mem_opt == CLS_FILE_MEM_OPT_ALL_FILES ? "all-files" : "directories");
	sr_cls_file_control_set_mem_opt(mem_opt);
	snprintf(str_mem_opt, sizeof(str_mem_opt), "%d", mem_opt);
	if (sr_engine_write_conf("FILE_CLS_MEM_OPTIMIZE", str_mem_opt) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to write memory optimization result to configuration file", REASON);
		return SR_ERROR;
	}

	// Send the memory optimization value to the Kernel
	if (sr_control_set_mem_opt(mem_opt) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=failed to set memory optimization flag to Kernel", REASON);
		return SR_ERROR;
	}

#ifdef DEBUG
	f_app = fopen("/tmp/app.txt", "w");
#endif

	if (sysrepo_mng_session_start(&sysrepo_handler)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=wl file:fail to init persistent db",REASON);
		return SR_ERROR;
	}

	rule_id = SR_FILE_WL_START_RULE_NO;
	
	if ((rc = sr_white_list_hash_exec_for_all(is_apply ? file_apply_cb : wl_file_delete_cb)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=file wl hash exec failed",REASON);
		return SR_ERROR;
	}

	if (sys_repo_mng_commit(&sysrepo_handler) != SR_SUCCESS) { 
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=failed to commit wl file rules from persistent db", REASON);
	}

	sysrepo_mng_session_end(&sysrepo_handler);

#ifdef DEBUG
	fclose(f_app);
#endif

	return SR_SUCCESS;
}
