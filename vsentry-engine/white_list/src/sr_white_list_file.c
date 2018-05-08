#include "sr_types.h"
#include "sr_white_list.h"
#include "sr_white_list_file.h"
#include "engine_sal.h"
#include <string.h>
#include "sr_cls_file_control.h"
#include "sr_actions_common.h"
#include "sr_cls_rules_control.h"
#include "sysrepo_mng.h"

#define SR_START_RULE_NO 3072
#define SR_END_RULE_NO 4095

static SR_32 rule_id; 
static sysrepo_mng_handler_t sysrepo_handler;
static char *home_dir;

#define CHECK_DIR(dir_name) \
	if (!memcmp(file, dir_name, strlen(dir_name))) { \
		strcpy(file_dir, dir_name); \
		return file_dir; \
	}

static char *get_file_to_learn(char *file, char *file_dir)
{
	CHECK_DIR("/tmp")
	CHECK_DIR("/var/spool")
	if (home_dir)
		CHECK_DIR(home_dir)

	return file;
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

/* For each binary ther will be at maximum 3 rules. One for each premisiion. The file will be tuples, the rule number
	is staring from 3k - up to 4k !!! */ 

SR_32 sr_white_list_file_open(struct sr_ec_file_open_t *file_open_info)
{
	sr_white_list_item_t *white_list_item;
	char exec[SR_MAX_PATH_SIZE], *file_to_learn, file_dir[SR_MAX_PATH_SIZE];
	sr_white_list_file_t **iter;

	if (wr_white_list_get_mode() != SR_WL_MODE_LEARN)
		return SR_SUCCESS;

        if (sal_get_process_name(file_open_info->pid, exec, SR_MAX_PATH_SIZE) != SR_SUCCESS)
                strcpy(exec, "*");

	// The file to learn might be only a part of the path 
	file_to_learn = get_file_to_learn(file_open_info->file, file_dir);

	if (!(white_list_item = sr_white_list_hash_get(exec))) {
		if (sr_white_list_hash_insert(exec, &white_list_item) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=whilte list insert - failed",REASON);
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
				"%s=learn hash update: memory allocation failed",REASON);
			return SR_ERROR;
		}
		strncpy((*iter)->file, file_to_learn, SR_MAX_PATH_SIZE);
	}
	(*iter)->fileop |= file_open_info->fileop;

	return SR_SUCCESS;
}

void sr_white_list_file_print(sr_white_list_file_t *white_list_file)
{
	sr_white_list_file_t *iter;

	for (iter = white_list_file; iter; iter = iter->next)
		printf("  file:%s: fileop:%x \n", iter->file, iter->fileop);
	
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

static SR_32 file_apply_cb(void *hash_data, void *data)
{
	sr_white_list_item_t *wl_item = (sr_white_list_item_t *)hash_data;
	sr_white_list_file_t *iter;

	if (!hash_data)
		return SR_ERROR;

	for (iter = wl_item->white_list_file; iter; iter = iter->next) {
		printf("rule#%d file:%s: fileop:%x exec:%s \n", rule_id, iter->file, iter->fileop, wl_item->exec);
		if (rule_id > SR_END_RULE_NO) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=File learn rule exeeds max number of rules file:%s exec:%s",
					REASON, iter->file, wl_item->exec);
			continue;
		}
		if (sys_repo_mng_create_file_rule(&sysrepo_handler, rule_id, iter->file, wl_item->exec, "*", "allow_log", iter->fileop) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sys_repo_mng_create_file_rule  fiel rule id:%d ",
					REASON, rule_id);
		}
		rule_id++;
	}

	return SR_SUCCESS;
}

static SR_32 file_unapply_cb(void *hash_data, void *data)
{
	// TODO : delete rulues.

	return SR_SUCCESS;
}

SR_32 sr_white_list_file_apply(SR_BOOL is_apply)
{
	SR_32 rc;
	
	if (sysrepo_mng_session_start(&sysrepo_handler)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sysrepo_mng_session_start failed",REASON);
		return SR_ERROR;
	}

	rule_id = SR_START_RULE_NO;
	
	if ((rc = sr_white_list_hash_exec_for_all(is_apply ? file_apply_cb : file_unapply_cb)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_white_list_hash_exec_for_all failed",REASON);
		return SR_ERROR;
	}

	if (sys_repo_mng_commit(&sysrepo_handler) != SR_SUCCESS) { 
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sys_repo_mng_commit failed ", REASON);
	}

	sysrepo_mng_session_end(&sysrepo_handler);

	return SR_SUCCESS;
}
