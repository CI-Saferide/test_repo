#include "sr_types.h"
#include "sr_white_list.h"
#include "sr_white_list_file.h"
#include "engine_sal.h"
#include <string.h>
#include "sr_cls_file_control.h"
#include "sr_actions_common.h"
#include "sr_cls_rules_control.h"

#define SR_START_RULE_NO 3072

static SR_32 rule_id; 

/* For each binary ther will be at maximum 3 rules. One for each premisiion. The file will be tuples, the rule number
	is staring from 3k - up to 4k !!! */ 

SR_32 sr_white_list_file_open(struct sr_ec_file_open_t *file_open_info)
{
	sr_white_list_item_t *white_list_item;
	char exec[SR_MAX_PATH_SIZE];
	sr_white_list_file_t **iter;

	if (wr_white_list_get_mode() != SR_WL_MODE_LEARN)
		return SR_SUCCESS;

        if (sal_get_process_name(file_open_info->pid, exec, SR_MAX_PATH_SIZE) != SR_SUCCESS)
                strcpy(exec, "*");

	if (!(white_list_item = sr_white_list_hash_get(exec))) {
		if (sr_white_list_hash_insert(exec, &white_list_item) != SR_SUCCESS) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=whilte list insert - failed",REASON);
			return SR_ERROR;
		}
	}

	for (iter = &(white_list_item->white_list_file); 
		*iter && strcmp((*iter)->file, file_open_info->file); iter = &((*iter)->next));
	/* If no such file and fileop then insert */
	if (!*iter) { 
		SR_Zalloc(*iter, sr_white_list_file_t *, sizeof(sr_white_list_file_t));
		if (!*iter) {
			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=learn hash update: memory allocation failed",REASON);
			return SR_ERROR;
		}
		strncpy((*iter)->file, file_open_info->file, SR_MAX_PATH_SIZE);
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

static SR_32 file_protect_cb(void *hash_data, void *data)
{
	sr_white_list_item_t *wl_item = (sr_white_list_item_t *)hash_data;
	sr_white_list_file_t *iter;
	SR_U16 actions_bitmap = SR_CLS_ACTION_ALLOW | SR_CLS_ACTION_LOG;

	if (!hash_data)
		return SR_ERROR;

	for (iter = wl_item->white_list_file; iter; iter = iter->next) {
		printf("rule#%d file:%s: fileop:%x exec:%s \n", rule_id, iter->file, iter->fileop, wl_item->exec);
		sr_cls_file_add_rule(iter->file, wl_item->exec, "*", rule_id, (SR_U8)1);
		sr_cls_rule_add(SR_FILE_RULES, rule_id, actions_bitmap, iter->fileop, 0, 0, 0, 0, 0, 0, 0);
		rule_id++;

	}
	return SR_SUCCESS;
}

SR_32 sr_white_list_file_protect(void)
{
	SR_32 rc;
	
	rule_id = 0;
	
	if ((rc = sr_white_list_hash_exec_for_all(file_protect_cb)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=sr_white_list_hash_exec_for_all failed",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}
