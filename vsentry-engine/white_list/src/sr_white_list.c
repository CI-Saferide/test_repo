#include <sr_gen_hash.h>
#include "sr_white_list.h"
#include "sal_mem.h"

#define HASH_SIZE 500

static sr_wl_mode_t wl_mode;

static struct sr_gen_hash *white_list_hash;

static SR_32 white_list_comp(void *data_in_hash, void *comp_val)
{
        sr_white_list_item_t *white_list_item = (sr_white_list_item_t *)data_in_hash;
	char *comp_exe = (char *)comp_val;

        if (!data_in_hash)
                return -1;

	return strncmp(white_list_item->exec, comp_exe, SR_MAX_PATH_SIZE);
}

static void white_list_print(void *data_in_hash)
{
	sr_white_list_item_t *white_list_item = (sr_white_list_item_t *)data_in_hash;

	printf("exec:%s: \n", white_list_item->exec);

	sr_white_list_file_print(white_list_item->white_list_file);
	sr_white_list_canbus_print(white_list_item->white_list_can);
}

static SR_U32 white_list_create_key(void *data)
{
	sr_white_list_item_t *white_list_item = (sr_white_list_item_t *)data;
	SR_U32 num = 0, len, i;
	// TODO : Ctreate a better hash key creation function.
	
	len = strlen(white_list_item->exec);
	for (i = 0; i < len; i++)
		num += white_list_item->exec[i]; 

	return num;
}

static void white_list_free(void *data_in_hash)
{
	sr_white_list_item_t *white_list_item = (sr_white_list_item_t *)data_in_hash;

	if (!white_list_item)
		return;

	sr_white_list_file_cleanup(white_list_item->white_list_file);
	sr_white_list_canbus_cleanup(white_list_item->white_list_can);

	SR_Free(white_list_item);
}

SR_32 sr_white_list_init(void)
{
	hash_ops_t hash_ops = {};

	if (sr_white_list_file_init() != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_file_init",REASON);
		return SR_ERROR;
	}

	hash_ops.create_key = white_list_create_key;
	hash_ops.comp = white_list_comp;
	hash_ops.print = white_list_print;
	hash_ops.free = white_list_free;
	if (!(white_list_hash = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
			"%s=file_hash_init: sr_gen_hash_new failed",REASON);
		return SR_ERROR;
	}
	wl_mode = SR_WL_MODE_OFF;

	return SR_SUCCESS;
}

SR_32 sr_white_list_set_mode(sr_wl_mode_t new_wl_mode)
{
	SR_32 rc;

	if (wl_mode == new_wl_mode)
		return SR_SUCCESS;
	switch (wl_mode) {
		case SR_WL_MODE_LEARN:
			break;
		case SR_WL_MODE_APPLY:
			// Remove the rules
			if ((rc = sr_white_list_file_apply(SR_FALSE)) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_file_apply failed",REASON);
                		return SR_ERROR;
			}
			if ((rc = sr_white_list_canbus_apply(SR_FALSE)) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_canbus_apply failed",REASON);
                		return SR_ERROR;
			}
			break;
		case SR_WL_MODE_OFF:
			break;
		default:
			return SR_ERROR;
	}
	switch (new_wl_mode) { 
		case SR_WL_MODE_LEARN:
			sr_white_list_delete_all();
			break;
		case SR_WL_MODE_APPLY:
			wl_mode = SR_WL_MODE_APPLY;
			if ((rc = sr_white_list_file_apply(SR_TRUE)) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_file_apply failed",REASON);
                		return SR_ERROR;
			}
			if ((rc = sr_white_list_canbus_apply(SR_TRUE)) != SR_SUCCESS) {
               			CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=sr_white_list_canbus_apply failed",REASON);
                		return SR_ERROR;
			}
			break;
		case SR_WL_MODE_OFF:
			break;
		default:
			return SR_ERROR;
	}
	wl_mode = new_wl_mode;

	return SR_SUCCESS;
}

sr_wl_mode_t sr_white_list_get_mode(void)
{
	return wl_mode;
}

SR_32 sr_white_list_hash_insert(char *exec, sr_white_list_item_t **new_item)
{
	sr_white_list_item_t *white_list_item;
	SR_32 rc;

	if (sr_gen_hash_get(white_list_hash, exec)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                "%s=whilte list insert - item failed",REASON);
		return SR_ERROR;
        }
		
	SR_Zalloc(white_list_item, sr_white_list_item_t *, sizeof(sr_white_list_item_t));
	if (!white_list_item) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=learn hash update: memory allocation failed",REASON);
		return SR_ERROR;
	}
	if (new_item)
		*new_item = white_list_item;
		
	strncpy(white_list_item->exec, exec, SR_MAX_PATH_SIZE);
	if ((rc = sr_gen_hash_insert(white_list_hash, (void *)exec, white_list_item)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                               "%s=%s: sr_gen_hash_insert failed",REASON, __FUNCTION__);
		return SR_ERROR;
	}       

	return SR_SUCCESS;
}

sr_white_list_item_t *sr_white_list_hash_get(char *exec)
{
	sr_white_list_item_t *item;

	if (!(item = sr_gen_hash_get(white_list_hash, exec)))
		return NULL;

	return item;
}

void sr_white_list_uninit(void)
{
	switch (wl_mode) {
		case SR_WL_MODE_LEARN:
			break;
		case SR_WL_MODE_APPLY:
			// Remove the rules
			if (sr_white_list_file_apply(SR_FALSE) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sr_white_list_file_apply failed",REASON);
			}
			if (sr_white_list_canbus_apply(SR_FALSE) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=sr_white_list_canbus_apply failed",REASON);
			}
			break;
		case SR_WL_MODE_OFF:
			break;
		default:
			break;
	}
        sr_gen_hash_destroy(white_list_hash);
	sr_white_list_file_uninit();
}

SR_32 sr_white_list_hash_exec_for_all(SR_32 (*cb)(void *hash_data, void *data))
{
	return sr_gen_hash_exec_for_each(white_list_hash, cb, NULL);
}

SR_32 sr_white_list_hash_delete(char *exec)
{
	SR_32 rc;
	
	if ((rc = sr_gen_hash_delete(white_list_hash, exec) != SR_SUCCESS)) {
		return rc;
	}

	return rc;
}

SR_32 sr_white_list_delete_all(void)
{
	return sr_gen_hash_delete_all(white_list_hash);
}

void sr_white_list_hash_print(void)
{
	sr_gen_hash_print(white_list_hash);
}
