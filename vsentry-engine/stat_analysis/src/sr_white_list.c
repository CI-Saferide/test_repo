#include <sr_gen_hash.h>
#include "sr_white_list.h"

#define HASH_SIZE 500

static struct sr_gen_hash *white_list_hash;

typedef struct white_list_item  {
	char exec[SR_MAX_PATH_SIZE];
} white_list_item_t;

static SR_32 white_list_comp(void *data_in_hash, void *comp_val)
{
        white_list_item_t *white_list_item = (white_list_item_t *)data_in_hash;
	char *comp_exe = (char *)comp_val;

        if (!data_in_hash)
                return -1;

	return strncmp(white_list_item->exec, comp_exe, SR_MAX_PATH_SIZE);
}

static void white_list_print(void *data_in_hash)
{
	white_list_item_t *white_list_item = (white_list_item_t *)data_in_hash;

	printf("exec:%s: \n", white_list_item->exec);
}

static SR_U32 white_list_create_key(void *data)
{
	white_list_item_t *white_list_item = (white_list_item_t *)data;
	SR_U32 num = 0, len, i;
	// TODO : Ctreate a better hash key creation function.
	
	len = strlen(white_list_item->exec);
	for (i = 0; i < len; i++)
		num += white_list_item->exec[i]; 

	return num;
}

static void white_list_free(void *data_in_hash)
{
	SR_Free(data_in_hash);
}

SR_32 sr_white_list_init(void)
{
        hash_ops_t hash_ops = {};

        hash_ops.create_key = white_list_create_key;
        hash_ops.comp = white_list_comp;
        hash_ops.print = white_list_print;
        hash_ops.free = white_list_free;
        if (!(white_list_hash = sr_gen_hash_new(HASH_SIZE, hash_ops, 0))) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=file_hash_init: sr_gen_hash_new failed",REASON);
                return SR_ERROR;
        }

        return SR_SUCCESS;
}

SR_32 sr_white_list_hash_insert(char *exec)
{
	white_list_item_t *white_list_item;
	SR_32 rc;

	if (sr_gen_hash_get(white_list_hash, exec)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                "%s=whilte list insert - item existsfailed",REASON);
		return SR_ERROR;
        }
		
	SR_Zalloc(white_list_item, white_list_item_t *, sizeof(white_list_item_t));
	if (!white_list_item) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
				"%s=learn hash update: memory allocation failed",REASON);
		return SR_ERROR;
	}
	strncpy(white_list_item->exec, exec, SR_MAX_PATH_SIZE);
	if ((rc = sr_gen_hash_insert(white_list_hash, (void *)exec, white_list_item)) != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                               "%s=%s: sr_gen_hash_insert failed",REASON, __FUNCTION__);
		return SR_ERROR;
	}       

	return SR_SUCCESS;
}

void sr_white_list_uninit(void)
{
        sr_gen_hash_destroy(white_list_hash);
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

