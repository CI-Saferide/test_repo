#ifndef __SR_WHITE_LIST_H_
#define  __SR_WHITE_LIST_H_

#include "sr_sal_common.h"
#include "sr_ec_common.h"
#include "sr_msg_dispatch.h"
#include "sr_msg.h"
#include "sr_white_list_file.h"
#include "sr_white_list_can.h"
#include "sr_white_list_ip.h"

#define WHITE_LIST_ACTION "allow_wl"

typedef enum {
        SR_WL_MODE_LEARN,
        SR_WL_MODE_APPLY,
        SR_WL_MODE_OFF,
} sr_wl_mode_t;

typedef struct white_list_item  {
	char exec[SR_MAX_PATH_SIZE];
	sr_white_list_file_t *white_list_file;
	sr_wl_can_item_t *white_list_can;
} sr_white_list_item_t;

SR_32 sr_white_list_init(void);
void sr_white_list_uninit(void);
SR_32 sr_white_list_hash_insert(char *exec, sr_white_list_item_t **new_item);
sr_white_list_item_t *sr_white_list_hash_get(char *exec);
SR_32 sr_white_list_hash_exec_for_all(SR_32 (*cb)(void *hash_data, void *data));
SR_32 sr_white_list_hash_delete(char *exec);
SR_32 sr_white_list_delete_all(void);
void sr_white_list_hash_print(void);
SR_32 sr_white_list_set_mode(sr_wl_mode_t new_wl_mode);
sr_wl_mode_t sr_white_list_get_mode(void);

#endif
