#ifndef __WHITE_LIST_FILE_H__
#define __WHITE_LIST_FILE_H__

#include "sr_ec_common.h"

typedef struct white_list_file {
	char file[SR_MAX_PATH_SIZE];
	SR_U8 fileop;
	struct white_list_file *next;
} sr_white_list_file_t;

SR_32 sr_white_list_file_wl(struct sr_ec_file_wl_t *file_wl_info);
void sr_white_list_file_print(sr_white_list_file_t *while_list_file);
void sr_white_list_file_cleanup(sr_white_list_file_t *white_list_file);
SR_32 sr_white_list_file_apply(void);
SR_32 sr_white_list_file_init(void);
void sr_white_list_file_uninit(void);

#endif
