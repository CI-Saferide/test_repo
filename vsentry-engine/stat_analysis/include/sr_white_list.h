#ifndef __SR_WHITE_LIST_H_
#define  __SR_WHITE_LIST_H_

SR_32 sr_white_list_init(void);
void sr_white_list_uninit(void);
SR_32 sr_white_list_hash_insert(char *exec);
SR_32 sr_white_list_hash_exec_for_all(SR_32 (*cb)(void *hash_data, void *data));
SR_32 sr_white_list_hash_delete(char *exec);
SR_32 sr_white_list_delete_all(void);
void sr_white_list_hash_print(void);

#endif
