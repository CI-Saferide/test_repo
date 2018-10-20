#ifndef SR_WHITE_LIST_IP_H_
#define SR_WHITE_LIST_IP_H_
#include "sr_ec_common.h"

SR_32 sr_white_list_ip_init(void);
void sr_white_list_ip_uninit(void);
SR_32 sr_white_list_ip_new_connection( struct sr_ec_new_connection_wl_t *pNewConnection);
void sr_white_list_ip_print(void);
SR_32 sr_white_list_ip_delete_all(void);
SR_32 sr_white_list_ip_apply(SR_32 is_apply);
void white_list_ip_print_cb_register(void (*i_print_cb)(char *buf));
#endif
