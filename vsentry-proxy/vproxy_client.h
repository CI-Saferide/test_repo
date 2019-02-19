#ifndef __VPROXY_CLIENT_H__
#define __VPROXY_CLIENT_H__

#include "message.h"

void 	vproxy_client_reset_counters(void);
int 	vproxy_client_send_new_policy_msg(int fd);
_xc_preserve_interface \
int 	vproxy_client_handle_recv_msg(int fd, struct raw_message *raw_msg);
#endif /* __VPROXY_CLIENT_H__ */
