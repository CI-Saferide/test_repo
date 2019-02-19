#ifndef __IRDETO_UNIX_INTERFACE_H__
#define __IRDETO_UNIX_INTERFACE_H__

#include "sr_types.h"

#define IRDETO_UNIX_INTERFACE_FILE "/tmp/irdeto_interface.socket"

SR_32 irdeto_unix_interface_init(void);
void irdeto_unix_interface_uninit(void);

#endif /* __IRDETO_UNIX_INTERFACE_H__ */
