#ifndef __SAL_CLI_INTERFACE_H__
#define __SAL_CLI_INTERFACE_H__

#include "sr_types.h"

#define SR_CLI_INTERFACE_FILE "/tmp/cli_interface.socket"

SR_32 sal_cli_interface_init(void);
void sal_cli_interface_uninit(void);

#endif
