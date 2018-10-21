#ifndef _SR_ENGINE_CLI_H
#define _SR_ENGINE_CLI_H

#define SR_CLI_INTERFACE_FILE "/tmp/cli_interface.socket"
#define SR_CLI_END_OF_ENTITY '#'
#define SR_CLI_END_OF_TRANSACTION '&'

void sr_engine_cli_load(SR_32 fd);
void sr_engine_cli_print(SR_32 fd);
SR_32 sr_engine_cli_commit(SR_32 fd);

#endif
