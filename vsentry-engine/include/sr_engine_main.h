#ifndef __ENGINE_MAIN_H
#define __ENGINE_MAIN_H

#include "sr_types.h"

SR_32 sr_engine_start(int argc, char *argv[]);
SR_32 sr_engine_write_conf(char *param, char *value);
SR_BOOL get_engine_state(void);
void set_engine_state(SR_BOOL is_on);
SR_32 sr_engine_get_db_lock(void);
SR_32 sr_engine_get_db_unlock(void);

#endif
