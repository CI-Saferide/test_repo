#ifndef __DB_TOOLS_H_
#define  __DB_TOOLS_H_

#include <sr_types.h>
#include <action.h>

char *get_action_string(action_e action);
action_e get_action_code(char *action);
char *get_action_log_facility_string(log_facility_e log_facility);
log_facility_e get_action_log_facility_code(char *log_facility);

#endif
