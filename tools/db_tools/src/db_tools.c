#include <db_tools.h>
#include "sr_msg.h"
#include "sentry.h"
#include "action.h"
#include "ip_rule.h"
#include "file_rule.h"
#include "can_rule.h"
#include <string.h>
#include <ctype.h>

char *get_action_string(action_e action)
{
        static char action_string[ACTION_STR_SIZE];

        switch (action) {
          case ACTION_NONE:
                strcpy(action_string, "none");
                break;
          case ACTION_DROP:
                strcpy(action_string, "drop");
                break;
          case ACTION_ALLOW:
                strcpy(action_string, "allow");
                break;
          default:
                strcpy(action_string, "invalid");
                break;
        }

        return action_string;
}

action_e get_action_code(char *action)
{
        if (!strcmp(action, "none"))
                return ACTION_NONE;
        if (!strcmp(action, "drop"))
                return ACTION_DROP;
        if (!strcmp(action, "allow"))
                return ACTION_ALLOW;
        return ACTION_INVALID;
}

char *get_action_log_facility_string(log_facility_e log_facility)
{
        static char log_facility_string[LOG_FACILITY_SIZE];

        switch (log_facility) {
                case LOG_NONE:
                        strcpy(log_facility_string, "none");
                        break;
                case LOG_TO_SYSLOG:
                        strcpy(log_facility_string, "syslog");
                        break;
                case LOG_TO_FILE:
                        strcpy(log_facility_string, "file");
                        break;
                default:
                        strcpy(log_facility_string, "invalid");
                        break;
        }

        return log_facility_string;
}

log_facility_e get_action_log_facility_code(char *log_facility)
{
        if (!strcmp(log_facility, "none"))
                return LOG_NONE;
        if (!strcmp(log_facility, "syslog"))
                return LOG_TO_SYSLOG;
        if (!strcmp(log_facility, "file"))
                return LOG_TO_FILE;
        return LOG_INVALID;
}

