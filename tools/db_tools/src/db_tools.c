#include <db_tools.h>
#include "sr_msg.h"
#include "sentry.h"
#include "action.h"
#include "ip_rule.h"
#include "file_rule.h"
#include "can_rule.h"
#include "sr_canbus_common.h"
#include <string.h>
#include <ctype.h>

char *get_rule_string(rule_type_t rule_type)
{
        static char rule_string[MAX_RULE_TYPE];

        switch (rule_type) {
          case RULE_TYPE_CAN:
                strcpy(rule_string, "CAN");
                break;
          case RULE_TYPE_IP:
                strcpy(rule_string, "IP");
                break;
          case RULE_TYPE_FILE:
                strcpy(rule_string, "File");
                break;
          default:
                strcpy(rule_string, "invalid");
                break;
        }

        return rule_string;
}

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

char *get_dir_desc(SR_8 dir)
{
	static char res[100];

	switch (dir) {
		case SENTRY_DIR_IN:
			strcpy(res, "in");	
			break;
		case SENTRY_DIR_OUT:
			strcpy(res, "out");	
			break;
		case SENTRY_DIR_BOTH:
			strcpy(res, "both");	
			break;
		default:
			strcpy(res, "invalid");	
			break;
	};

	return res;
} 

SR_8 get_dir_id(char *dir)
{
	if (!strcmp(dir, "in"))
		return SENTRY_DIR_IN;
	if (!strcmp(dir, "out"))
		return SENTRY_DIR_OUT;
	if (!strcmp(dir, "both"))
		return SENTRY_DIR_BOTH;
        return -1;
}

char *get_ip_proto_name(SR_U8 ip_proto)
{
	static char proto_name[16];

	switch (ip_proto) {
		case 6:
			strcpy(proto_name, "tcp");
			break;
		case 17:
			strcpy(proto_name, "udp");
			break;
		case 0:
			strcpy(proto_name, "any");
			break;
		default:
			strcpy(proto_name, "invalid");
			break;
	}

	return proto_name;
}

SR_8 get_ip_proto_code(char *ip_proto)
{
	if (!strcmp(ip_proto, "tcp"))
		return 6;
	if (!strcmp(ip_proto, "udp"))
		return 17;
	if (!strcmp(ip_proto, "any"))
		return 0;
	return -1;
}

SR_U8 can_dir_convert(SR_U8 dir)
{
	switch (dir) {
		case SR_CAN_IN:
			return SENTRY_DIR_IN;
		case SR_CAN_OUT:
			return SENTRY_DIR_OUT;
		case SR_CAN_BOTH:
			return SENTRY_DIR_BOTH;
		default:
			return 99;
        }
}

char *prem_db_to_cli(char *prem_str)
{
	static char cli_perm[4];
	SR_U8 perm = atoi(prem_str + 2);

	cli_perm[0] = 0;
	if (perm & FILE_PERM_R)
		strcat(cli_perm, "r");
	if (perm & FILE_PERM_W)
		strcat(cli_perm, "w");
	if (perm & FILE_PERM_X)
		strcat(cli_perm, "x");

	return cli_perm;
}

char *perm_cli_to_db(char *perm_str)
{
	SR_U8 perm = 0;
	static char db_perm[4];

	if (strstr(perm_str, "r"))
		perm |= FILE_PERM_R;
	if (strstr(perm_str, "w"))
		perm |= FILE_PERM_W;
	if (strstr(perm_str, "x"))
		perm |= FILE_PERM_X;

	sprintf(db_perm, "77%d", perm);

	return db_perm;
}

SR_BOOL is_valid_ip(char *ip_addr)
{
	char buf[100] = {}, num_of_dots = 0;
	SR_U32 ind = 0;

	for (; *ip_addr; ip_addr++) { 
		if (*ip_addr) {
			if (*ip_addr == '.') {
				num_of_dots++;
				if (num_of_dots > 3)
					return SR_FALSE;
				if (atoi(buf) > 255)
					return SR_FALSE;
				buf[0] = 0;
				ind = 0;
			} else if (isdigit(*ip_addr)) {
				if (ind > 2)
					return SR_FALSE;
				buf[ind++] = *ip_addr;
			 } else
				return SR_FALSE;
		}
	}

	if (num_of_dots < 3)
		return SR_FALSE;
	return (atoi(buf) <= 255);
}
