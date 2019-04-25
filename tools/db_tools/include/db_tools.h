#ifndef __DB_TOOLS_H_
#define  __DB_TOOLS_H_

#include <sr_types.h>
#include <action.h>
    
typedef enum {
        RULE_TYPE_CAN,
        RULE_TYPE_FILE,
        RULE_TYPE_IP,
		RULE_TYPE_MAX = RULE_TYPE_IP,
		RULE_TYPE_TOTAL = (RULE_TYPE_MAX + 1),
} rule_type_t;

typedef enum {
        LOG_TARGET_NONE,
        LOG_TARGET_SYSLOG,
        LOG_TARGET_FILE,
		LOG_TARGET_MAX = LOG_TARGET_FILE,
		LOG_TARGET_TOTAL = (LOG_TARGET_MAX + 1),
} sr_log_target_t;

#define MAX_RULE_TYPE 20

char *get_rule_string(rule_type_t rule_type);
char *get_action_string(action_e action);
action_e get_action_code(char *action);
char *get_action_log_facility_string(log_facility_e log_facility);
log_facility_e get_action_log_facility_code(char *log_facility);
char *get_dir_desc(SR_8 dir);
SR_8 get_dir_id(char *dir);
char *get_ip_proto_name(SR_U8 ip_proto);
SR_U8 can_dir_convert(SR_U8 dir);
SR_8 get_ip_proto_code(char *ip_proto);
char *prem_db_to_cli(char *prem_str);
char *perm_cli_to_db(char *perm_str);
SR_BOOL is_valid_ip(char *ip_addr);
SR_32 get_log_facility_enum(char *log);

#endif
