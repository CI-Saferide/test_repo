#ifndef __IRDETO_STATIC_WL_RULES_H
#define  __IRDETO_STATIC_WL_RULES_H

typedef struct {
	SR_U32  rule_id;
	char	filename[FILE_NAME_SIZE];
	char	permission[4];
	char	user[USER_NAME_SIZE];
	char	program[PROG_NAME_SIZE]; 
} static_file_rule_t;

static static_file_rule_t irdeto_static_wl [] = {
	/* Rule id,  File path, permission, user,  program}, */
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/cmb_drvc"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/cmb_main"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/dpa"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/init"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/isrt"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/ivs"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/qa_client"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/qa_serfver"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/sswa_agent"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/telemetry"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/ugkp"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/unionfs"},
	{SR_FILE_WL_START_STATIC_RULE_NO, "/customer_persistent/YAS", "rw", "*", "/usr/bin/vproxy"},
	{SR_FILE_WL_START_STATIC_RULE_NO + 1, "/oldroot/pivot/underlay", "rwx", "*", "/usr/bin/unionfs"},
	{0, ""},  // Must be the last entry.
};

#endif

