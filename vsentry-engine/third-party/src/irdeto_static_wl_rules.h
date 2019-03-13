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
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/cmb_drvc"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/cmb_main"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/dpa"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/init"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/isrt"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/ivs"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/qa_client"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/qa_serfver"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/sswa_agent"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/telemetry"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/ugkp"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/unionfs"},
	{0, "/customer_persistent/YAS", "rw", "*", "/usr/bin/vproxy"},
	{1, "/oldroot/pivot/underlay", "rwx", "*", "/usr/bin/unionfs"},
	{0, ""},  // Must be the last entry.
};

#endif

