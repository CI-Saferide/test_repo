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
	/* Ruke id,  File path, permission, user,  program}, */
/*
	{SR_FILE_WL_START_STATIC_RULE_NO, "/work/file1.txt", "rwx", "*", "*"},
	{SR_FILE_WL_START_STATIC_RULE_NO + 1, "/work/file2.txt", "rwx", "*", "/bin/cat"},
*/
	{0, ""},  // Must be the last entry.
};

#endif

