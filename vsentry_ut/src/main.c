#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "sysrepo_mng.h"

#define MAX_STR_SIZE 512

#define FIXED_PART_START "{\"canVersion\": 238, \"ipVersion\": 238, \"systemVersion\": 238, \"actionVersion\": 238, \"actions\": [{\"log\": false, \"drop\": false, \"id\": 1111, \"allow\": true, \"name\": \"allow\"}, {\"log\": true, \"drop\": false, \"id\": 1112, \"allow\": true, \"name\": \"allow_log\"}, {\"log\": true, \"drop\": true, \"id\": 1113, \"allow\": false, \"name\": \"drop\"}]"

#define CHANGED_PART_FILE ", \"systemPolicies\": [{\"priority\": \"%d\", \"id\": 11, \"fileName\": \"%s\", \"permissions\": \"%d\", \"execProgram\": \"%s\", \"user\": \"%s\", \"actionName\": \"%s\"}], \"canPolicies\": [], \"ipPolicies\": []"

#define FIXED_PART_END "}"

static char *home, test_area[MAX_STR_SIZE];
static int is_verbose;

int stam;

static char *get_cmd_output(void *cmd)
{
  FILE *fp;
  static char buf[1024];

  if (!(fp = popen(cmd, "r")))
        return NULL;

  if (!fgets(buf, sizeof(buf)-1, fp))
	return NULL;
  buf[strlen(buf) - 1] = 0;

  pclose(fp);

  return buf;
}

static char *get_json(int rule_id, char *file_name, int perm, char *user, char *exec_prog, char *action)
{
	static char json_str[10000];

	sprintf(json_str,FIXED_PART_START CHANGED_PART_FILE FIXED_PART_END, rule_id, file_name, perm, exec_prog, user, action);

	return json_str;
}

static void check_test(int rc, int is_success, int test, int *err_count)
{
	if (!((rc == 0 && is_success) || (rc != 0 && !is_success))) {
		(*err_count)++;
		printf("ERROR test#%d\n", test);
	}
}

static void file_test_case(sysrepo_mng_handler_t *handler, char *file_name, int rule_id, int perm, char *user, char *exec_prog, char *action, char *cmd, int *test_count, int *err_count,
	int is_success, char *desc)
{
	char file[MAX_STR_SIZE];

	(*test_count)++;
	if (is_verbose)
		printf(">>>>> T#%d >>>>>>>>>>>>>>>>>>>>>> %s cmd:%s\n", *test_count, desc, cmd);
	sprintf(file, "%s/%s", test_area, file_name);
	sysrepo_mng_parse_json(handler, get_json(rule_id, file, perm, user, exec_prog, action), NULL, 0);
	sleep(1);
	check_test(system(cmd), is_success, *test_count, err_count);
}

static void open_file_test_case(sysrepo_mng_handler_t *handler, char *file_name, char *open_attr, int rule_id, int perm, char *user, char *exec_prog, char *action,
	 int *test_count, int *err_count, int is_success, char *desc)
{
	char file[MAX_STR_SIZE];
	FILE *f;

	(*test_count)++;
	if (is_verbose)
		printf(">>>>> T#%d >>>>>>>>>>>>>>>>>>>>>> %s \n", *test_count, desc);
	sprintf(file, "%s/%s", test_area, file_name);
	if (rule_id > -1)
		sysrepo_mng_parse_json(handler, get_json(rule_id, file, perm, user, exec_prog, action), NULL, 0);
	else
		sysrepo_mng_parse_json(handler, FIXED_PART_START FIXED_PART_END, NULL, 0);
	sleep(1);
	f = fopen(file, open_attr);
	check_test(!f, is_success, *test_count, err_count);
	if (f)
		fclose(f);
}

static int create_file_setup(void)
{
	char cmd[MAX_STR_SIZE];
	int rc;

	sprintf(cmd, "rm -rf %s", test_area);
	rc = system(cmd);
	sprintf(cmd, "mkdir -p %s", test_area);
	rc = system(cmd);
	sprintf(cmd, "mkdir -p %s/dirrp", test_area);
	rc = system(cmd);
	sprintf(cmd, "mkdir -p %s/dirwp", test_area);
	rc = system(cmd);
	sprintf(cmd, "echo AAAAAA > %s/dirrp/file", test_area);
	rc = system(cmd);
	sprintf(cmd, "echo AAAAAA > %s/filerp", test_area);
	rc = system(cmd);
	sprintf(cmd, "echo AAAAAA > %s/filerp1", test_area);
	rc = system(cmd);
	sprintf(cmd, "echo AAAAAA > %s/filerp2", test_area);
	rc = system(cmd);
	sprintf(cmd, "echo AAAAAA > %s/filewp", test_area);
	rc = system(cmd);
	sprintf(cmd, "echo AAAAAA > %s/file", test_area);
	rc = system(cmd);
	sprintf(cmd, "echo ls > %s/filexp", test_area);
	rc = system(cmd);
	sprintf(cmd, "chmod +x  %s/filexp", test_area);
	rc = system(cmd);
	rc = system("sudo useradd -p `mkpasswd unix11` -m -g users test_user");

	return rc;
}

static void cleanup_file_setup(void)
{
	char cmd[MAX_STR_SIZE];
	int rc;

	rc = system("sudo deluser test_user");
	sprintf(cmd, "rm -rf %s", test_area);
	rc = system(cmd);
}

static int handle_file(sysrepo_mng_handler_t *handler)
{
	char cmd[MAX_STR_SIZE], *cat_prog, *user;
	int rc = 0, err_count = 0, test_count = 0;

	sprintf(test_area, "%s/test_area", home);

	/* Delete all rules */
	sysrepo_mng_parse_json(handler, FIXED_PART_START FIXED_PART_END, NULL, 0);
	sleep(1);

	create_file_setup();

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> LS a protected dir */
	sprintf(cmd, "ls %s/dirrp", test_area);
	file_test_case(handler, "dirrp", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 0, "LS a protected dir");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> READ a protected file */
	sprintf(cmd, "cat %s/filerp > /dev/null", test_area);
	file_test_case(handler, "filerp", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 0, "READ a protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> REMOVE a read protected file */
	sprintf(cmd, "rm %s/filerp", test_area);
	file_test_case(handler, "filerp", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 1, "REMOVE a read protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>  MOVE a read protected file */
	sprintf(cmd, "mv %s/filerp1 %s/filerp_m", test_area, test_area);
	file_test_case(handler, "filerp1", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 0, "MOVE a read protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> SOFT LINK a read protected file */
	sprintf(cmd, "ln -s %s/filerp1 %s/filerp_s", test_area, test_area);
	file_test_case(handler, "filerp1", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 1, "SOFT LINK a read protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> READ a soft linked read protected file */
	sprintf(cmd, "cat %s/filerp_s > /dev/null", test_area);
	file_test_case(handler, "filerp1", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 0, "READ a soft linked read protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> HARD LINK a read protected file */
	sprintf(cmd, "ln %s/filerp1 %s/filerp_l", test_area, test_area);
	file_test_case(handler, "filerp1", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 0, "HARD LINK a read protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> COPY read protected file */
	sprintf(cmd, "cp %s/filerp1 %s/filerp_c", test_area, test_area);
	file_test_case(handler, "filerp1", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 0, "COPY read protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> OPEN a read protected file to read */
	open_file_test_case(handler, "filerp1", "r", 11, 4, "*", "*", "drop",  &test_count, &err_count, 0, "OPEN read protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> DELETE rule and OPEN a non protected file to read */
	open_file_test_case(handler, "filerp1", "r", -1, 0, "", "", "",  &test_count, &err_count, 1, "OPEN read protected file - no rule");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> READ a file fro, a read protrcted dir */
	sprintf(cmd, "cat %s/dirrp/file", test_area);
	file_test_case(handler, "dirrp", 11, 4, "*", "*", "drop", cmd , &test_count, &err_count, 0, "READ a file fro, a read protrcted dir");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> READ from a write protected file */
	sprintf(cmd, "cat %s/filewp > /dev/null", test_area);
	file_test_case(handler, "filewp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 1, "READ from a write protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> WRITE to a write protected file */
	sprintf(cmd, "echo kkk >  %s/filewp", test_area);
	file_test_case(handler, "filewp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "WRITE to a write protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> WRITE to a write protected dir */
	sprintf(cmd, "echo kkk > %s/dirwp/file_new", test_area);
	file_test_case(handler, "dirwp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "WRITE to a write protected dir");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RM a write protected dir */
	sprintf(cmd, "rm -r %s/dirwp", test_area);
	file_test_case(handler, "dirwp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "REMOVE a write protected dir");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> RM a write protected file */
	sprintf(cmd, "rm -r %s/filewp", test_area);
	file_test_case(handler, "filewp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "REMOVE a write protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> MV to a write protected file */
	sprintf(cmd, "mv %s/file %s/filewp", test_area, test_area);
	file_test_case(handler, "filewp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "MV to a write protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> MV to a write protected dir */
	sprintf(cmd, "mv %s/file %s/dirrp", test_area, test_area);
	file_test_case(handler, "dirrp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "MV to a write protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> COPY to a write protected file */
	sprintf(cmd, "cp %s/file %s/filewp", test_area, test_area);
	file_test_case(handler, "filewp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "MV to a write protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> COPY to a write protected dir */
	sprintf(cmd, "cp %s/file %s/dirrp", test_area, test_area);
	file_test_case(handler, "dirrp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "MV to a write protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> SOFT LINK into a write proteced dir */
	sprintf(cmd, "ln -s %s/file %s/dirrp/file_s", test_area, test_area);
	file_test_case(handler, "dirrp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "SOFT LINK of into a write proteced dir");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> HARD LINK into a write proteced dir */
	sprintf(cmd, "ln %s/file %s/dirrp/file_s", test_area, test_area);
	file_test_case(handler, "dirrp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "HARD LINK of into a write proteced dir");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> SOFT LINK of a write proteced file */
	sprintf(cmd, "ln -s %s/filewp %s/file_s", test_area, test_area);
	file_test_case(handler, "filewp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 1, "SOFT LINK of write proteced file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> UPDATE the SOFT LINK of a write proteced file */
	sprintf(cmd, "cat XXXXXX > %s/file_s", test_area);
	file_test_case(handler, "filewp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "UPDATE the SOFT LINK of a write proteced file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> HARD LINK of a write proteced file */
	sprintf(cmd, "ln %s/filewp %s/file_s1", test_area, test_area);
	file_test_case(handler, "filewp", 11, 2, "*", "*", "drop", cmd , &test_count, &err_count, 0, "HARD LINK of write proteced file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> OPEN a write protected file to read */
	open_file_test_case(handler, "filewp", "r", 11, 2, "*", "*", "drop",  &test_count, &err_count, 1, "OPEN write protected file to read");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> OPEN a write protected file to write */
	open_file_test_case(handler, "filewp", "w", 11, 2, "*", "*", "drop",  &test_count, &err_count, 0, "OPEN write protected file to write");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> READ an EXE protected file  */
	sprintf(cmd, "cat %s/filexp > /dev/null", test_area);
	file_test_case(handler, "filexp", 11, 1, "*", "*", "drop", cmd , &test_count, &err_count, 1, "READ an EXE protected file");

	/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> EXECUTE an EXE protected file  */
	sprintf(cmd, "%s/filexp", test_area);
	file_test_case(handler, "filexp", 11, 1, "*", "*", "drop", cmd , &test_count, &err_count, 0, "EXECUTE an EXE protected file");

	if ((cat_prog = get_cmd_output("which cat"))) {
		/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> READ a protected file with exec prog*/
		sprintf(cmd, "cat %s/filerp2 > /dev/null", test_area);
		file_test_case(handler, "filerp2", 11, 4, "*", cat_prog , "drop", cmd , &test_count, &err_count, 0, "READ a protected file with exec prog");
		/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> ACCESSING a read protected file with exec prog of cat with different executable*/
		sprintf(cmd, "cp %s/filerp2 %s/filerp2_c", test_area, test_area);
		file_test_case(handler, "filerp2", 11, 4, "*", cat_prog, "drop", cmd , &test_count, &err_count, 1,
			"ACCESSING a read protected file with exec prog of cat with different executable");
	}

	if ((user = getenv("USER"))) {
		/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> READ a protected file with user match*/
		sprintf(cmd, "cat %s/filerp2 > /dev/null", test_area);
		file_test_case(handler, "filerp2", 11, 4, user, "*", "drop", cmd , &test_count, &err_count, 0, "READ a protected file with user match");
		/* >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> READ a protected file with user NON match*/
		sprintf(cmd, "cat %s/filerp2 > /dev/null", test_area);
		file_test_case(handler, "filerp2", 11, 4, "test_user", "*", "drop", cmd , &test_count, &err_count, 1, "READ a protected file with user NON match");
	}
	

	/* Delete all rules */
	sysrepo_mng_parse_json(handler, FIXED_PART_START FIXED_PART_END, NULL, 0);

	cleanup_file_setup();

	printf("\n\n=========================== FILE PROTECT TESTS REPROT ==============================\n");

	if (!err_count) {
		printf("\n******************************* SUCESSES ******************** \n Number of tests:%d\n", test_count);
	} else {
		printf("\n******************************* FAILED ********************** \n Number erros:%d/ Out of %d tests\n", err_count, test_count);
		rc = -1;
	}

	return rc;
}

int main(int argc, char **argv)
{
	sysrepo_mng_handler_t handler;
	int rc = 0, opt;
	char *type = NULL;

	if (getenv("TEST_AREA_HOME"))
		home = strdup(getenv("TEST_AREA_HOME"));
	else
		home = strdup(getenv("HOME"));

	while ((opt = getopt(argc, argv, "vt:")) != -1) {
		switch (opt) { 
			case 't':
				type = strdup(optarg);
				break;
			case 'v':
				is_verbose = 1;
				break;
			default:
				printf("Invalid option %c ignored \n", opt);
				break;
		}
	}

	if  (!type)
		return -1;

	if (sysrepo_mng_session_start(&handler)) {
		printf("sysrepo_mng_session_start failed \n");
		rc = -1;
		goto cleanup;
        }

	if (!strcmp(type, "file")) {
		rc = handle_file(&handler);
		goto cleanup;
	}

cleanup:
	sysrepo_mng_session_end(&handler);

	return rc;
}
