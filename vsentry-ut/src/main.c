#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "sysrepo_mng.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>

#define FIXED_PART_START "{\"canVersion\": 238, \"ipVersion\": 238, \"systemVersion\": 238, \"actionVersion\": 238, \"actions\": [{\"log\": false, \"drop\": false, \"id\": 1111, \"allow\": true, \"name\": \"allow\"}, {\"log\": true, \"drop\": false, \"id\": 1112, \"allow\": true, \"name\": \"allow_log\"}, {\"log\": true, \"drop\": true, \"id\": 1113, \"allow\": false, \"name\": \"drop\"}]"

#define CHANGED_PART_FILE ", \"systemPolicies\": [{\"priority\": \"%d\", \"id\": 11, \"fileName\": \"%s\", \"permissions\": \"%d\", \"execProgram\": \"%s\", \"user\": \"%s\", \"actionName\": \"%s\"}], \"canPolicies\": [], \"ipPolicies\": []"

#define CHANGED_PART_IP ", \"ipPolicies\": [{\"priority\": \"%d\", \"id\": 11, \"srcIp\": \"%s\", \"dstIp\": \"%s\", \"srcNetmask\": \"%s\", \"dstNetmask\": \"%s\", \"srcPort\":%d, \"dstPort\":%d, \"protocol\": \"%s\", \"execProgram\": \"%s\", \"user\": \"%s\", \"actionName\": \"%s\"}], \"canPolicies\": [], \"systemPolicies\": []"

#define CHANGED_PART_CAN ", \"canPolicies\": [{\"priority\": \"%d\", \"id\": 11, \"msgId\": \"%s\", \"canDirection\": \"%s\", \"execProgram\": \"%s\", \"user\": \"%s\", \"actionName\": \"%s\"}], \"ipPolicies\": [], \"systemPolicies\": []"

#define FIXED_PART_END "}"

#define TEST_PORT 7788
#define VSENTRY_LOG "/var/log/vsentry0.log"
#define MAX_STR_SIZE 512
#define MAX_LOG_LINE 512
#define MAX_USER_SIZE 64

static char *home, test_area[MAX_STR_SIZE];
static int is_verbose;
FILE *flog;

int get_ip_address(char ip[])
{
	FILE *f;
	char line[100] , *interface , *dest;
	struct ifaddrs *ifaddr, *ifa;
     
	f = fopen("/proc/net/route" , "r");
     
	while(fgets(line , 100 , f)) {
		interface = strtok(line , " \t");
		dest = strtok(NULL , " \t");
         
        	if(interface && dest && !strcmp(dest, "00000000"))
            		break;
        }

	if (getifaddrs(&ifaddr) == -1) { 
		perror("getifaddrs");
		return -1;
	}
 
	for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)  {
		if (!ifa->ifa_addr)
			continue;
		if (ifa->ifa_addr->sa_family != AF_INET)
			continue;
        	if (strcmp(ifa->ifa_name , interface) != 0)
			continue;
                if (getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), ip, NI_MAXHOST , NULL , 0 , NI_NUMERICHOST)) {
			perror("getnameinfo");
			return -1;
		}
        }

	freeifaddrs(ifaddr);

	return 0;
}

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

static char *get_file_json(int rule_id, char *file_name, int perm, char *user, char *exec_prog, char *action)
{
	static char json_str[10000];

	sprintf(json_str,FIXED_PART_START CHANGED_PART_FILE FIXED_PART_END, rule_id, file_name, perm, exec_prog, user, action);

	return json_str;
}

static char *get_ip_json(int rule_id, char *src_addr, char *src_netmask, char *dst_addr, char *dst_netmask, char *protocol, int src_port, int  dst_port, char *user, char *exec_prog, char *action)
{
	static char json_str[10000];

	sprintf(json_str,FIXED_PART_START CHANGED_PART_IP FIXED_PART_END, rule_id, src_addr, dst_addr, src_netmask, dst_netmask, src_port, dst_port, protocol, exec_prog, user, action);

	return json_str;
}

static char *get_can_json(int rule_id, char *msg_id, char *dir, char *user, char *exec_prog, char *action)
{
	static char json_str[10000];

	sprintf(json_str,FIXED_PART_START CHANGED_PART_CAN FIXED_PART_END, rule_id, msg_id, dir, exec_prog, user, action);

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
	sysrepo_mng_parse_json(handler, get_file_json(rule_id, file, perm, user, exec_prog, action), NULL, 0);
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
		sysrepo_mng_parse_json(handler, get_file_json(rule_id, file, perm, user, exec_prog, action), NULL, 0);
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
	int rc __attribute__((unused));

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
	rc = system("sudo useradd -m -g users test_user");

	return rc;
}

static void cleanup_file_setup(void)
{
	char cmd[MAX_STR_SIZE];
	int rc __attribute__((unused));

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

static FILE *log_init(void)
{
	FILE *flog;

        if (!(flog = fopen(VSENTRY_LOG, "r")))
                return NULL;
	fseek(flog, 0, SEEK_END);

	return flog;
}

static void log_deinit(FILE *flog)
{
	fclose(flog);
}

static int log_is_string_exists(FILE *flog, char *str)
{
        char buf[MAX_LOG_LINE];
	int is_found = 0;
        
	while (fgets(buf, MAX_LOG_LINE, flog))  {
		if (strstr(buf, str))
			is_found = 1;
	}

	return is_found;
}

static int test_ip_rule(sysrepo_mng_handler_t *handler, int fd, int rule_id, char *cmd, char *src_addr, char *src_netmask, char *dst_addr, char *dst_netmask, char *protocol,
		int src_port, int dst_port, char *user, char *exec, char *action, int *test_count, int *err_count)
{
	struct sockaddr_in remote = {};
	char log_search_string[100];
	int rc __attribute__((unused));

	(*test_count)++;
	sysrepo_mng_parse_json(handler, FIXED_PART_START FIXED_PART_END, NULL, 0);
	sleep(1);
	sysrepo_mng_parse_json(handler, get_ip_json(rule_id, src_addr, src_netmask, dst_addr, dst_netmask, protocol, src_port, dst_port, user, exec, action), NULL, 0);
	sleep(1);
	if (fd > -1)
		sendto(fd, cmd, strlen(cmd), 0, (struct sockaddr *)&remote, sizeof(remote));
	else
		rc = system(cmd);
	sleep(2);
	if (is_verbose)
		printf(">>>>> T#%d >>>>>>>>>>>>>>>>>>>>>> %s \n", *test_count, cmd);
	/* Check the log */
	sprintf(log_search_string, "RuleNumber=%d Action=", rule_id);
	if (!log_is_string_exists(flog, log_search_string)) {
		printf("%s FAILED !!!!!\n", cmd);
		(*err_count)++;
	}

	return 0;
}

static int handle_ip(sysrepo_mng_handler_t *handler)
{
	struct sockaddr_in remote = {};
	int rc = 0, fd, err_count = 0, test_count = 0;
	char *server_addr, cmd[MAX_STR_SIZE], user[MAX_USER_SIZE], local_ip[64];

	if (!(server_addr = getenv("TEST_SERVER_ADDR"))) {
		printf("No test server address defined. TEST_SERVER_ADDR\n");
		return -1;
	}

	if (!(flog = log_init())) 
		return -1;

	get_ip_address(local_ip);

	inet_aton(server_addr, &remote.sin_addr);
	remote.sin_port = htons(TEST_PORT);
	remote.sin_family = AF_INET;
	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
		perror("socket");
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&remote, sizeof(remote)) < 0) {
		perror("connect");
		return -1;
	}

	sprintf(cmd, "IPERF_UDP,%s,8888", local_ip);
	test_ip_rule(handler, fd, 10, cmd, server_addr, "255.255.255.255", "0.0.0.0", "255.255.255.255", "UDP",
		0, 8888, "*", "*", "drop", &test_count, &err_count);

	sprintf(cmd, "iperf -u -c %s -p 8888 -t 1", server_addr);
	test_ip_rule(handler, -1, 10, cmd, "0.0.0.0", "255.255.255.255", server_addr, "255.255.255.255", "UDP",
		0, 8888, "*", "*", "drop", &test_count, &err_count);

	getlogin_r(user, MAX_USER_SIZE);
	sprintf(cmd, "SSH,%s,%s", local_ip, user);
	test_ip_rule(handler, fd, 10, cmd, server_addr, "255.255.255.255", "0.0.0.0", "255.255.255.255", "TCP",
		0, 22, "*", "*", "drop", &test_count, &err_count);

	/* Delete rule */
	sysrepo_mng_parse_json(handler, FIXED_PART_START FIXED_PART_END, NULL, 0);

	if (!err_count) {
		printf("\n******************************* SUCESSES ******************** \n Number of tests:%d\n", test_count);
	} else {
		printf("\n******************************* FAILED ********************** \n Number erros:%d/ Out of %d tests\n", err_count, test_count);
		rc = -1;
	}

	close(fd);

	log_deinit(flog);
		
	return rc;
}

static int test_can_rule(sysrepo_mng_handler_t *handler, int rule_id, char *cmd, char *msg_id, char *dir,
		char *user, char *exec, char *action, int *test_count, int *err_count, int is_success)
{
	int rc __attribute__((unused)), is_string_exists;
	char log_search_string[MAX_STR_SIZE];

	(*test_count)++;
	sysrepo_mng_parse_json(handler, FIXED_PART_START FIXED_PART_END, NULL, 0);
	rc = sleep(1);
	sysrepo_mng_parse_json(handler, get_can_json(rule_id, msg_id, dir, user, exec, action), NULL, 0);
	rc = sleep(1);
	rc = system(cmd);
	if (is_verbose)
		printf(">>>>> T#%d >>>>>>>>>>>>>>>>>>>>>> %s \n", *test_count, cmd);
	rc = sleep(1);
	/* Check the log */
	sprintf(log_search_string, "RuleNumber=%d Action=", rule_id);
	is_string_exists = log_is_string_exists(flog, log_search_string);
	if ((is_string_exists && is_success) || (!is_string_exists && !is_success)) {
		printf("%s FAILED !!!!!\n", cmd);
		(*err_count)++;
	}
	
	return 0;
}

static int handle_can(sysrepo_mng_handler_t *handler)
{
	int rc = 0, err_count = 0, test_count = 0;
	char *user, *can_prog, cmd[1000];

	system("sudo useradd -m -g users test_user");
	if (!(flog = log_init())) 
		return -1;

	test_can_rule(handler, 10, "cansend vcan0 123#", "123", "OUT", "*", "*", "drop", &test_count, &err_count, 0);

	test_can_rule(handler, 10, "cansend vcan0 124#", "123", "OUT", "*", "*", "drop", &test_count, &err_count, 1);

	test_can_rule(handler, 10, "cansend vcan0 125#", "any", "OUT", "*", "*", "drop", &test_count, &err_count, 0);

	//test_can_rule(handler, 10, "cansend vcan0 126#", "126", "IN", "*", "*", "drop", &test_count, &err_count, 0);

	if ((can_prog = get_cmd_output("which cansend"))) {
		test_can_rule(handler, 10, "cansend vcan0 123#", "123", "OUT", "*", can_prog, "drop", &test_count, &err_count, 0);
		sprintf(cmd,"sudo cp %s %s1\n", can_prog, can_prog);
		system(cmd);
		test_can_rule(handler, 10, "cansend1 vcan0 123#", "123", "OUT", "*", can_prog, "drop", &test_count, &err_count, 1);
	}

	if ((user = getenv("USER"))) {
		test_can_rule(handler, 10, "cansend vcan0 123#", "123", "OUT", "user", "*", "drop", &test_count, &err_count, 0);
		test_can_rule(handler, 10, "cansend vcan0 123#", "123", "OUT", "test_user", "*", "drop", &test_count, &err_count, 1);
	}

	/* Delete rule */
	sysrepo_mng_parse_json(handler, FIXED_PART_START FIXED_PART_END, NULL, 0);

	if (!err_count) {
		printf("\n******************************* SUCESSES ******************** \n Number of tests:%d\n", test_count);
	} else {
		printf("\n******************************* FAILED ********************** \n Number erros:%d/ Out of %d tests\n", err_count, test_count);
		rc = -1;
	}

	log_deinit(flog);
	rc = system("sudo deluser test_user > /dev/null");
		
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
	if (!strcmp(type, "ip")) {
		rc = handle_ip(&handler);
		goto cleanup;
	}
	if (!strcmp(type, "can")) {
		rc = handle_can(&handler);
		goto cleanup;
	}

cleanup:
	sysrepo_mng_session_end(&handler);

	return rc;
}
