#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <ut_server.h>

#define FIXED_PART_START "{\"canVersion\": 238, \"ipVersion\": 238, \"systemVersion\": 238, \"actionVersion\": 238, \"actions\": [{\"log\": false, \"drop\": false, \"id\": 1111, \"allow\": true, \"name\": \"allow\"}, {\"log\": true, \"drop\": false, \"id\": 1112, \"allow\": true, \"name\": \"allow_log\"}, {\"log\": true, \"drop\": true, \"id\": 1113, \"allow\": false, \"name\": \"drop\"}]"

#define CHANGED_PART_FILE ", \"systemPolicies\": [{\"priority\": \"%d\", \"id\": 11, \"fileName\": \"%s\", \"permissions\": \"%d\", \"execProgram\": \"%s\", \"user\": \"%s\", \"actionName\": \"%s\"}], \"canPolicies\": [], \"ipPolicies\": []"

#define CHANGED_PART_IP ", \"ipPolicies\": [{\"priority\": \"%d\", \"id\": 11, \"srcIp\": \"%s\", \"dstIp\": \"%s\", \"srcNetmask\": \"%s\", \"dstNetmask\": \"%s\", \"srcPort\":%d, \"dstPort\":%d, \"protocol\": \"%s\", \"execProgram\": \"%s\", \"user\": \"%s\", \"actionName\": \"%s\"}], \"canPolicies\": [], \"systemPolicies\": []"

#define CHANGED_PART_CAN ", \"canPolicies\": [{\"priority\": \"%d\", \"id\": 11, \"msgId\": \"%s\", \"canDirection\": \"%s\", \"canInterface\": \"%s\", \"execProgram\": \"%s\", \"user\": \"%s\", \"actionName\": \"%s\"}], \"ipPolicies\": [], \"systemPolicies\": []"

#define FIXED_PART_END "}"

#define CHECK_RESULT(x)	if(x) return x;

#define TEST_PORT 7788
#define VSENTRY_LOG "/var/log/vsentry0.log"
#define MAX_STR_SIZE 512
#define MAX_LOG_LINE 512
#define MAX_USER_SIZE 64

static int is_verbose;
FILE *flog;

int sr_config_get_mod_state(void)
{
	return 0;
}

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

int main(int argc, char **argv)
{
	int rc = 0, opt;
	char *type = NULL;

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

	return rc;
}
