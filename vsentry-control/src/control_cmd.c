#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/un.h>
#include <errno.h>

static char *commands[] = {
	"wl_learn",
	"wl_apply",
	"wl_print",
	"wl_reset",
	"sp_learn",
	"sp_apply",
	"sp_off",
	NULL,
};

static int is_valid_cmd(char *cmd)
{
	int i;

	for (i = 0; commands[i]; i++) {
		if (!strcmp(cmd, commands[i]))
			return 1;
	}
	return 0;
}

static void usage(char *prog)
{
	printf("usage: %s -c [cmd]\n", prog);
	printf("wl_learn		- start new white list learning\n");
	printf("wl_apply		- while in wl_learn mode, applies current learned info\n");
	printf("wl_apply		- while in wl_learn mode, prints current learned info to the log\n");
	printf("wl_reset		- reset white list info (clears any applied learning data\n");
	printf("sp_learn		- start new system policer learning\n");
	printf("sp_apply		- while in sp_learn mode, applies current learned info\n");
	printf("sp_off			- disables system policer feature\n");
}

int main(int argc, char **argv)
{
	struct sockaddr_un addr = {};
	char cmd[200];
	int opt, fd,rc;

	*cmd = 0;
	while ((opt = getopt(argc, argv, "c:h"))  != -1 ) { 
		switch (opt) { 
			case 'c':
				strcpy(cmd, optarg);
          			break;
			case 'h':
				usage(argv[0]);
				return 0;
        		default:
				printf("Invalid option %c ignored\n", opt);
				return -1;
     		}
	}
	if (!is_valid_cmd(cmd)) {
		usage(argv[0]);
		return -1; 
	}

	if ( (fd = socket(AF_UNIX, SOCK_STREAM, 0)) == -1) { 
		perror("socket error");
		return -1;
	}

 	addr.sun_family = AF_UNIX;
	strcpy(addr.sun_path, "/tmp/sr_umanager.socket");

	if (connect(fd, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("connect error");
		return -1;
	}

	rc = write(fd, cmd , strlen(cmd));
	if (rc < 0) {
        	perror("write error");
        	return -1;
  	 }
	if (rc < strlen(cmd))
		fprintf(stderr,"partial write");
	close(fd);

 	return 0;
}

