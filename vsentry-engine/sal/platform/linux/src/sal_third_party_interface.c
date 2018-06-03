#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#include "sal_third_party_interface.h"
#include "sr_log.h"
#include "sr_types.h"
#include "sr_white_list.h"

static SR_BOOL is_run;
static pthread_t t;

static void handle_data(char *buf)
{
	printf("Got buf:%s: \n", buf);
	if (!memcmp(buf, "learn", strlen("learn"))) {
		sr_white_list_set_mode(SR_WL_MODE_LEARN);
	}
	if (!memcmp(buf, "apply", strlen("apply")))
		sr_white_list_set_mode(SR_WL_MODE_APPLY);
}

static void *third_party_server(void *p)
{
	int sock, msgsock, rval;
	struct sockaddr_un server = {};
	char buf[1024];

	unlink(SR_THIRD_PARTY_FILE);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	if (sock < 0) {
		printf("opening stream socket %s\n", strerror(errno));
		return NULL;
	}

	server.sun_family = AF_UNIX;
	strcpy(server.sun_path, SR_THIRD_PARTY_FILE);
	if (bind(sock, (struct sockaddr *) &server, sizeof(struct sockaddr_un))) {
		printf("binding stream socket %s\n", strerror(errno));
		return NULL;
	}

	printf("Socket name %s\n", server.sun_path);
	listen(sock, 1);

	while (is_run) {
		msgsock = accept(sock, 0, 0);

		if (msgsock == -1)
			printf("accept %s\n", strerror(errno));
		else do {
			bzero(buf, sizeof(buf));
			rval = read(msgsock, buf, 1024);
			if (rval < 0)
				printf("reading stream message %s\n", strerror(errno));
			else if (rval == 0)
				printf("ending connection\n");
			else
				handle_data(buf);
			} while (rval > 0);
		
		close(msgsock);
	}
	close(sock);
	unlink(SR_THIRD_PARTY_FILE);

	return NULL;
}

SR_32 sal_third_party_interface_init(void)
{
	is_run = SR_TRUE;

	if (pthread_create(&t, NULL, third_party_server, &is_run) != 0) {
		printf("pthread_create: %s\n", strerror(errno));
        	return SR_ERROR;
	}

	return SR_SUCCESS;
}

void sal_third_party_interface_uninit(void)
{
	is_run = SR_FALSE;
	pthread_cancel(t);
}
