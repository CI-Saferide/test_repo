#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <ut_server.h>
#include <sr_types.h>
#include <pthread.h>
#include <sys/socket.h>
#include <poll.h>
#include <netinet/in.h>
#include <net/if.h>
#include <string.h>
#include <sr_stat_analysis.h>

#define UT_BACKLOG 10
#define UT_SELECT_TIMEOUT 5

static SR_BOOL is_run;
static pthread_t t;

static enum UT_CMD_E ut_parsed_requset(char *req)
{
  if (strstr(req, UT_CMD_LEARN_STR))
     return UT_CMD_LERAN;
  if (strstr(req, UT_CMD_PROTECT_STR))
     return UT_CMD_PROTECT;
  if (strstr(req, UT_CMD_DONE_STR))
     return UT_CMD_DONE;
  if (strstr(req, UT_CMD_OFF_STR))
     return UT_CMD_OFF;

  return UT_CMD_INVALID;
}

static void *ut_server_thread(void *p)
{
	short port = UT_DEFAULT_PORT;
	struct sockaddr_in sa = {}, ca = {};
	int fd, con_fd, n;
	socklen_t calen = sizeof(ca);
	SR_BOOL is_done = SR_FALSE;
	fd_set rd_set;
	struct timeval tv = {};
	char msg_buf[UT_FIXED_MESSAGE_LEN + 1];
	enum UT_CMD_E cmd;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
     		perror("socket");
		return NULL;
	}
	
	sa.sin_addr.s_addr = INADDR_ANY;
	sa.sin_port = htons(port);
	sa.sin_family = AF_INET;
	printf("Binding to port %d \n", port);
	if (bind(fd, (struct sockaddr *)&sa, sizeof(ca))) {
		perror("socket");
		return NULL;
	}
	listen(fd, UT_BACKLOG);

	tv.tv_sec = 5;
	while (is_run) {
		printf("Accepting...\n");
		if ((con_fd = accept(fd, (struct sockaddr *)&ca, &calen)) < 0) {
			perror("socket");
			return NULL;
		}
		is_done = SR_FALSE;
		while (!is_done) {
			FD_ZERO(&rd_set);
			FD_SET(con_fd, &rd_set);
			if (select(con_fd + 1, &rd_set, NULL, NULL, &tv) < 0) {
				perror("select");
				return NULL;
			}
			if (!FD_ISSET(con_fd, &rd_set))
				continue;
			if ((n = recv(con_fd, msg_buf, UT_FIXED_MESSAGE_LEN, 0)) < 0) {
				perror("recv");
				return NULL;
			}
			msg_buf[n] = 0;
			cmd = ut_parsed_requset(msg_buf);
			switch (cmd) {
				case UT_CMD_LERAN:
					printf ("Goto learn mode\n");
					sr_stat_analysis_learn_mode_set(SR_STAT_MODE_LEARN);
					break;
				case UT_CMD_PROTECT:
                                	printf ("Goto protect mode\n");
                                	sr_stat_analysis_learn_mode_set(SR_STAT_MODE_PROTECT);
					break;
				case UT_CMD_OFF:
                                	printf ("Goto off mode\n");
                                	sr_stat_analysis_learn_mode_set(SR_STAT_MODE_OFF);
					break;
				case UT_CMD_DONE:
                                	printf ("Done \n");
					is_done = 1;
					break;
				default:
					break;
			}
		}
	}

	close(fd);

	return NULL;
}

int ut_server_start(void)
{
	is_run = SR_TRUE;
	pthread_create(&t, NULL, ut_server_thread, NULL);

	return SR_SUCCESS;
}

int ut_server_stop(void)
{
	is_run = SR_FALSE;

	return SR_SUCCESS;
}

