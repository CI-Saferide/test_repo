#include "sr_log.h"
#include "sr_types.h"
#include "sr_tasks.h"
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <poll.h>
#include <sys/un.h>
#include <pthread.h>
#include <string.h>
#include <signal.h>

#include "vproxy_client.h"

#define POLL_TIMEOUT 	500
#define TIME_INTERVAL 	10
#define TIME_INTERVAL2 	1

static SR_BOOL run_client = SR_FALSE;
static SR_BOOL connected = SR_FALSE;
static SR_32 fd = -1;

/*************************************************************************
 * function: 	start_server
 * description:	the function will:
 * 			connect to server
 * 			start exmaple thread to generate new policy  messages
 * 			handle any incomming request from server
 * in params: 	void
 * out params: 	n/a
 * return: 	MSG_ERROR on error, MSG_SUCCESS on success
 *************************************************************************/
static SR_32 start_client(void)
{
	socklen_t len;
	struct sockaddr_un remote;
	struct sockaddr *remote_saddr = (struct sockaddr *)&remote;
	SR_32 ret;

	/* create socket and connect to server */
	fd = socket(AF_UNIX, SOCK_SEQPACKET,0);
	if (fd < 0) {
		msg_err("socket failed\n");
		return SR_ERROR;
	}

	remote.sun_family = AF_UNIX;
	strcpy(remote.sun_path, LOCAL_SOCKET_PATH);
	len = strlen(remote.sun_path) + sizeof(remote.sun_family);

	if (connect(fd, remote_saddr, len) < 0) {
		msg_err("connect failed\n");
		goto exit_err;
	}

	connected = true;
	msg_dbg("connected to server\n");

	while (true)  {
		struct pollfd pfd[] = { { fd, POLLIN, 0} };

		/* wait for incomming messages */
		ret = poll(pfd, 1, POLL_TIMEOUT);
		if (ret == 0)
			/* timeout */
			continue;
		else if(ret < 0)
			/* error polling */
			break;

		if (pfd[0].revents & POLLIN) {
			struct raw_message raw_msg;

			/* read the message header from socket */
			ret = read(fd, &raw_msg, TOTAL_MSG_SIZE);
			if (ret != TOTAL_MSG_SIZE) {
				msg_err("read failed\n");
				break;
			}

			/* handle request */
			if (vproxy_client_handle_recv_msg(fd, &raw_msg) != MSG_SUCCESS)
				break;
		}
	}

exit_err:
	connected = false;
	close(fd);
	fd = -1;
	vproxy_client_reset_counters();

	/* if we break from the while it means we failed somewhere */
	return SR_ERROR;
}

static SR_32 irdeto_interface_server(void *data)
{
	while (run_client) {
		start_client();
		sleep(TIME_INTERVAL2);
	}

        return SR_SUCCESS;
}

SR_32 irdeto_interface_init(void)
{
        SR_32 ret;

	run_client = SR_TRUE;
        ret = sr_start_task(SR_IRDETO_INTERFACE, irdeto_interface_server);
        if (ret != SR_SUCCESS) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                                "%s=failed to start irdeto unix socket",REASON);
                return SR_ERROR;
        }

        return SR_SUCCESS;
}

void irdeto_interface_uninit(void)
{
	run_client = SR_FALSE;
        sr_stop_task(SR_IRDETO_INTERFACE);
}

