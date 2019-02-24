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
#include <sys/select.h>
#include <sys/inotify.h>

#include "vproxy_client.h"
#include "message.h"
#include "file_rule.h"
#include "sr_cls_wl_common.h"
#include "sr_actions_common.h"
#include "sr_cls_file_control.h"
#include "sr_cls_rules_control.h"
#include "sr_config_parse.h"

#define POLL_TIMEOUT 	500
#define TIME_INTERVAL 	10
#define TIME_INTERVAL2 	1
#define BUF_LEN 512

static SR_BOOL run_irdeto = SR_FALSE;
static SR_BOOL connected = SR_FALSE;
static SR_32 fd = -1;

static void handle_msg(struct raw_message *raw_msg)
{
	switch (raw_msg->type) {
		case TELEMETRY_MSG:
		        CEF_log_event(SR_CEF_CID_SYSTEM, "IRDETO", SEVERITY_MEDIUM, "%s", raw_msg->data);
			break;
		default:
			break;
	}
}

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
			handle_msg(&raw_msg);
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
	while (run_irdeto) {
		start_client();
		sleep(TIME_INTERVAL2);
	}

        return SR_SUCCESS;
}

static SR_32 irdeto_policy_server(void *data)
{
	int policy_fd, ret, n;
	fd_set rfds;
	char buf[BUF_LEN], *p;
	struct timeval tv = {};
	struct inotify_event *event;
	unsigned int notify_mask = IN_CLOSE_WRITE;
	struct config_params_t *config_params;

	config_params = sr_config_get_param();

	policy_fd = inotify_init1(IN_NONBLOCK);
	ret = inotify_add_watch(policy_fd, config_params->policy_dir, notify_mask);
	if (ret < 0) {
		perror("inotify_add_watch");
		return SR_ERROR;
	}

	while (run_irdeto) {
		FD_ZERO(&rfds);
		FD_SET(policy_fd, &rfds);
		tv.tv_sec = 2 * TIME_INTERVAL2;

		ret = select(policy_fd + 1, &rfds, NULL, NULL, &tv);
		if (ret < 0) {
			perror("select");
			continue;
		}
		if (!ret)
			continue;

		n = read(policy_fd, buf, BUF_LEN);
		for (p = buf; p < buf + n; ) {
			event = (struct inotify_event *) p;
			if (event->mask & IN_CLOSE_WRITE) {
				printf("IN_CLOSE_WRITE !!!!\n");
				if (fd > -1)
					vproxy_client_send_new_policy_msg(fd);
				break;
			}
			p += sizeof(struct inotify_event) + event->len;
		}
	}

	return SR_SUCCESS;
}

typedef struct {
	char	filename[FILE_NAME_SIZE];
	char	permission[4];
	char	user[USER_NAME_SIZE];
	char	program[PROG_NAME_SIZE]; 
} static_file_rule_t;

SR_32 create_irdeto_static_white_list(void)
{
	static static_file_rule_t irdeto_static_wl [] = {
		/* {"/work/file1.txt", "rwx", "*", "/bin/cat"}, Example */
		{""},  // Must be the last entry.
	};
	SR_U32 rule_no, i;
	SR_U8 perm;
	SR_U16 actions_bitmap = SR_CLS_ACTION_ALLOW | SR_CLS_ACTION_LOG;

	for (i = 0; *irdeto_static_wl[i].filename; i++) {
		perm = 0;
		rule_no = i + SR_FILE_WL_START_STATIC_RULE_NO;
		if (rule_no >= SR_FILE_WL_START_RULE_NO) {
                	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                       	                         "%s=Maximum number of statis wl rules have reached.", REASON);
			return SR_ERROR;
		}
		if (strstr(irdeto_static_wl[i].permission, "r"))
			perm |= SR_FILEOPS_READ;
		if (strstr(irdeto_static_wl[i].permission, "w"))
			perm |= SR_FILEOPS_WRITE;
		if (strstr(irdeto_static_wl[i].permission, "x"))
			perm |= SR_FILEOPS_EXEC;

		sr_cls_file_add_rule(irdeto_static_wl[i].filename, irdeto_static_wl[i].program, irdeto_static_wl[i].user, rule_no, (SR_U8)1);
		sr_cls_rule_add(SR_FILE_RULES, rule_no, actions_bitmap, perm, SR_RATE_TYPE_BYTES, 0, 0 ,0, 0, 0, 0);
	}                   

	return SR_SUCCESS;
}

SR_32 irdeto_interface_init(void)
{
	SR_32 ret;

	run_irdeto = SR_TRUE;
	ret = sr_start_task(SR_IRDETO_INTERFACE, irdeto_interface_server);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to start irdeto unix socket",REASON);
		return SR_ERROR;
	}
	if (create_irdeto_static_white_list()) {
                CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
                                                "%s=failed to create Irdeto static white list ",REASON);
                return SR_ERROR;
	}
	ret = sr_start_task(SR_IRDETO_POLICY, irdeto_policy_server);
	if (ret != SR_SUCCESS) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH,
					"%s=failed to start irdeto unix socket",REASON);
		return SR_ERROR;
	}

	return SR_SUCCESS;
}

void irdeto_interface_uninit(void)
{
	run_irdeto = SR_FALSE;
	sr_stop_task(SR_IRDETO_INTERFACE);
	sr_stop_task(SR_IRDETO_POLICY);
}

