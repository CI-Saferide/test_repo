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

#include "vproxy_client.h"
#include "sr_log.h"

static int recv_telemetry_msgs = 0;

/*************************************************************************
 * function: 	vproxy_client_reset_counters
 * description:	this function will reset all static counters incase the
 * 		server exit/crash/etc.
 * in params: 	n/a.
 * out params: 	n/a
 * return: 	void
 *************************************************************************/
void vproxy_client_reset_counters(void)
{
	recv_telemetry_msgs = 0;
}

/*************************************************************************
 * function: 	vproxy_client_handle_telemetry_request
 * description:	this function handle telemetry request from server. the
 * 		message should be logged to a log file as is (for now) and
 * 		respond with the value of the counter counting all log
 * 		messages received unti now, including the last one
 * in params: 	int fd - socket fd.
 * 		char *tlm - the telemetry message
 * out params: 	n/a
 * return: 	MSG_ERROR on error, MSG_SUCCESS on success
 *************************************************************************/
static int vproxy_client_handle_telemetry_request(int fd, char *tlm)
{
	int ret;
	struct message msg;
	struct raw_message *raw_msg = (struct raw_message*)(_xc_transformcast(void *)(&msg));
	struct telemetry_msg_ack *ack = (struct telemetry_msg_ack*) (_xc_transformcast (void *) (&(msg.data)));

	recv_telemetry_msgs++;

	/* TODO: send recv msg (tlm) to vsentry logger */
	msg_dbg("got new log message (total %d): %s\n", recv_telemetry_msgs, tlm);

	CEF_log_event(SR_CEF_CID_SYSTEM, "irdeto", SEVERITY_MEDIUM, "%s", tlm);

	/* prepare the response */
	msg.type = TELEMETRY_MSG_ACK;
	ack->messages_received = recv_telemetry_msgs;

	/* send the message to server */
	ret = write(fd, raw_msg, TOTAL_MSG_SIZE);
	if (ret != TOTAL_MSG_SIZE) {
		msg_err("write failed\n");
		return MSG_ERROR;
	}

	return MSG_SUCCESS;
}

/*************************************************************************
 * function: 	vproxy_client_respond_query
 * description:	this function handle a query request from from vproxy. the
 * 		message contain a challenge number that we should increment
 * 		by 1 and send it back.
 * in params: 	int fd - socket fd.
 * 		struct sanity_query_msg *query - hold the challenge
 * out params: 	n/a
 * return: 	MSG_ERROR on error, MSG_SUCCESS on success
 *************************************************************************/
static int vproxy_client_respond_query(int fd, struct sanity_query_msg *query)
{
	int ret;
	struct message msg;
	struct raw_message *raw_msg = (struct raw_message*)(_xc_transformcast(void *)(&msg));
	struct sanity_query_msg_ack *res = (struct sanity_query_msg_ack*) (_xc_transformcast (void *) (&(msg.data)));

	/* prepare the response */
	msg.type = SANITY_QUERY_MSG_ACK;
	res->response = (query->challenge + 1);

	msg_dbg("got query with challenge %u responding with %u\n", query->challenge, res->response);

	/* send the message to server */
	ret = write(fd, raw_msg, TOTAL_MSG_SIZE);
	if (ret != TOTAL_MSG_SIZE) {
		msg_err("write failed: %s\n", strerror(ret));
		return MSG_ERROR;
	}

	return MSG_SUCCESS;
}

/*************************************************************************
 * function: 	vproxy_client_send_new_policy_msg
 * description:	this function send new policy msg to server.
 * in params: 	int fd - socket fd.
 * out params: 	n/a
 * return: 	MSG_ERROR on error, MSG_SUCCESS on success
 *************************************************************************/
int vproxy_client_send_new_policy_msg(int fd)
{
	struct message msg;
	struct raw_message *raw_msg = (struct raw_message*)(_xc_transformcast(void *)(&msg));
	int ret;

	/* prepare the policy update message */
	msg.type = POLICY_UPDATE_MSG;

	msg_dbg("sending new policy update message\n");

	/* send the message to server */
	ret = write(fd, raw_msg, TOTAL_MSG_SIZE);
	if (ret != TOTAL_MSG_SIZE) {
		msg_err("write failed: %s\n", strerror(ret));
		return MSG_ERROR;
	}

	return MSG_SUCCESS;
}

/*************************************************************************
 * function: 	vproxy_handle_recv_msg
 * description:	main function that handle all incomming msgs.
 * in params: 	struct message *msg
 * out params: 	n/a
 * return: 	MSG_ERROR on error, MSG_SUCCESS on success
 *************************************************************************/
int vproxy_client_handle_recv_msg(int fd, struct raw_message *raw_msg)
{
	int ret = MSG_SUCCESS;
	struct message *msg = (struct message*)(_xc_transformcast(void *)(raw_msg));

	switch (msg->type) {
	case SANITY_QUERY_MSG:
		{
			struct sanity_query_msg *query = (struct sanity_query_msg*) (_xc_transformcast (void *) (&(msg->data)));

			ret = vproxy_client_respond_query(fd, query);
		}
		break;

	case TELEMETRY_MSG:
		{
			_xc_preservetype char log[TOTAL_MSG_SIZE-1];
			int i;

			for (i=0; i<(TOTAL_MSG_SIZE-1); i++)
				log[i] = msg->data[i];

			ret = vproxy_client_handle_telemetry_request(fd, log);
		}
		break;

	default:
		msg_err("unsupported msg type\n");
		ret = MSG_ERROR;
		break;
	}

	return ret;
}
