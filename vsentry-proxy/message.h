#ifndef __MESSAGE_H__
#define __MESSAGE_H__

#include "stdint.h"

#ifdef DEBUG

#include <stdio.h>
#include <string.h>

#define msg_dbg(fmt, ...) \
	fprintf(stdout, fmt, ##__VA_ARGS__)
#define msg_err(fmt, ...) \
	fprintf(stderr, fmt, ##__VA_ARGS__)
#else
#define msg_dbg(...)
#define msg_err(...)
#endif

#ifndef XPP_ENABLED
#define _xc_transformtype(x)
#define _xc_transformcast(x)
#define _xc_preservetype
#define _xc_preserve_interface
#endif

#define LOCAL_SOCKET_PATH 	"/tmp/server.local"
#define TOTAL_MSG_SIZE 		1024
#define MSG_ERROR 		-1
#define MSG_SUCCESS 		0

struct telemetry_msg_ack {
	uint32_t 	messages_received;
};

/**
 * Sent from vProxy to vSentry to make sure it's alive
 * every X seconds
 */
struct sanity_query_msg {
	uint32_t 	challenge;
};

/* vSentry response to vProxy */
struct sanity_query_msg_ack {
	/*
	response must be query_msg->challenge +1
	*/
	uint32_t 	response;
};

enum {
	TELEMETRY_MSG 		= 0,
	TELEMETRY_MSG_ACK 	= 1,
	SANITY_QUERY_MSG 	= 2,
	SANITY_QUERY_MSG_ACK 	= 3,
	POLICY_UPDATE_MSG 	= 4
};


/** Message representation in serialized form
 *
 * | Message         Message
 * | size in bytes | type   |   Payload             |
 * +---------------+--------+-----------------------+
 * |    2-bytes    | 1-byte |   N-bytes             |
*/

struct message {
	_xc_transformtype(blue) unsigned int 	type;
	_xc_transformtype(red)  unsigned char 	data[TOTAL_MSG_SIZE-1];
} __attribute__((packed, aligned(4)));

struct raw_message {
	unsigned int 	type;
	unsigned char 	data[TOTAL_MSG_SIZE-1];
} __attribute__((packed, aligned(4)));

#endif /* __MESSAGE_H__ */
