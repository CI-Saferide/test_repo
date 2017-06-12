#ifndef SAL_LINUX_ENGINE_H
#define SAL_LINUX_ENGINE_H


#ifdef PLATFORM_LINUX

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <stdlib.h>
#include <linux/netlink.h>
#include <poll.h>

#include <sys/socket.h>

#include <pthread.h>

typedef enum {
	PROTOCOL_UDP,
	PROTOCOL_TCP,
	PROTOCOL_RAW
} SAL_PROTOCOL;

int sal_socket(SAL_PROTOCOL protocol, int port);

int sal_bind(int fd);
int sal_bind_log(int fd);

//void sal_sendmsg(int fd,char *data);
void sal_sendmsg(char *data, int size);

int sal_recvmsg(struct msghdr *rcv_msg, void *data);

int sal_recvmsg_loop();

#endif /* PLATFORM_LINUX */

#endif /* SAL_LINUX_ENGINE_H*/
