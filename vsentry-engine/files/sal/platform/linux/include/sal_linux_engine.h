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

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh;
struct iovec iov;
struct msghdr msg;

struct sockaddr_nl src_addr_log, dest_addr_log;
struct nlmsghdr *nlh_log;
struct iovec iov_log;
struct msghdr msg_log;

int main_sock_fd,log_sock_fd;

typedef enum {
	PROTOCOL_UDP,
	PROTOCOL_TCP,
	PROTOCOL_RAW
} SAL_PROTOCOL;

int sal_socket(SAL_PROTOCOL protocol, int port);

int sal_bind(int fd);
int sal_bind_log(int fd);

void sal_sendmsg(int fd,char *data);

int sal_recvmsg(int fd);

int sal_recvmsg_loop();

#endif /* PLATFORM_LINUX */

#endif /* SAL_LINUX_ENGINE_H*/
