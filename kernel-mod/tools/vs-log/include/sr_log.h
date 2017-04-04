#ifndef SR_LOG_H
#define SR_LOG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>

#include <stdlib.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <poll.h>

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/

#define MAX_MSG_LEN             240

#define SR_LOG_EMERG			1
#define SR_LOG_ALERT			1
#define SR_LOG_CRIT				1
#define SR_LOG_ERR				1
#define SR_LOG_WARN				1
#define SR_LOG_NOTICE			1
#define SR_LOG_INFO				1
#define SR_LOG_DEBUG			1

enum SR_LOG_PRIORITY {
    LOG_EMERG,	
    LOG_ALERT,	
    LOG_CRIT,
    LOG_ERR,	
    LOG_WARN,		
    LOG_NOTICE,	
    LOG_INFO,	
    LOG_DEBUG		
};

int sr_log_init (const char* app_name, int flags);
int sr_net_init (/*hardcoded for now...*/);
int __sr_print (enum SR_LOG_PRIORITY priority, int line, const char *file, const char *fmt, ...);
#define sr_print(priority, ...) __sr_print(priority, __LINE__, __FILE__, __VA_ARGS__)


/* global variables */
char g_app_name[20];

struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh;
struct iovec iov;
int sock_fd;
struct msghdr msg;


#ifdef __cplusplus
}
#endif

#endif /* SR_LOG_H */
