#include "include/sr_log.h"

const static char    *log_level_str[8] = {
"EMERGENCY", /* LOG_EMERG   = system is unusable               */
"ALERT",     /* LOG_ALERT   = action must be taken immediately */
"CRITICAL",  /* LOG_CRIT    = critical conditions              */
"ERROR",     /* LOG_ERR     = error conditions                 */
"WARNING",   /* LOG_WARNING = warning conditions               */
"NOTICE",    /* LOG_NOTICE  = normal but significant condition */
"INFO",      /* LOG_INFO    = informational                    */
"DEBUG",     /* LOG_DEBUG   = debug-level messages             */
};

char* file_basename(const char* file){

    char* pattern;
    char* tmp = (char*)file;
    
    pattern = strstr(tmp, "/");
    while (NULL != pattern) {
        pattern+=1;
        tmp = pattern;
        pattern = strstr(pattern, "/");
    }
    return (tmp);
}

int sr_log_init (const char* app_name, int flags)
{
    strcpy(g_app_name, app_name);
}

int __sr_print (enum SR_LOG_PRIORITY priority, int line, const char *file, const char *fmt, ...){

    char     msg[MAX_MSG_LEN];
    char     output_msg[MAX_MSG_LEN];
    va_list  args;
    time_t t = time(NULL);
	struct tm tm = *localtime(&t);
    
    /* create msg */
    va_start(args, fmt);
    vsnprintf(msg, MAX_MSG_LEN-1, fmt, args);
    va_end(args);
    msg[MAX_MSG_LEN - 1] = 0;
    /* create final message */
    snprintf(output_msg, MAX_MSG_LEN-1, "%d-%d-%d %d:%d:%d %s %s[%d] %s\n", tm.tm_mday, tm.tm_mon + 1,tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,g_app_name,file_basename(file), line, msg);
    
    output_msg[MAX_MSG_LEN - 1] = 0;
    fprintf (stderr, "[%s] %s", log_level_str[priority], output_msg);
}

int sr_net_init (/*hardcoded for now...*/){
    struct pollfd poll_set[2];
    int fd_index, numfds=0;
    int idle_timer, msg_len;
    nlh = NULL; //Dangling pointer ;)

    sock_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_USER);
    if (sock_fd < 0)
        return -1;

    memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */

    bind(sock_fd, (struct sockaddr *)&src_addr, sizeof(src_addr));

    memset(&dest_addr, 0, sizeof(dest_addr));
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; /* For Linux Kernel */
    dest_addr.nl_groups = 0; /* unicast */

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;

    strcpy(NLMSG_DATA(nlh), "Registration & Configuration");

    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    sr_print(LOG_INFO, "Sending message to kernel...\n");
    //printf("Sending message to kernel...\n");
    sendmsg(sock_fd, &msg, 0);

	// Receive loop
	poll_set[0].fd = sock_fd;
	poll_set[0].events = POLLIN;
	numfds++;
	
	idle_timer = 30; // total time in 10 seconds multiples - 5 Minutes

	while (idle_timer) {
		int fd_index;

		if (poll(poll_set, numfds, 10000)) {
			for (fd_index = 0; fd_index < numfds; fd_index++) {
				if ((poll_set[fd_index].revents & POLLIN ) && 
						(poll_set[fd_index].fd == sock_fd)) {
					/* Read message from kernel */
					msg_len = recvmsg(sock_fd, &msg, 0);
					sr_print(LOG_INFO, "%s",NLMSG_DATA(nlh));
					//printf("Kernel message[%d bytes]:\n%s\n", nlh->nlmsg_len-sizeof(struct nlmsghdr), NLMSG_DATA(nlh));
				} else {
					//printf("Poll failure - event %d\n", poll_set[fd_index].revents);
					sr_print(LOG_ERR,"Poll failure - event %d\n", poll_set[fd_index].revents); 
				}
			}
		} else { // timed out
			idle_timer --;
		}
	}
	//printf("Poll timed out\n");
	sr_print(LOG_ERR,"Poll timed out\n");
	close(sock_fd);
}
