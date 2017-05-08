#include "sr_log.h" /* this file comes from kernel folder. mutual file between kernel and user space */
#include "sal_linux_engine.h"

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
    snprintf(output_msg, MAX_MSG_LEN-1, "%d-%d-%d %d:%d:%d %s %s[%d] %s\n",
		tm.tm_mday, tm.tm_mon + 1,tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec,g_app_name,file_basename(file), line, msg);
    
    output_msg[MAX_MSG_LEN - 1] = 0;
    fprintf (stderr, "[%s] %s", log_level_str[priority], output_msg);
}

int sr_net_init (/*hardcoded for now...*/){

    char *sr_msg;
	
    sock_fd = sal_socket(PROTOCOL_RAW, NETLINK_USER); //this function for userspace only, cannot be used in kernel module!!
    if (sock_fd < 0)
        return -1;

    sal_bind(sock_fd);
	
	sr_msg = "Ping from userspcae!!";
	
    sal_sendmsg(sock_fd,sr_msg); //sending msg to kernel space
	
	return sal_recvmsg_loop(); // Receive loop from kernel
}
