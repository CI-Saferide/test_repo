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

unsigned long  tid[2];
typedef void (*sal_thread_cb_t)(void*);

char g_app_name[20];

char* file_basename(const char* file)
{
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

int __sr_print (enum SR_LOG_PRIORITY priority, int line, const char *file, const char *fmt, ...)
{
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
		tm.tm_mday, tm.tm_mon + 1,tm.tm_year + 1900, 
		tm.tm_hour, tm.tm_min, tm.tm_sec,
		g_app_name,file_basename(file), line, msg);
    
    output_msg[MAX_MSG_LEN - 1] = 0;
    fprintf (stderr, "[%s] %s", log_level_str[priority], output_msg);
}

int sr_net_init (void/*hardcoded for now...*/)
{
    char *sr_msg;
    int err;
	sal_thread_cb_t sal_thread_process_msg;
	
    main_sock_fd = sal_socket(PROTOCOL_RAW, NETLINK_USER);//this function for userspace only, cannot be used in kernel module!! 
    if(main_sock_fd < 0){
		sr_print(LOG_ERR, "failed to create socket on port: %d\n",NETLINK_USER);
		return -1;
	}
	/*
	log_sock_fd = sal_socket(PROTOCOL_RAW, NETLINK_LOG_USER);//this function for userspace only, cannot be used in kernel module!!
	if(log_sock_fd < 0){
		sr_print(LOG_ERR, "failed to create socket on port: %d\n",NETLINK_LOG_USER);
		return -1;
	}	*/							  
  
    sal_bind(main_sock_fd);
    //sal_bind_log(log_sock_fd);
    
	sr_msg = "Ping from userspcae!!";
	
    sal_sendmsg(main_sock_fd,sr_msg); //sending msg to kernel space
    
    err = pthread_create(&(tid[0]), NULL, sal_recvmsg_loop, NULL);
        if (err != 0){
            printf("\ncan't create thread :[%s]", strerror(err));
            return err;
        }else
            printf("\n Thread created successfully\n");
            
	return err;
	//return sal_recvmsg_loop(); // Receive loop from kernel
}

int sal_recvmsg_loop()
{		
	unsigned int ctr = 0;
	int fd_index, numfds=0; 
    int idle_timer, msg_len; 
	struct pollfd poll_set[2];	
	struct CEF_payload *cef;
	/*
	struct pollfd {
	int fd;             * file descriptor for an open file. 
						  in poll function if this is neg value 'events' will be ignored, revents will return as 0
						  possible to use this for temporary stop monitoring one of the fds
						   
	short events;       * The input event flags . 
						* bit mask (flag) to determine the type of events of intrest,
						  example: events =0; 
						  revents will return : POLLHUP || POLLERR || POLLNVAL 
						 						
	short revents;      * The output event flags 
						  filled by the kernel with the events that actually occurred.
  	}; */
			
	poll_set[0].fd = main_sock_fd; 
	poll_set[0].events = POLLIN; // flag that means "There is data to read"
	numfds++; //num of actual fds in poll_set (in our case it's just 1)
	
	while (1) {
		
		/*If none of the events requested (and no error) has occurred for any of the fds in poll_set
			poll() blocks until one of the events occurs. -- this could cause an infinite block 
			timeout : number of milliseconds that poll() should block waiting for any fds to become ready.
				The call will block until either:
					* a file descriptor becomes ready;
					* the call is interrupted by a signal handler; or
					* the timeout expires.
		*/	
		/**
cef example:

CEF:Version|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|Severity|[Extension]

CEF:1.2|SafeRide|vSentry|1.0|100|Malware stopped|10|src=10.0.0.1 dst=2.1.2.2 spt=1232

typedef struct CEF_payload
{   
    float						cef_version;
    char						dev_vendor[32];
    char						dev_product[32];
    float						dev_version;			
	enum dev_event_class_ID		class;
	char						name[32];
    enum severity				sev;
    char 						extension[256]; 
}CEF_payload;
 * **/
		//timeout > 0 : will be in millsecs
		//timeout < 0 :infinite timeout 
		//timeout == 0 : return immediately, even if no file descriptors are ready.		
		if (poll(poll_set, numfds, 0)) {  
			for (fd_index = 0; fd_index < numfds; fd_index++) {
				if ((poll_set[fd_index].revents & POLLIN ))   //check POLLIN specific bit 
					//	&&(poll_set[fd_index].fd == sock_fd))
					{					
					/* Read message from kernel */
					msg_len = sal_recvmsg(main_sock_fd); //also cleans the msghdr!!
					cef = NLMSG_DATA(nlh);
					//sr_print(LOG_INFO, "%s",cef->extension);
					printf("CEF:%.1f|%s|%s|%.1f|%d|%s|%d|%s\n", cef->cef_version,
																cef->dev_vendor,
																cef->dev_product,
																cef->dev_version,
																cef->class,
																cef->name,
																cef->sev,
																cef->extension);
				}else{
					sr_print(LOG_ERR,"Poll failure - event %d\n", poll_set[fd_index].revents); 
				}
			}
		} 
	}
	//close(main_sock_fd);
	
	return 0; //NEED TO RETURN FIXED ERROR CODE
}
