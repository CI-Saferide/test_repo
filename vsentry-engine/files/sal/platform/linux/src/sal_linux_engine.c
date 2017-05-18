/* 
 * file: sal_linux_engine.c
 * purpose: this file implements the sal functions for linux os
*/

#include "sal_errno.h"
#include "sal_linux_engine.h"
#include "sr_log.h"

#ifdef PLATFORM_LINUX

int sal_socket(SAL_PROTOCOL protocol, int port)
{
	int rc;
	switch (protocol) {
		case PROTOCOL_UDP: 
			rc = socket(PF_NETLINK, SOCK_DGRAM, port); 
			break;
		case PROTOCOL_TCP: 
			rc = socket(PF_NETLINK, SOCK_STREAM, port); 
			break;
		case PROTOCOL_RAW: 
			rc = socket(PF_NETLINK, SOCK_RAW, port);  
			break;
	}
	if(rc > 0)
		return rc;
	return (SAL_SOCKET_ERR + rc);
}

int sal_bind(int fd)
{
	nlh = NULL; //Dangling pointer ;)
	
	memset(&src_addr, 0, sizeof(src_addr));
    src_addr.nl_family = AF_NETLINK;
    src_addr.nl_pid = getpid(); /* self pid */

	if (bind(fd, (struct sockaddr *)&src_addr, sizeof(src_addr))<0) 
    {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }
	
	memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.nl_family = AF_NETLINK;
    dest_addr.nl_pid = 0; // For Linux Kernel
    dest_addr.nl_groups = 0; //unicast 

    nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh->nlmsg_pid = getpid();
    nlh->nlmsg_flags = 0;
    
    iov.iov_base = (void *)nlh;
    iov.iov_len = nlh->nlmsg_len;
    
    msg.msg_name = (void *)&dest_addr;
    msg.msg_namelen = sizeof(dest_addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;	
    
    return 0;// invent some feedback or error code...
}
/*
int sal_bind_log(int fd)
{
	nlh_log = NULL; //Dangling pointer ;)
	
	memset(&src_addr_log, 0, sizeof(src_addr_log));
    src_addr_log.nl_family = AF_NETLINK;
    src_addr_log.nl_pid = getpid(); //self pid 
 
	bind(fd, (struct sockaddr *)&src_addr_log, sizeof(src_addr_log));
	
	
	
	memset(&dest_addr_log, 0, sizeof(dest_addr_log));
    dest_addr_log.nl_family = AF_NETLINK;
    dest_addr_log.nl_pid = 0; // For Linux Kernel
    dest_addr_log.nl_groups = 0; //unicast 

    nlh_log = (struct nlmsghdr *)malloc(NLMSG_SPACE(MAX_PAYLOAD));
    memset(nlh_log, 0, NLMSG_SPACE(MAX_PAYLOAD));
    nlh_log->nlmsg_len = NLMSG_SPACE(MAX_PAYLOAD);
    nlh_log->nlmsg_pid = getpid();
    nlh_log->nlmsg_flags = 0;
    
    iov_log.iov_base = (void *)nlh;
    iov_log.iov_len = nlh->nlmsg_len;
    
    msg_log.msg_name = (void *)&dest_addr;
    msg_log.msg_namelen = sizeof(dest_addr);
    msg_log.msg_iov = &iov;
    msg_log.msg_iovlen = 1;	
    
    return 0;// invent some feedback or error code...
}*/
void sal_sendmsg(int fd,char *data)
{
	strcpy(NLMSG_DATA(nlh), data);
	//sr_print(LOG_INFO, "Sending message to kernel...\n");
	sendmsg(fd, &msg, 0); //sending msg to kernel space
}

int sal_recvmsg(int fd)
{
	 return recvmsg(fd, &msg, 0);
}

#endif /* #ifdef PLATFORM_LINUX */
