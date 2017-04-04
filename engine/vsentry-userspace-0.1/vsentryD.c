#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <poll.h>

#define NETLINK_USER 31

#define MAX_PAYLOAD 1024 /* maximum payload size*/
struct sockaddr_nl src_addr, dest_addr;
struct nlmsghdr *nlh = NULL;
struct iovec iov;
int sock_fd;
struct msghdr msg;

int main(int argc, char *argv[]){

    struct pollfd poll_set[2];
    int fd_index, numfds=0;
    int idle_timer, msg_len;

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

    printf("Sending message to kernel...\n");
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
					printf("Kernel message[%d bytes]:\n%s\n", nlh->nlmsg_len-sizeof(struct nlmsghdr), NLMSG_DATA(nlh));
				} else {
					printf("Poll failure - event %d\n", poll_set[fd_index].revents);
				}
			}
		} else { // timed out
			idle_timer --;
		}
	}
	printf("Poll timed out\n");
	close(sock_fd);
}

