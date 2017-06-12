/* file: sal_linux.c
 * purpose: this file implements the sal functions for linux os
*/
#include "multiplexer.h"

#ifdef PLATFORM_LINUX
#include "sal_errno.h"
#include "sal_linux.h"
#include <linux/delay.h>

_sock_recv_cb_t _sal_sock_recv_cb[MAX_SUPPORTED_SOCKETS];

struct sock *sal_sock = NULL;
struct sock *sal_log_sock = NULL;
struct netlink_kernel_cfg cfg[2];

int sr_vsentryd_pid = 0;

static void sal_recv_msg(struct sk_buff *skb)
{
    int index = 0; //To decide which CALLBACK function to use

	struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "vSentry Kernel Module Alive\n";
    int res;

    msg_size = strlen(msg);
    printk("sal_recv_msg: Entry\n");

    nlh = (struct nlmsghdr *)skb->data;
    sr_vsentryd_pid = nlh->nlmsg_pid; /*pid of sending process */
    printk(KERN_DEBUG "Netlink received payload(PID: %d):%s\n",sr_vsentryd_pid, (char *)nlmsg_data(nlh));

    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = nlmsg_unicast(sal_sock, skb_out, sr_vsentryd_pid);
    if (res < 0)
        printk(KERN_INFO "error while sending keepalive to sr-engine\n");

	_sal_sock_recv_cb[index]((char *)nlmsg_data(nlh)); //TESTING THE CALLBACK

}

int sal_socket_tx_msg(int socket_index, CEF_payload payload, int payload_size)
{
	struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
	int ret;

    if(!sr_vsentryd_pid) { // Daemon not connected
		return 0; 
    }

    skb_out = nlmsg_new(payload_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "failed to allocate new skb\n");
        return -1;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, payload_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    memcpy(nlmsg_data(nlh), &payload, payload_size);
	//nlmsg_unicast() takes ownership of the skb and frees it itself.
    ret = nlmsg_unicast(sal_sock, skb_out, sr_vsentryd_pid);
    if (ret < 0) {
		
		switch (ret) {
			case -ECONNREFUSED:
				printk ("errno %d: -ECONNREFUSED failed to tx message: %s\n",ret,payload.extension);
				break;
			case -EPERM:
				printk ("errno %d: -EPERM failed to tx message: %s\n",ret,payload.extension);
				break;
			case -ENOMEM:
				printk ("errno %d: -ENOMEM failed to tx message: %s\n",ret,payload.extension);
				break;
			case -EAGAIN:
				printk ("errno %d: -EAGAIN failed to tx message: %s\n",ret,payload.extension);
				break;
			case -ERESTARTSYS:
				printk ("errno %d: -ERESTARTSYS failed to tx message: %s\n",ret,payload.extension);
				break;
			case -EINTR:
				printk ("errno %d: -EINTR failed to tx message: %s\n",ret,payload.extension);
				break;
			default:
				printk ("errno %d: failed to tx message: %s\n",ret,payload.extension);
				break;
				
		}
		//printk(KERN_ERR "sr_vsentryd_pid: %d\n",sr_vsentryd_pid);		
		//sr_vsentryd_pid = 0;
		skb_out = NULL;		
		return -1;
    }
    return 0;
}

int sal_kernel_socket_init(int socket_index, int port, _sock_recv_cb_t sal_sock_recv_cb)
{
	cfg[socket_index].input = sal_recv_msg;
	
	_sal_sock_recv_cb[socket_index] = sal_sock_recv_cb; /*Registering the callback*/
	
	if(	socket_index == MAIN_SOCKET_INDEX){
		sal_sock = netlink_kernel_create(&init_net, port, (struct netlink_kernel_cfg *)&cfg);
		if (!sal_sock ) {
			printk(KERN_ALERT "error creating socket on port:%d.\n",port);
			return -10;
		}
	}	
	/*
	if(	socket_index == LOG_SOCKET_INDEX){
		sal_log_sock = netlink_kernel_create(&init_net, port, &cfg);
		if (!sal_log_sock ) {
			printk(KERN_ALERT "error creating socket on port:%d.\n",port);
			return -10;
		}		
	}*/

	return 0;
}

void sal_kernel_socket_exit(int socket_index)
{
	netlink_kernel_release(sal_sock);
	//netlink_kernel_release(sal_log_sock);
}
#endif /* #ifdef PLATFORM_LINUX */
