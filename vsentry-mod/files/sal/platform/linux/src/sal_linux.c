/* file: sal_linux.c
 * purpose: this file implements the sal functions for linux os
*/

#include "sal_errno.h"
#include "sal_linux.h"

#ifdef PLATFORM_LINUX

_sock_recv_cb_t _sal_sock_recv_cb[MAX_SUPPORTED_SOCKETS];

struct sock *sal_sock = NULL;
struct netlink_kernel_cfg cfg;

int sr_vsentryd_pid = 0;


static void sal_recv_msg(struct sk_buff *skb)
{
    int index = 0;

	struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "vSentry Kernel Module Alive\n";
    int res;
    
    //while (skb->sk != &sal_sock[index])
	//index++;

    msg_size = strlen(msg);

    nlh = (struct nlmsghdr *)skb->data;
    printk(KERN_DEBUG "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
    pid = nlh->nlmsg_pid; /*pid of sending process */

    sr_vsentryd_pid = nlh->nlmsg_pid;


    skb_out = nlmsg_new(msg_size, 0);
    if (!skb_out) {
        printk(KERN_ERR "failed to allocate new skb\n");
        return;
    }

    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_size, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    strncpy(nlmsg_data(nlh), msg, msg_size);

    res = nlmsg_unicast(sal_sock, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO "error while sending keepalive to user\n");


	_sal_sock_recv_cb[index]((char *)nlmsg_data(nlh)); //TESTING THE CALLBACK
}

int sal_socket_tx_msg(int socket_index, char *msg, int msg_len)
{
    struct nlmsghdr *nlh;
    struct sk_buff *skb_out;
	int ret;

    if (!sr_vsentryd_pid) { // Daemon not connected
		return 0; 
    }

    skb_out = nlmsg_new(msg_len, 0);
    if (!skb_out) {
        printk(KERN_ERR "failed to allocate new skb\n");
        return -1;
    }
    nlh = nlmsg_put(skb_out, 0, 0, NLMSG_DONE, msg_len, 0);
    NETLINK_CB(skb_out).dst_group = 0; /* not in mcast group */
    memcpy(nlmsg_data(nlh), msg, msg_len);

    ret = nlmsg_unicast(sal_sock, skb_out, sr_vsentryd_pid);
    if (ret < 0) {
		sr_vsentryd_pid = 0;	
        printk(KERN_INFO "error while sending msg to user (%d)\n", ret);
		return -1;
    }

    return 0;

}

int sal_kernel_socket_init(int socket_index, int port, _sock_recv_cb_t sal_sock_recv_cb)
{
	cfg.input = sal_recv_msg;
	
	_sal_sock_recv_cb[0] = sal_sock_recv_cb; /*Registering the callback*/
		
	sal_sock = netlink_kernel_create(&init_net, port, &cfg);
	if (!sal_sock) {
        printk(KERN_ALERT "error creating socket on port:%d.\n",port);
        return -10;
    }

	return 0;
}

void sal_kernel_socket_exit(int socket_index)
{
	netlink_kernel_release(sal_sock);
}

void sal_event_cb(void *data)
{
    /* do stuff and things with the event */
    printk(KERN_INFO "TESTING_CALLBACK: %s",(char*)data);
    
}

#endif /* #ifdef PLATFORM_LINUX */
