#include "sr_netlink.h"

struct sock *nl_sk = NULL;
int sr_vsentryd_pid = 0;

static void nl_recv_msg(struct sk_buff *skb)
{
    struct nlmsghdr *nlh;
    int pid;
    struct sk_buff *skb_out;
    int msg_size;
    char *msg = "vSentry Kernel Module Alive\n";
    int res;

    msg_size = strlen(msg);

    nlh = (struct nlmsghdr *)skb->data;
    //printk(KERN_DEBUG "Netlink received msg payload:%s\n", (char *)nlmsg_data(nlh));
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

    res = nlmsg_unicast(nl_sk, skb_out, pid);
    if (res < 0)
        printk(KERN_INFO "error while sending keepalive to user\n");
}

int nl_tx_msg(char *msg, int msg_len)
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

    ret = nlmsg_unicast(nl_sk, skb_out, sr_vsentryd_pid);
    if (ret < 0) {
	sr_vsentryd_pid = 0;	
        printk(KERN_INFO "error while sending msg to user (%d)\n", ret);
	return -1;
    }

    return 0;

}

struct netlink_kernel_cfg cfg = {
	.input = nl_recv_msg,
};

int sr_netlink_init(void)
{
    //nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, 0, nl_recv_msg, NULL, THIS_MODULE);

    nl_sk = netlink_kernel_create(&init_net, NETLINK_USER, &cfg);
    if (!nl_sk) {
        printk(KERN_ALERT "error creating socket.\n");
        return -10;
    }

    return 0;
}

void sr_netlink_exit(void){

    printk(KERN_INFO "netlink socket released!\n");
    netlink_kernel_release(nl_sk);
}
