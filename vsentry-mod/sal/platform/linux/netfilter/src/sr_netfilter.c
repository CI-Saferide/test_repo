#include "linux/module.h"
#include "linux/skbuff.h"
#include "linux/kernel.h"
#include "linux/udp.h"
#include "linux/tcp.h"
#include "linux/ip.h"
#include "linux/netfilter.h"
#include "linux/netfilter_ipv4.h"

#ifdef CONFIG_NETFILTER

/* hook types are NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING */

unsigned int sr_netfilter_hook_fn(void *priv,
                    struct sk_buff *skb,          
                    const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	unsigned int src_ip = (unsigned int)ip_header->saddr;
	unsigned int dest_ip = (unsigned int)ip_header->daddr;
	struct udphdr *udp_header;
 
   struct tcphdr *tcp_header;
	unsigned int src_port = 0;

	unsigned int dest_port = 0;

	/***get src and dest port number***/
	if (ip_header->protocol==17) {

		udp_header = (struct udphdr *)skb_transport_header(skb);

		src_port = (unsigned int)ntohs(udp_header->source);
		dest_port = (unsigned int)ntohs(udp_header->dest);

	} else if (ip_header->protocol == 6) {

		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		src_port = (unsigned int)ntohs(tcp_header->source);

		dest_port = (unsigned int)ntohs(tcp_header->dest);

	}
	printk(KERN_INFO "IN packet info: src ip: %x, src port: %x; dest ip: %x, dest port: %x; proto: %un", src_ip, src_port, dest_ip, dest_port, ip_header->protocol); 

	return NF_ACCEPT;
}

struct nf_hook_ops nfho;

int sr_netfilter_init(void)
{
	nfho.hook = sr_netfilter_hook_fn;
	nfho.hooknum = NF_INET_LOCAL_IN;
	nfho.pf = PF_INET;     
	nfho.priority = NF_IP_PRI_FIRST;    
	nf_register_hook(&nfho);         // Register the hook

    printk(KERN_INFO "Registering netfilter hooks!\n");
    return 0;
}

void sr_netfilter_uninit(void)
{
	nf_unregister_hook(&nfho);
    printk(KERN_INFO "Unregistering netfilter hooks!\n");
}

#endif
