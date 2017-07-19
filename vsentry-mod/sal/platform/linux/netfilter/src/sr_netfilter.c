#include "linux/module.h"
#include "linux/skbuff.h"
#include "linux/kernel.h"
#include "linux/udp.h"
#include "linux/tcp.h"
#include "linux/ip.h"
#include "linux/netfilter.h"
#include "linux/netfilter_ipv4.h"
#include "sr_sal_common.h"
#include "sr_scanner_det.h"
#include "sr_classifier.h"
#include "event_mediator.h"

#ifdef CONFIG_NETFILTER

/* hook types are NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING */


unsigned int sr_netfilter_hook_fn(void *priv,
                    struct sk_buff *skb,          
                    const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

	if ( ((ip_header->protocol == IPPROTO_TCP) && ((struct tcphdr *)skb_transport_header(skb))->syn) || (ip_header->protocol == IPPROTO_UDP)) {
		if(sr_scanner_det_rcv(skb)==SR_CLS_ACTION_DROP)
			return NF_DROP;
	}
	if ((ip_header->protocol == IPPROTO_TCP) && (((struct tcphdr *)skb_transport_header(skb))->syn)&&!(((struct tcphdr *)skb_transport_header(skb))->ack)) {
		if (vsentry_incoming_connection(skb) == SR_CLS_ACTION_DROP) {
			return NF_DROP;
		}
	}

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

    sal_printf("Registering netfilter hooks!\n");
    return 0;
}

void sr_netfilter_uninit(void)
{
	nf_unregister_hook(&nfho);
    sal_printf("Unregistering netfilter hooks!\n");
}

#endif
