#include "linux/module.h"
#include "linux/skbuff.h"
#include "linux/kernel.h"
#include "linux/udp.h"
#include "linux/tcp.h"
#include "linux/ip.h"
#include "linux/netfilter.h"
#include "linux/netfilter_ipv4.h"
#include "linux/ptp_classify.h"
#include "sr_sal_common.h"
#include "sr_scanner_det.h"
#include "sr_classifier.h"
#include "sr_control.h"
#include "event_mediator.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_connection.h"
#endif

#ifdef CONFIG_NETFILTER

/* hook types are NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING */

unsigned int sr_netfilter_hook_fn(void *priv,
                    struct sk_buff *skb,          
                    const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
#ifdef SR_STAT_ANALYSIS_DEBUG
	static int non_uc;
#endif

	if (SR_FALSE == vsentry_get_state()) 
		return NF_ACCEPT;

	if ( ((ip_header->protocol == IPPROTO_TCP) && ((struct tcphdr *)skb_transport_header(skb))->syn) || (ip_header->protocol == IPPROTO_UDP)) {
		if(sr_scanner_det_rcv(skb)==SR_CLS_ACTION_DROP)
			return NF_DROP;
	}
	if ((ip_header->protocol == IPPROTO_TCP) && (((struct tcphdr *)skb_transport_header(skb))->syn)&&!(((struct tcphdr *)skb_transport_header(skb))->ack)) {
		if (vsentry_incoming_connection(skb) == SR_CLS_ACTION_DROP) {
			return NF_DROP;
		}
	}

#ifdef CONFIG_STAT_ANALYSIS
	if ((ip_header->protocol == IPPROTO_TCP && !((struct tcphdr *)skb_transport_header(skb))->syn) ||
		ip_header->protocol == IPPROTO_UDP) {
		sr_connection_data_t *conp, con = {};
		struct tcphdr *tcp_header;
		struct udphdr *udp_header;

		con.con_id.saddr.v4addr = ntohl(ip_header->saddr);
		con.con_id.daddr.v4addr = ntohl(ip_header->daddr);
		if (con.con_id.daddr.v4addr == INADDR_BROADCAST) {
			// Hnalde broadcast
#ifdef SR_STAT_ANALYSIS_DEBUG
			non_uc ++;
			if (non_uc % 100 == 0)
				printk("DROPED BC :%x count:%d \n", con.con_id.saddr.v4addr, non_uc);
#endif
			return NF_ACCEPT;
		}
		if (IN_MULTICAST(con.con_id.daddr.v4addr)) {
			// Hnalde Multicast
#ifdef SR_STAT_ANALYSIS_DEBUG
			non_uc ++;
			if (non_uc % 100 == 0)
				printk("DROPED BC :%x count:%d \n", con.con_id.saddr.v4addr, non_uc);
#endif
			return NF_ACCEPT;
		}

		if (!ip_header->daddr || !ip_header->saddr)
			return NF_ACCEPT;
		con.con_id.ip_proto = ip_header->protocol;
		if (ip_header->protocol == IPPROTO_TCP) { 
			tcp_header = (struct tcphdr *)skb_transport_header(skb);
			if (!tcp_header->dest || !tcp_header->source)
				return NF_ACCEPT;
			con.con_id.dport = ntohs(tcp_header->dest);
			con.con_id.sport = ntohs(tcp_header->source);
			con.rx_bytes = ntohs(ip_header->tot_len) - ip_header->ihl * 4 - tcp_header->doff * 4;
		} else {
			udp_header = (struct udphdr *)skb_transport_header(skb);
			if (!udp_header->dest || !udp_header->source)
				return NF_ACCEPT;
			con.con_id.dport = ntohs(udp_header->dest);
			con.con_id.sport = ntohs(udp_header->source);
			con.rx_bytes = ntohs(udp_header->len) - UDP_HLEN;
		}
		con.rx_msgs = 1;

		if ((conp = sr_stat_connection_lookup(&con.con_id))) {
			sr_stat_connection_update_counters(conp, 0, con.rx_bytes, con.rx_msgs, 0, 0);
		} else {
			if (sr_stat_connection_insert(&con, SR_CONNECTION_NONBLOCKING | SR_CONNECTION_ATOMIC) != SR_SUCCESS) {
				return NF_ACCEPT;
			}
		}
	}
#endif

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
