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
#include "sr_stat_port.h"
#endif
#include "sr_cls_sk_process.h"
#include "sr_cls_conn_obj.h"

#ifdef CONFIG_NETFILTER

/* hook types are NF_INET_PRE_ROUTING, NF_INET_LOCAL_IN, NF_INET_FORWARD, NF_INET_LOCAL_OUT, NF_INET_POST_ROUTING */

unsigned int sr_netfilter_hook_fn(void *priv,
                    struct sk_buff *skb,          
                    const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	disp_info_t disp = {};
	struct tcphdr *tcp_header;
	sr_connection_id_t con_id;
#ifdef SR_STAT_ANALYSIS_DEBUG
	static int non_uc;
#endif

	if (SR_FALSE == vsentry_get_state()) 
		return NF_ACCEPT;

	/*if ( ((ip_header->protocol == IPPROTO_TCP) && ((struct tcphdr *)skb_transport_header(skb))->syn) || (ip_header->protocol == IPPROTO_UDP)) {
		if(sr_scanner_det_rcv(skb)==SR_CLS_ACTION_DROP)
			return NF_DROP;
	}*/
	if ((ip_header->protocol == IPPROTO_TCP) && (((struct tcphdr *)skb_transport_header(skb))->syn)&&!(((struct tcphdr *)skb_transport_header(skb))->ack)) {
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		con_id.daddr.v4addr = ntohl(ip_header->saddr); // This is the remote address
		con_id.saddr.v4addr = ntohl(ip_header->daddr); // This is the local address
		con_id.dport = ntohs(tcp_header->source); // This is the remote port
		con_id.sport = ntohs(tcp_header->dest); // This is the local port
		con_id.ip_proto = IPPROTO_TCP;

		if (sr_conn_obj_hash_get(&con_id, SR_TRUE)) {
			return NF_ACCEPT;
		}
		if (vsentry_incoming_connection(skb) == SR_CLS_ACTION_DROP) {
			return NF_DROP;
		}
		if (sr_conn_obj_hash_insert(&con_id, SR_TRUE) == SR_ERROR) {
			return NF_DROP;
		}
	}

	if (ip_header->protocol == IPPROTO_UDP) {
		struct udphdr *udp_header;

		udp_header = (struct udphdr *)skb_transport_header(skb);
		disp.tuple_info.daddr.v4addr.s_addr = ntohl(ip_header->daddr);
		disp.tuple_info.saddr.v4addr.s_addr = ntohl(ip_header->saddr);
		disp.tuple_info.sport = ntohs(udp_header->source);
		disp.tuple_info.dport = ntohs(udp_header->dest);
		disp.tuple_info.ip_proto = IPPROTO_UDP;
		disp.tuple_info.size = ntohs(udp_header->len) - UDP_HLEN;
#ifdef CONFIG_STAT_ANALYSIS
		disp.tuple_info.id.pid = sr_stat_port_find_pid(disp.tuple_info.dport);
#endif
		con_id.daddr.v4addr = ntohl(ip_header->saddr); // This is the remote address
		con_id.saddr.v4addr = ntohl(ip_header->daddr); // This is the local address
		con_id.dport = ntohs(udp_header->source); // This is the remote port
		con_id.sport = ntohs(udp_header->dest); // This is the local port
		con_id.ip_proto = IPPROTO_UDP;

		if (sr_conn_obj_hash_get(&con_id, SR_TRUE)) {
			return NF_ACCEPT;
		}

		if (disp_ipv4_recvmsg(&disp) != SR_CLS_ACTION_ALLOW)
			return NF_DROP;

		if (sr_conn_obj_hash_insert(&con_id, SR_TRUE) == SR_ERROR) {
			return NF_DROP;
		}
	}

#ifdef CONFIG_STAT_ANALYSIS
	if ((ip_header->protocol == IPPROTO_TCP && !((struct tcphdr *)skb_transport_header(skb))->syn) ||
		ip_header->protocol == IPPROTO_UDP) {
		sr_connection_data_t *conp, con = {};
		struct udphdr *udp_header;

		con.con_id.saddr.v4addr = ntohl(ip_header->saddr);
		con.con_id.daddr.v4addr = ntohl(ip_header->daddr);
		if (con.con_id.daddr.v4addr == INADDR_BROADCAST) {
			// Hnalde broadcast
#ifdef SR_STAT_ANALYSIS_DEBUG
			non_uc ++;
			if (non_uc % 100 == 0)
				CEF_log_event(SR_CEF_CID_SYSTEM, "Stat dropped broadcast" , SEVERITY_LOW,
							"%s=dropped BC :%x count:%d",MESSAGE,
							con.con_id.saddr.v4addr, non_uc);
#endif
			return NF_ACCEPT;
		}
		if (IN_MULTICAST(con.con_id.daddr.v4addr)) {
			// Hnalde Multicast
#ifdef SR_STAT_ANALYSIS_DEBUG
			non_uc ++;
			if (non_uc % 100 == 0)
				CEF_log_event(SR_CEF_CID_SYSTEM, "Stat dropped broadcast" , SEVERITY_LOW,
							"%s=dropped BC :%x count:%d",MESSAGE,
							con.con_id.saddr.v4addr, non_uc);
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

unsigned int sr_netfilter_out_hook_fn(void *priv,
                    struct sk_buff *skb,          
                    const struct nf_hook_state *state)
{
	struct iphdr *ip_header;
	struct udphdr *udp_header;
	disp_info_t disp = {};
	sk_process_item_t *process_info_p;
	sr_connection_data_t *conp, con = {};

	if (SR_FALSE == vsentry_get_state()) 
		return NF_ACCEPT;

	if (!skb)
		return NF_ACCEPT;

	ip_header = (struct iphdr *)skb_network_header(skb);

	if (!ip_header || !ip_header->daddr || !ip_header->saddr)
		return NF_ACCEPT;
	if (ip_header->protocol == IPPROTO_UDP) {
		udp_header = (struct udphdr *)skb_transport_header(skb);
		disp.tuple_info.daddr.v4addr.s_addr = ntohl(ip_header->daddr);
		disp.tuple_info.saddr.v4addr.s_addr = ntohl(ip_header->saddr);
		disp.tuple_info.sport = ntohs(udp_header->source);
		disp.tuple_info.dport = ntohs(udp_header->dest);
		disp.tuple_info.ip_proto = IPPROTO_UDP;
		disp.tuple_info.size = ntohs(udp_header->len) - UDP_HLEN;
		if ((process_info_p = sr_cls_sk_process_hash_get(skb->sk))) {
			disp.tuple_info.id.pid = process_info_p->process_info.pid;
			disp.tuple_info.id.uid = process_info_p->process_info.uid;
		}
		con.con_id.daddr.v4addr = ntohl(ip_header->daddr); 
		con.con_id.saddr.v4addr = ntohl(ip_header->saddr);
		con.con_id.dport = ntohs(udp_header->dest); 
		con.con_id.sport = ntohs(udp_header->source);
		con.con_id.ip_proto = IPPROTO_UDP;
		con.is_outgoing = SR_TRUE;

		if ((con.con_id.dport == 53 || con.con_id.sport == 53)) {
			if ((conp = sr_stat_connection_lookup(&con.con_id))) {
				sr_stat_connection_update_counters(conp, 0, con.rx_bytes, con.rx_msgs, 0, 0);
			} else {
				sr_stat_connection_insert(&con, SR_CONNECTION_NONBLOCKING | SR_CONNECTION_ATOMIC);
			}
		}

		if (sr_conn_obj_hash_get(&con.con_id, SR_TRUE)) {
			return NF_ACCEPT;
		}

		if (disp_ipv4_sendmsg(&disp) != SR_CLS_ACTION_ALLOW)
			return NF_DROP;

		if (sr_conn_obj_hash_insert(&con.con_id, SR_TRUE) == SR_ERROR) {
			return NF_DROP;
		}
	}

	return NF_ACCEPT;
}

struct nf_hook_ops nfho;
struct nf_hook_ops nfh_tx;

int sr_netfilter_init(void)
{
	nfho.hook = sr_netfilter_hook_fn;
	nfho.hooknum = NF_INET_LOCAL_IN;
	nfho.pf = PF_INET;     
	nfho.priority = NF_IP_PRI_FIRST;    
	nf_register_hook(&nfho);         // Register the hook

	nfh_tx.hook = sr_netfilter_out_hook_fn;
	nfh_tx.hooknum = NF_INET_LOCAL_OUT;
	nfh_tx.pf = PF_INET;     
	nfh_tx.priority = NF_IP_PRI_FIRST;    
	nf_register_hook(&nfh_tx);         // Register the hook

    sal_kernel_print_info("Registering netfilter hooks!\n");
    return 0;
}

void sr_netfilter_uninit(void)
{
	nf_unregister_hook(&nfho);
	nf_unregister_hook(&nfh_tx);
    sal_kernel_print_info("Unregistering netfilter hooks!\n");
}

#endif
