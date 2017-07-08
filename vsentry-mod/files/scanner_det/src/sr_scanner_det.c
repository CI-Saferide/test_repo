#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_cls_file.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#include "net/tcp.h"
#include "linux/time.h"
#include "sr_scanner_det.h"
#include "sal_bitops.h"

unsigned long last_time;
SR_BOOL scan_detected = 0;
unsigned long scan_start = 0;
SR_U32 scan_source = 0;
SR_U32 source_counter = 0;
SR_U32 scan_counter = 0;
bit_array udp_port_histogram;
int cnt=0;

void sr_scanner_det_init(void) 
{
	struct timespec ts;

	getnstimeofday(&ts);
	memset(&udp_port_histogram, 0, sizeof(udp_port_histogram));
	scan_counter = 0;
	last_time = ts.tv_sec;
}

int scanner_suspicious_conn(struct sk_buff *skb)
{
	struct timespec ts;
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

	getnstimeofday(&ts);
	// Check attack source
	if (ip_header->saddr == scan_source) {
		source_counter++;
	} else {
		scan_source = ip_header->saddr;
		source_counter = 1;
	}

	if (ts.tv_sec > last_time) {
		last_time = ts.tv_sec;
		//printk(KERN_INFO "SR UDP rate for last second was %d\n", scan_counter);
		scan_counter = 1;
		memset(&udp_port_histogram, 0, sizeof(udp_port_histogram));
		source_counter = scan_source = 0;

	} else if (++scan_counter > MAX_SCAN_RATE) { // re-engage if still above threshold for this second
		scan_start = ts.tv_sec;
		if (!scan_detected) {
			if (source_counter < scan_counter/3) { // heuristic number - could be anything...
				printk(KERN_INFO "SR Detected port scan. initiating counter measures\n");
			} else {
				unsigned int src_ip = ntohl((unsigned int)ip_header->saddr);
				printk(KERN_INFO "SR Detected port scan from source %02d.%02d.%02d.%02d. initiating counter measures\n",
					(src_ip&0xff000000)>>24, (src_ip&0x00ff0000)>>16, (src_ip&0xff00)>> 8, src_ip&0xff);
			}
			scan_detected = 1;
		}
	}

	if (ts.tv_sec < (scan_start + SR_SCAN_DURATION)) {
		// Still under attack, drop packet
		return NF_DROP;
	} else {
		//printk(KERN_INFO "SR port scan is over\n");
		scan_detected = 0;
	}
	return NF_ACCEPT;
}

int sr_scanner_det_rcv(struct sk_buff *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tcp_header = NULL;
	struct udphdr *udp_header = NULL;
	unsigned int dest_port = 0;
	struct sock *sk;

	if (ip_header->protocol == 6) {
		tcp_header = (struct tcphdr *)skb_transport_header(skb);

		sk = __inet_lookup_skb(&tcp_hashinfo, skb, tcp_header->source, tcp_header->dest);
		if (!sk) { // closed port, scanner ?
			return (scanner_suspicious_conn(skb));
		}
	} else { // UDP packet
		udp_header = (struct udphdr *)skb_transport_header(skb);

		dest_port = (unsigned int)ntohs(udp_header->dest);
		if (!sal_bit_array_is_set( dest_port % SR_MAX_RULES, &udp_port_histogram)) {
			sal_set_bit_array(dest_port % SR_MAX_RULES, &udp_port_histogram);
			return(scanner_suspicious_conn(skb));
		}
	}
	return NF_ACCEPT;
}
