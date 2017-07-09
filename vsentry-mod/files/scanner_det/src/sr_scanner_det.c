#include "dispatcher.h"
#include "sal_module.h"
#include "sal_bitops.h"
#include "sr_radix.h"
#include "sr_cls_file.h"
#include "sr_classifier.h"
#include "sr_sal_common.h"
#ifdef LINUX
#include "sal_linux.h"
#endif // LINUX
#include "sr_scanner_det.h"
#include "sal_bitops.h"

unsigned long last_time;
SR_BOOL scan_detected = 0;
unsigned long scan_start = 0;
SR_U32 scan_source = 0;
SR_U32 source_counter = 0;
SR_U32 scan_counter = 0;
bit_array udp_port_histogram;
bit_array tcp_port_histogram;
int cnt=0;

void sr_scanner_det_init(void) 
{
	struct timespec ts;

	getnstimeofday(&ts);
	memset(&udp_port_histogram, 0, sizeof(udp_port_histogram));
	memset(&tcp_port_histogram, 0, sizeof(udp_port_histogram));
	scan_counter = 0;
	last_time = ts.tv_sec;
}

int scanner_suspicious_conn(void *skb)
{
	// Check attack source
	if (sal_packet_src_port(skb) == scan_source) {
		source_counter++;
	} else {
		scan_source = sal_packet_src_port(skb);
		source_counter = 1;
	}

	if (sal_get_curr_time() > last_time) {
		last_time = sal_get_curr_time();
		//printk(KERN_INFO "SR UDP rate for last second was %d\n", scan_counter);
		scan_counter = 1;
		memset(&udp_port_histogram, 0, sizeof(udp_port_histogram));
		memset(&tcp_port_histogram, 0, sizeof(udp_port_histogram));
		source_counter = scan_source = 0;

	} else if (++scan_counter > MAX_SCAN_RATE) { // re-engage if still above threshold for this second
		scan_start = sal_get_curr_time();
		if (!scan_detected) {
			if (source_counter < scan_counter/3) { // heuristic number - could be anything...
				printk(KERN_INFO "SR Detected port scan. initiating counter measures\n");
			} else {
				unsigned int src_ip = sal_packet_src_addr(skb);
				printk(KERN_INFO "SR Detected port scan from source %02d.%02d.%02d.%02d. initiating counter measures\n",
					(src_ip&0xff000000)>>24, (src_ip&0x00ff0000)>>16, (src_ip&0xff00)>> 8, src_ip&0xff);
			}
			scan_detected = 1;
		}
	}

	if (sal_get_curr_time() < (scan_start + SR_SCAN_DURATION)) {
		// Still under attack, drop packet
		//if (!(++cnt%256)) printk(KERN_INFO "SR dropping UDP packet\n");
		return NF_DROP;
	} else {
		//printk(KERN_INFO "SR port scan is over\n");
		scan_detected = 0;
	}
	return NF_ACCEPT;
}

int sr_scanner_det_rcv(void *skb)
{
	unsigned int dest_port = 0;

	if (sal_packet_ip_proto(skb) == 6) {
		dest_port = sal_packet_dest_port(skb);

		if (!sal_bit_array_is_set( dest_port % SR_MAX_RULES, &tcp_port_histogram)) {
			sal_set_bit_array(dest_port % SR_MAX_RULES, &tcp_port_histogram);
			return(scanner_suspicious_conn(skb));
		}
	} else { // UDP packet
		dest_port = sal_packet_dest_port(skb);

		if (!sal_bit_array_is_set( dest_port % SR_MAX_RULES, &udp_port_histogram)) {
			sal_set_bit_array(dest_port % SR_MAX_RULES, &udp_port_histogram);
			return(scanner_suspicious_conn(skb));
		}
	}
	return NF_ACCEPT;
}
