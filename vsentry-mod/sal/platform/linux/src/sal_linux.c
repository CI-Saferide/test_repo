/* file: sal_linux.c
 * purpose: this file implements the sal functions for linux os
*/

#include "sal_linux.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"

SR_32 sal_task_stop(void *data)
{
	struct task_struct *thread = (struct task_struct *)data;

	if (!thread) {
		sal_printf("sal_task_stop: invalid argument %p\n", data);
		return SR_ERROR;
	}

	kthread_stop(thread);

	thread = NULL;

	return SR_SUCCESS;
}

SR_32 sal_task_start(void **data, SR_32 (*task_func)(void *data))
{
	struct task_struct *thread;

	thread = kthread_create(task_func, NULL, "vsentry kernel thread");
	if (IS_ERR(thread)) {
		sal_printf("sal_task_start: failed to create new thread\n");
		return SR_ERROR;
	}

	*data = thread;

	sal_printf("sal_task_start: new task was created 0x%p 0x%p\n", thread, data);

	return SR_SUCCESS;
}

void sal_schedule_timeout(SR_U32 timeout)
{
	schedule_timeout_interruptible(usecs_to_jiffies(timeout));
}

void sal_schedule(void)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule();
}

void *sal_memcpy(void *dest, void *src, SR_32 len)
{
	return memcpy(dest, src, len);
}

void *sal_memset(void *dest, SR_8 ch, SR_32 len)
{
	return memset(dest, ch, len);
}

SR_8 *sal_strcpy(SR_8 *dest, SR_8 *src)
{
	return strcpy(dest, src);
}

SR_32 sal_sprintf(SR_8 *str, SR_8 *fmt, ...)
{
	int i;
	va_list  args;

	va_start(args, fmt);
	i = vsnprintf(str, (SR_MAX_LOG-1), fmt, args);
	va_end(args);

	return i;
}

void sal_printf(SR_8 *fmt, ...)
{
	int i;
	va_list args;
	SR_8 msg[SR_MAX_LOG];

	va_start(args, fmt);
	i = vsnprintf(msg, SR_MAX_LOG-1, fmt, args);
	va_end(args);

	msg[SR_MAX_LOG - 1] = 0;
	printk("%s", msg);
}

// NETWORK functions
SR_U16 sal_packet_dest_port(void *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tcp_header = NULL;
        struct udphdr *udp_header = NULL;
	if (ip_header->protocol == 6) {
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		return ((unsigned int)ntohs(tcp_header->dest));
	} else if (ip_header->protocol == 17) {
		udp_header = (struct udphdr *)skb_transport_header(skb);
		return ((unsigned int)ntohs(udp_header->dest));
	} else {
		return 0;
	}
}
SR_U16 sal_packet_src_port(void *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tcp_header = NULL;
        struct udphdr *udp_header = NULL;
	if (ip_header->protocol == 6) {
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		return ((unsigned int)ntohs(tcp_header->source));
	} else if (ip_header->protocol == 17) {
		udp_header = (struct udphdr *)skb_transport_header(skb);
		return ((unsigned int)ntohs(udp_header->source));
	} else {
		return 0;
	}
}

SR_U16 sal_packet_ip_proto(void *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	return (ip_header->protocol);
}

SR_U16 sal_packet_src_addr(void *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	return ntohl(ip_header->saddr);
}

SR_U16 sal_packet_dest_addr(void *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	return ntohl(ip_header->daddr);
}

// Time functions
SR_U32 sal_get_curr_time(void)
{
	struct timespec ts;
        getnstimeofday(&ts);
	return (ts.tv_sec);
}
SR_U32 sal_get_curr_time_nsec(void)
{
	struct timespec ts;
        getnstimeofday(&ts);
	return (ts.tv_nsec);
}
