#ifndef SAL_LINUX_H
#define SAL_LINUX_H

#include "sr_types.h"
#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/string.h>
#include <net/tcp.h>
#include <linux/time.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic pop

// Atomic counters
#define SR_ATOMIC	atomic_t
#define SR_ATOMIC_SET 	atomic_set
#define SR_ATOMIC_INC_RETURN atomic_inc_return

#define SR_RWLOCK	rwlock_t
#define SR_LOCK(x) //(x++)
#define SR_UNLOCK(x) //(x++)
//#define SR_ALLOC(x) kmalloc(x, GFP_KERNEL|GFP_ATOMIC)
#define SR_ALLOC(x) vmalloc(x)
//#define SR_ZALLOC(x) kcalloc(1, x, GFP_KERNEL|GFP_ATOMIC)
#define SR_ZALLOC(x) vzalloc(x)
//#define SR_FREE kfree
#define SR_FREE vfree

/* kernel print definitions */
#define pr_fmt(fmt) fmt
#define sal_kernel_print_emerg(fmt, ...) \
   printk(KERN_EMERG pr_fmt(fmt), ##__VA_ARGS__)
#define sal_kernel_print_alert(fmt, ...) \
	printk(KERN_ALERT pr_fmt(fmt), ##__VA_ARGS__)
#define sal_kernel_print_crit(fmt, ...) \
	printk(KERN_CRIT pr_fmt(fmt), ##__VA_ARGS__)
#define sal_kernel_print_err(fmt, ...) \
	printk(KERN_ERR pr_fmt(fmt), ##__VA_ARGS__)
#define sal_kernel_print_warning(fmt, ...) \
	printk(KERN_WARNING pr_fmt(fmt), ##__VA_ARGS__)
#define sal_kernel_print_warn sal_kernel_print_warning
#define sal_kernel_print_notice(fmt, ...) \
	printk(KERN_NOTICE pr_fmt(fmt), ##__VA_ARGS__)
#define sal_kernel_print_info(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)

#ifdef DEBUG_NETWORK	
#define sal_debug_network(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#else
#define sal_debug_network(fmt, ...)
#endif /* DEBUG_NETWORK */

#ifdef DEBUG_EVENT_MEDIATOR	
#define sal_debug_em(fmt, ...) \
	printk(KERN_INFO pr_fmt(fmt), ##__VA_ARGS__)
#else
#define sal_debug_em(fmt, ...)
#endif /* DEBUG_EVENT_MEDIATOR */

// Network functions
SR_U8 sal_packet_ip_proto(void *skb);
SR_U16 sal_packet_dest_port(void *skb);
SR_U16 sal_packet_src_port(void *skb);
SR_U32 sal_packet_src_addr(void *skb);
SR_U32 sal_packet_dest_addr(void *skb);


// Time functions
SR_U32 sal_get_curr_time(void);
SR_U32 sal_get_curr_time_nsec(void);

// Process functions
SR_U32 sal_get_exec_inode(SR_32 pid);

#endif /* SAL_LINUX_H*/
