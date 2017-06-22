#ifndef SAL_LINUX_H
#define SAL_LINUX_H

#include <linux/kernel.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/string.h>

#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wdeclaration-after-statement"
#pragma GCC diagnostic pop

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

#endif /* SAL_LINUX_H*/
