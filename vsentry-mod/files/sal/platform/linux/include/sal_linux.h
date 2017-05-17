#ifndef SAL_LINUX_H
#define SAL_LINUX_H


#ifdef PLATFORM_LINUX
#include <linux/kernel.h>
#include <net/sock.h> 

/* variables definitions */
#define SR_U8		unsigned char
#define SR_U16		unsigned short
#define SR_U32		unsigned long
#define SR_8		char
#define SR_16		short
#define SR_32		long
#define SR_BOOL		SR_U8
#define TRUE		1
#define FALSE		0


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
#endif /* PLATFORM_LINUX */

#define MAX_SUPPORTED_SOCKETS		2

typedef void (*_sock_recv_cb_t)(void*);

int  sal_kernel_socket_init(int socket_index, int port, _sock_recv_cb_t sal_sock_recv_cb);
void sal_kernel_socket_exit(int socket_index);
int sal_socket_tx_msg(int socket_index, char *msg, int msg_len);


#endif /* SAL_LINUX_H*/
