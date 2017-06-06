/* file: module_init.c
 * purpose: this file initialize the kernel module
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/utsname.h>

#include "sr_lsm_hooks.h"
#include "sal_linux.h"
#include "multiplexer.h"

#define MAIN_SOCKET_PORT		31
//#define LOG_SOCKET_PORT			18

#ifdef UNIT_TEST
#include "sal_bitops_test.h"
#endif /* UNIT_TEST */

MODULE_LICENSE("proprietary");
MODULE_DESCRIPTION("vSentry Kernel Module");

static int __init vsentry_init(void)
{	
	int rc = 0;
	
	printk(KERN_INFO "[%s]: module started. kernel version is %s\n",MODULE_NAME, utsname()->release);

	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	rc = register_lsm_hooks();
	if (rc)		
		printk(KERN_INFO "[%s]: registration to lsm failed!\n", MODULE_NAME);
	else
		printk(KERN_INFO "[%s]: registration to lsm succeedded\n", MODULE_NAME);
	#else
	reset_security_ops();
	if (register_security (&vsentry_ops)){
		printk(KERN_INFO "[%s]: registration to lsm failed!\n", MODULE_NAME);
		rc = -EPERM;
	} else {
		printk(KERN_INFO "[%s]: registration to lsm succeedded\n", MODULE_NAME);
	}
	#endif
	sal_kernel_socket_init(MAIN_SOCKET_INDEX, MAIN_SOCKET_PORT, main_socket_process_cb);
	//sal_kernel_socket_init(LOG_SOCKET_INDEX, LOG_SOCKET_PORT, log_socket_process_cb);
#ifdef UNIT_TEST	
	sal_bitops_test (0);
#endif /* UNIT_TEST */
	return rc; //Non-zero return means that the module couldn't be loaded.
}

static void __exit vsentry_cleanup(void)
{
	sal_kernel_socket_exit(MAIN_SOCKET_INDEX);
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
		unregister_lsm_hooks();
	#else
		reset_security_ops();
	#endif
	printk(KERN_INFO "[%s]: module released!\n", MODULE_NAME);
}

module_init(vsentry_init);
module_exit(vsentry_cleanup);
