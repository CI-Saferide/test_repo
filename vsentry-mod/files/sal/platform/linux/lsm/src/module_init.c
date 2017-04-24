/* file: module_init.c
 * purpose: this file initialize the kernel module
*/

#include "sr_netlink.h"
#include "sr_lsm_hooks.h"

MODULE_LICENSE("proprietary");
MODULE_DESCRIPTION("vSentry Kernel Module");
#define MODULE_NAME	"vsentry"

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
	sr_netlink_init();
	return rc;//Non-zero return means that the module couldn't be loaded.
}

static void __exit vsentry_cleanup(void)
{
	sr_netlink_exit();	
	#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
		unregister_lsm_hooks();
	#else
		reset_security_ops();
	#endif
	printk(KERN_INFO "[%s]: module released!\n", MODULE_NAME);
}

module_init(vsentry_init);
module_exit(vsentry_cleanup);
