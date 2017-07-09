/* file: module_init.c
 * purpose: this file initialize the kernel module
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/kthread.h>

#include "sr_lsm_hooks.h"
#include "sal_linux.h"
#include "dispatcher.h"
#include "sr_classifier.h"
#include "sr_cls_port.h"
#include "sr_ring_buf.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_tasks.h"
#include "main_loop.h"
#include "sr_scanner_det.h"

#ifdef UNIT_TEST
#include "sal_bitops_test.h"
#endif /* UNIT_TEST */

MODULE_LICENSE("proprietary");
MODULE_DESCRIPTION("vSentry Kernel Module");

static dev_t vsentry_dev;
static struct cdev *cdev_p;

extern int sr_netfilter_init(void);
extern void sr_netfilter_uninit(void);

int sr_vsentryd_pid = 0;

#if 0
static struct task_struct *tx_thread;
#endif

/* mmap fops callback */
static int vsentry_drv_mmap(struct file *file, struct vm_area_struct *vma)
{
	int ret;
	long length = vma->vm_end - vma->vm_start;
	sr_shmem *vsshmem;
	int type;
	struct task_struct *thread = NULL;

	pr_info("vsentry PID = %d\n",sr_vsentryd_pid);
	if (!sr_vsentryd_pid)
		sr_vsentryd_pid = current->pid;
		pr_info("vsentry PID = %d\n",sr_vsentryd_pid);

	pr_info("vsentry_drv_mmap length = %ld, vm_start 0x%p\n", length, (void *) vma->vm_start);

	switch (vma->vm_pgoff) {
		case ENG2MOD_PAGE_OFFSET:
			type = ENG2MOD_BUF;
			pr_info("vsentry_drv_mmap: initializing rx_buff\n");
			thread = sr_task_get_data(SR_MODULE_TASK);
			pr_info("vsentry_drv_mmap: thread 0x%p\n", thread);
			break;
		case MOD2ENG_PAGE_OFFSET:
			type = MOD2ENG_BUF;
			pr_info("vsentry_drv_mmap: initializing tx_buff\n");
			break;
		case LOG_BUF_PAGE_OFFSET:
			type = LOG_BUF;
			pr_info("vsentry_drv_mmap: initializing log_buff\n");
			break;
		default:
			pr_err("wrong offset %lu\n", vma->vm_pgoff);
			return -EINVAL;
	}

	/* get the pages */
	vsshmem = sr_msg_get_buf(type);
	if (vsshmem->buffer) {
		pr_err("buffer[%d] already allocated\n", type);
		return -EIO;
	}

	ret = sr_msg_alloc_buf(type, length);
	if (ret < 0) {
		pr_err("failed to allocate memory on offset %lu\n", vma->vm_pgoff);
		return -EIO;
	}

	/* remap pages to user space process */
	ret = remap_pfn_range(vma, vma->vm_start, virt_to_phys((void *)vsshmem->buffer) >> PAGE_SHIFT,
		length, vma->vm_page_prot);
	if (ret < 0) {
		pr_err ("failed to remap ... %d\n", ret);
		sr_msg_free_buf(type);
		return ret;
	}

	/* when buffer is allocated we can start write events */
	if (thread)
		wake_up_process(thread);

	return 0;
}

/* dummy read fops callback */
static ssize_t vsentry_drv_read(struct file *file, char __user * buffer, size_t length,
	loff_t * offset)
{
	return 0;
}

/* close fops callback */
int vsentry_drv_release (struct inode *inode, struct file *file)
{
	int i;
	sr_shmem* vsshmem;

	pr_info("vsentry_drv_release ... freeing all allocated memory\n");
	sr_vsentryd_pid = 0;
	for (i=0; i<TOTAL_BUFS; i++) {
		vsshmem = sr_msg_get_buf(i);
		if (vsshmem->buffer)
			sr_msg_free_buf(i);
	}

	return 0;
}

static struct file_operations vsentry_file_ops = {
	.owner = THIS_MODULE,
	.read = vsentry_drv_read,
	.mmap = vsentry_drv_mmap,
	.release = vsentry_drv_release,
};

#if 0
static int dummy_tx_thread_loop(void *arg)
{
	unsigned char data[128];
	int length, count;

	pr_info("dummy_tx_thread_loop started ...\n");

	while (!kthread_should_stop()){
		set_current_state(TASK_RUNNING);

		count = 0;

		while (count < 32) {
			length = (jiffies%128);
			memset(data, 0, 128);
			memset(data, '#', length);
			sr_send_msg(MOD2ENG_BUF, data, length);
			count++;
		}

		schedule_timeout_interruptible(msecs_to_jiffies(1000));
	}

	pr_info("rx_thread_loop ended\n");

	return 0;
}
#endif

static int __init vsentry_init(void)
{	
	int rc = 0;
	
	pr_info("[%s]: module started. kernel version is %s\n",MODULE_NAME, utsname()->release);

	rc = alloc_chrdev_region(&vsentry_dev, 0, 1, "vsentry");
	if (rc < 0) {
		pr_err("%s: Couldn't allocate device number (%d).\n", __func__, rc);
		return rc;
	}

	cdev_p = cdev_alloc();
	cdev_p->ops = &vsentry_file_ops;
	rc = cdev_add(cdev_p, vsentry_dev, 1);
	if (rc) {
		pr_err("%s: Couldn't add character device (%d)\n", __func__, rc);
		return rc;
	}

	/* start the vsentry module main function */
	if (sr_module_start() != SR_SUCCESS) {
		cdev_del(cdev_p);
		unregister_chrdev_region(vsentry_dev, 1);
		return -EIO;
	}

	sr_scanner_det_init();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	rc = register_lsm_hooks();
	if (rc)		
		pr_info("[%s]: registration to lsm failed!\n", MODULE_NAME);
	else
		pr_info("[%s]: registration to lsm succeedded\n", MODULE_NAME);
#else
	reset_security_ops();
	if (register_security (&vsentry_ops)){
		pr_info("[%s]: registration to lsm failed!\n", MODULE_NAME);
		rc = -EPERM;
	} else {
		pr_info("[%s]: registration to lsm succeedded\n", MODULE_NAME);
	}
#endif
	
	sr_netfilter_init();
	sr_classifier_init();
	//sr_cls_port_init();	
	//sr_cls_port_ut();
	// sr_cls_port_ut();
	
#ifdef UNIT_TEST	
	sal_bitops_test (0);
#endif /* UNIT_TEST */

#if 0
	tx_thread = kthread_run(dummy_tx_thread_loop, NULL, "vsentry dummy tx thread");
#endif

	return rc;
}

static void __exit vsentry_cleanup(void)
{
	int i;

#if 0
	kthread_stop(tx_thread);
#endif

	for (i=0; i<SR_MAX_TASK; i++)
		sr_stop_task(i);

	sr_netfilter_uninit();
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,2,0)
	unregister_lsm_hooks();
#else
	reset_security_ops();
#endif

	sr_classifier_uninit();
	//sr_cls_port_uninit();
	cdev_del(cdev_p);
	unregister_chrdev_region(vsentry_dev, 1);
	pr_info("[%s]: module released!\n", MODULE_NAME);
}

module_init(vsentry_init);
module_exit(vsentry_cleanup);
