/* file: module_init.c
 * purpose: this file initialize the kernel module
*/

#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/version.h>
#include <linux/utsname.h>
#include <linux/kthread.h>

#ifdef DEBUGFS_SUPPORT
#include "debugfs_support.h"
#endif
#include "sr_lsm_hooks.h"
#include "sal_linux.h"
#include "dispatcher.h"
#include "sr_classifier.h"
#ifdef CONFIG_STAT_ANALYSIS
#include "sr_stat_analysis.h"
#include "sr_stat_connection.h"
#endif
#include "sr_cls_process.h"
#include "sr_event_collector.h"
#include "sr_ring_buf.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_tasks.h"
#include "main_loop.h"
#include "sr_scanner_det.h"
#include "sr_ver.h"
#include "sr_control.h"
#include "sal_linux_mng.h"
#include "sr_ec_common.h"
#include "event_mediator.h"
#include "sal_ext_can_drivers.h"

#ifdef CONFIG_CAN_ML
#include "ml_can.h"
#endif /* CONFIG_CAN_ML */

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("vSentry Kernel Module");

static dev_t vsentry_dev;
static struct cdev *cdev_p;

int sr_netfilter_init(void);
void sr_netfilter_uninit(void);

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

	if (!vsentry_get_pid())
		vsentry_set_pid(current->pid);
		
	pr_info("vsentry PID = %d\n", vsentry_get_pid());
	pr_info("vsentry_drv_mmap length = %ld, vm_start 0x%p\n", length, (void *) vma->vm_start);

	switch (vma->vm_pgoff) {
		case ENG2MOD_PAGE_OFFSET:
			type = ENG2MOD_BUF;
			pr_info("vsentry_drv_mmap: initializing ENG2MOD_BUF\n");
			thread = sr_task_get_data(SR_MODULE_TASK);
			pr_info("vsentry_drv_mmap: thread 0x%p\n", thread);
			break;
		case MOD2ENG_PAGE_OFFSET:
			type = MOD2ENG_BUF;
			pr_info("vsentry_drv_mmap: initializing MOD2ENG_BUF\n");
			break;
		case ENG2LOG_PAGE_OFFSET:
			type = ENG2LOG_BUF;
			pr_info("vsentry_drv_mmap: initializing ENG2LOG_BUF\n");
			break;
		case MOD2LOG_PAGE_OFFSET:
			type = MOD2LOG_BUF;
			pr_info("vsentry_drv_mmap: initializing MOD2LOG_BUF\n");
			break;
		case MOD2STAT_PAGE_OFFSET:
			type = MOD2STAT_BUF;
			pr_info("vsentry_drv_mmap: initializing MOD2STAT_BUF\n");
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

	if (sal_shmem_alloc(vsshmem, length, type) != SR_SUCCESS) {
		pr_err("failed to allocate mem len %ld\n", length);
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

/* close fops callback */
int vsentry_drv_release (struct inode *inode, struct file *file)
{
	int i;
	sr_shmem* vsshmem;

	pr_info("vsentry_drv_release ... freeing all allocated memory\n");

	for (i=0; i<TOTAL_BUFS; i++) {
		vsshmem = sr_msg_get_buf(i);
		if (vsshmem->buffer)
			sr_msg_free_buf(i);
	}

	vsentry_set_pid(0);

	return 0;
}

static ssize_t vsentry_drv_read(struct file *fp, char __user *buf, size_t size, loff_t *offset)
{
	switch (size) {
		case SR_SYNC_GATHER_INFO:
			sal_linux_mng_readbuf_down(SYNC_INFO_GATHER);
			break;
		case SR_SYNC_ENGINE:
			sal_linux_mng_readbuf_down(SYNC_ENGINE);
			break;
		break;
			break;
	}
	
	return 0;
}

long vsentry_drv_ioctl_u(struct file *file, unsigned int i, unsigned long l)
{
	switch (i) {
		case SR_MOD_CMD_SYNC_ENGINE:
			if (sal_linux_mng_readbuf_up(SYNC_ENGINE) != SR_SUCCESS) {
				CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
					"%s=failed up readbuf ENGINE mutex:", REASON);
			}
			break;
		default:
			break;
	}

	return 0;
}

static struct file_operations vsentry_file_ops = {
	.owner = THIS_MODULE,
	.read = vsentry_drv_read,
	.mmap = vsentry_drv_mmap,
	.release = vsentry_drv_release,
	.unlocked_ioctl = vsentry_drv_ioctl_u,
};

#if 0
static int dummy_tx_thread_loop(void *arg)
{
	unsigned char *data;
	int count;

	pr_info("dummy_tx_thread_loop started ...\n");

	while (!kthread_should_stop()){
		set_current_state(TASK_RUNNING);

		count = 0;

		while (count < 32) {
			data = sr_get_msg(MOD2ENG_BUF, MOD2ENG_MSG_MAX_SIZE);
			if (data) {
				memset(data, 0, MOD2ENG_MSG_MAX_SIZE);
				memset(data, '#', count);
				sr_send_msg(MOD2ENG_BUF, MOD2ENG_MSG_MAX_SIZE);
			}
			count++;
		}

		schedule_timeout_interruptible(msecs_to_jiffies(1000));
	}

	pr_info("rx_thread_loop ended\n");

	return 0;
}
#endif

static int pcan_security_cb(SR_U32 msg_id, int is_dir_in, int can_dev_id) {
	return vsentry_can_driver_security(msg_id, is_dir_in, can_dev_id);
}

static int __init vsentry_init(void)
{
	int rc = 0;
	
	pr_info("[%s]: module started. kernel version is %s, module version is %d.%d (%s)\n",
			MODULE_NAME, utsname()->release, 
			VSENTRY_VER_MAJOR, VSENTRY_VER_MINOR, VSENTRY_VER_BUILD);

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

	sal_linux_mng_readbuf_init();

	sr_event_collector_init();

#ifdef CONFIG_STAT_ANALYSIS
	rc = sr_stat_analysis_init();
	if (rc != SR_SUCCESS) {
		pr_info("[%s]: init stat_analysis failed!\n", MODULE_NAME);
		cdev_del(cdev_p);
		return rc;
	}
#endif /* CONFIG_STAT_ANALYSIS */

#ifdef CONFIG_CAN_ML
	rc = sr_ml_can_hash_init();
	if (rc != SR_SUCCESS) {
		pr_info("[%s]: init can_ml failed!\n", MODULE_NAME);
		cdev_del(cdev_p);
		return rc;
	}
#endif /* CONFIG_CAN_ML */

	sr_classifier_init();

	rc = register_lsm_hooks();
	if (rc)	{
		pr_info("[%s]: registration to lsm failed!\n", MODULE_NAME);
		cdev_del(cdev_p);
		return rc;
	}
	pr_info("[%s]: registration to lsm succeedded\n", MODULE_NAME);	

	sr_netfilter_init();
	
#ifdef DEBUGFS_SUPPORT
	rc = debugfs_init();
		if (rc) {
		pr_debug("Cannot create debugfs 'vsentry'!\n");
		return rc;
	}
#endif	
	
	//sr_cls_add_ipv4(htonl(0x0a0a0a00), htonl(0xFFFFFF00), 60, SR_DIR_SRC);
	//sr_cls_add_ipv4(htonl(0x0a0a0a00), htonl(0xFFFFFF00), 60, SR_DIR_DST);
	//sr_cls_port_add_rule(0, 60, SR_DIR_SRC, IPPROTO_TCP);
	//sr_cls_port_add_rule(22, 60, SR_DIR_DST, IPPROTO_TCP);

	//sr_cls_rule_add(SR_NET_RULES, 60, SR_CLS_ACTION_DROP, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	
#if 0
	tx_thread = kthread_run(dummy_tx_thread_loop, NULL, "vsentry dummy tx thread");
#endif

	security_cb_register(pcan_security_cb);

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

	unregister_lsm_hooks();
	sr_netfilter_uninit();
	sr_classifier_uninit();
#ifdef CONFIG_STAT_ANALYSIS
	sr_stat_analysis_uninit();
#endif

#ifdef CONFIG_CAN_ML
	sr_ml_can_hash_deinit();
#endif

	cdev_del(cdev_p);
	unregister_chrdev_region(vsentry_dev, 1);
#ifdef DEBUGFS_SUPPORT
	debugfs_deinit();
#endif
	pr_info("[%s]: module released!\n", MODULE_NAME);
}

module_init(vsentry_init);
module_exit(vsentry_cleanup);
