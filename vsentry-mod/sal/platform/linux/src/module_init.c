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
#include "sr_cls_process.h"
#include "sr_event_collector.h"

#include "sr_ring_buf.h"
#include "sr_shmem.h"
#include "sr_msg.h"
#include "sr_tasks.h"
#include "main_loop.h"
#include "sr_scanner_det.h"

#ifdef UNIT_TEST
#include "sal_bitops_test.h"
#endif /* UNIT_TEST */

MODULE_LICENSE("GPL");
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

	if (!sr_vsentryd_pid)
		sr_vsentryd_pid = current->pid;
		
	pr_info("vsentry PID = %d\n",sr_vsentryd_pid);
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

	for (i=0; i<TOTAL_BUFS; i++) {
		vsshmem = sr_msg_get_buf(i);
		if (vsshmem->buffer)
			sr_msg_free_buf(i);
	}

	sr_vsentryd_pid = 0;

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

#ifdef SR_DEMO
void sr_demo(void) 
{
	// Populate rules for demo on 7/13/2017
#ifdef 0
	sr_cls_add_ipv4(htonl(0x0a0a0a00), htonl(0xFFFFFF00), 50, SR_DIR_SRC);
	sr_cls_port_add_rule(22, 50, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x0a0a0a00), htonl(0xFFFFFF00), 60, SR_DIR_SRC);
	sr_cls_port_add_rule(24, 60, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x709), htonl(0xFFFFFFFF), 70, SR_DIR_SRC);
	sr_cls_port_add_rule(22, 70, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x0a0a0a2e), htonl(0xFFFFFFFF), 80, SR_DIR_SRC);
	sr_cls_port_add_rule(22, 80, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x555), htonl(0xFFFFFFFF), 90, SR_DIR_SRC);
	sr_cls_port_add_rule(555, 90, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x0a000000), htonl(0xFF000000), 100, SR_DIR_SRC);
	sr_cls_port_add_rule(22, 100, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_add_ipv4(htonl(0x00000000), htonl(0x00000000), 110, SR_DIR_SRC);
	sr_cls_add_ipv4(htonl(0x0a0a0a32), htonl(0xFFFFFFFF), 110, SR_DIR_DST);
	sr_cls_port_add_rule(0, 110, SR_DIR_SRC, IPPROTO_TCP);
	sr_cls_port_add_rule(22, 110, SR_DIR_DST, IPPROTO_TCP);
	sr_cls_rule_add(SR_NET_RULES, 50, SR_CLS_ACTION_ALLOW, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_uid_add_rule(SR_NET_RULES, UID_ANY, 50);
	sr_cls_rule_add(SR_NET_RULES, 60, SR_CLS_ACTION_ALLOW, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_uid_add_rule(SR_NET_RULES, UID_ANY, 60);
	sr_cls_rule_add(SR_NET_RULES, 70, SR_CLS_ACTION_ALLOW, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_uid_add_rule(SR_NET_RULES, UID_ANY, 70);
	sr_cls_rule_add(SR_NET_RULES, 80, SR_CLS_ACTION_ALLOW|SR_CLS_ACTION_LOG, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_uid_add_rule(SR_NET_RULES, UID_ANY, 80);
	sr_cls_rule_add(SR_NET_RULES, 90, SR_CLS_ACTION_ALLOW, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_uid_add_rule(SR_NET_RULES, UID_ANY, 90);
	sr_cls_rule_add(SR_NET_RULES, 100, SR_CLS_ACTION_DROP, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_uid_add_rule(SR_NET_RULES, UID_ANY, 100);
	sr_cls_rule_add(SR_NET_RULES, 110, SR_CLS_ACTION_DROP, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_uid_add_rule(SR_NET_RULES, UID_ANY, 110);


	sr_cls_inode_add_rule(1603491, 1); // /templab/file1
	sr_cls_uid_add_rule(SR_FILE_RULES, UID_ANY, 1);
	sr_cls_inode_add_rule(1605650, 2); // /templab/dir2
	sr_cls_uid_add_rule(SR_FILE_RULES, UID_ANY, 2);
	sr_cls_inode_add_rule(1605649, 3); // /templab/dir1
	sr_cls_uid_add_rule(SR_FILE_RULES, UID_ANY, 3);
	sr_cls_inode_add_rule(1603488, 4); // /templab
	sr_cls_uid_add_rule(SR_FILE_RULES, UID_ANY, 4);

	sr_cls_inode_add_rule(4089093, 5); // /tmp/hilik
	sr_cls_uid_add_rule(SR_FILE_RULES, 1002, 5); // user hilik
	sr_cls_inode_add_rule(4089093, 6); // /tmp/hilik
	sr_cls_uid_add_rule(SR_FILE_RULES, 1001, 6); // user hilik2
	sr_cls_inode_add_rule(4089094, 7); // /tmp/hilik2
	sr_cls_uid_add_rule(SR_FILE_RULES, 1001, 7); // user hilik2
	sr_cls_inode_add_rule(0, 8); // ANY
	sr_cls_uid_add_rule(SR_FILE_RULES, 1001, 8); // user hilik2
	
	sr_cls_rule_add(SR_FILE_RULES, 1, SR_CLS_ACTION_ALLOW, SR_FILEOPS_READ,0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(SR_FILE_RULES, 2, SR_CLS_ACTION_DROP, SR_FILEOPS_READ,0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(SR_FILE_RULES, 3, SR_CLS_ACTION_ALLOW, SR_FILEOPS_WRITE|SR_FILEOPS_READ,0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(SR_FILE_RULES, 4, SR_CLS_ACTION_DROP, SR_FILEOPS_WRITE|SR_FILEOPS_READ,0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(SR_FILE_RULES, 5, SR_CLS_ACTION_DROP, SR_FILEOPS_READ,0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(SR_FILE_RULES, 6, SR_CLS_ACTION_ALLOW, SR_FILEOPS_READ,0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(SR_FILE_RULES, 7, SR_CLS_ACTION_ALLOW, SR_FILEOPS_WRITE,0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	sr_cls_rule_add(SR_FILE_RULES, 8, SR_CLS_ACTION_DROP, SR_FILEOPS_WRITE,0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
#endif
}
#endif // SR_DEMO


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

	sr_event_collector_init();

	rc = register_lsm_hooks();
	if (rc)	{
		pr_info("[%s]: registration to lsm failed!\n", MODULE_NAME);
		cdev_del(cdev_p);
		return rc;
	}
	pr_info("[%s]: registration to lsm succeedded\n", MODULE_NAME);	

	sr_netfilter_init();
	sr_classifier_init();
	
	//sr_cls_add_ipv4(htonl(0x0a0a0a00), htonl(0xFFFFFF00), 60, SR_DIR_SRC);
	//sr_cls_add_ipv4(htonl(0x0a0a0a00), htonl(0xFFFFFF00), 60, SR_DIR_DST);
	//sr_cls_port_add_rule(0, 60, SR_DIR_SRC, IPPROTO_TCP);
	//sr_cls_port_add_rule(22, 60, SR_DIR_DST, IPPROTO_TCP);

	//sr_cls_rule_add(SR_NET_RULES, 60, SR_CLS_ACTION_DROP, 0, 0, SR_CLS_ACTION_DROP, 0, 0, 0, 0);
	
#ifdef UNIT_TEST
	sal_bitops_test (0);
	sr_cls_port_ut();
	sr_cls_uid_ut();
	sr_cls_canid_ut();
	sr_cls_exec_file_ut();
	sr_cls_process_ut();
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

	unregister_lsm_hooks();
	sr_classifier_uninit();
	sr_netfilter_uninit();

	cdev_del(cdev_p);
	unregister_chrdev_region(vsentry_dev, 1);
	pr_info("[%s]: module released!\n", MODULE_NAME);
}

module_init(vsentry_init);
module_exit(vsentry_cleanup);
