/* file: sal_linux.c
 * purpose: this file implements the sal functions for linux os
*/

#include "sal_linux.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"
#include "dispatcher.h"
#include <linux/netdevice.h>
#include <linux/inetdevice.h>

SR_32 sal_get_local_ips(SR_U32 local_ips[], SR_U32 *count, SR_U32 max)
{
	struct net_device *dev;
	struct in_device *in_dev;

	*count = 0;
	read_lock(&dev_base_lock);
	dev = first_net_device(&init_net);
	while (dev && *count < max) {
		rcu_read_lock();
		in_dev = __in_dev_get_rcu(dev);
		if (!in_dev) {
			rcu_read_unlock();
			return SR_ERROR;
		}
		for_primary_ifa(in_dev) {
			local_ips[*count] = ntohl(ifa->ifa_local);
			(*count)++;
		} endfor_ifa(in_dev);

		rcu_read_unlock(); 
		dev = next_net_device(dev);
	}
	read_unlock(&dev_base_lock);

	return SR_SUCCESS;
}

SR_32 sal_task_stop(void *data)
{
	struct task_struct *thread = (struct task_struct *)data;

	if (!thread) {
		sal_kernel_print_err("sal_task_stop: invalid argument %p\n", data);
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
		sal_kernel_print_err("sal_task_start: failed to create new thread\n");
		return SR_ERROR;
	}

	*data = thread;

	sal_kernel_print_info("sal_task_start: new task was created 0x%p 0x%p\n", thread, data);

	return SR_SUCCESS;
}


SR_32 sal_wake_up_process(void *data)
{
	struct task_struct *thread = (struct task_struct *)data;
	
	wake_up_process(thread);

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

// NETWORK functions
SR_U16 sal_packet_dest_port(void *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	struct tcphdr *tcp_header = NULL;
    struct udphdr *udp_header = NULL;

	if (ip_header->protocol == IPPROTO_TCP) {
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		return ((unsigned int)ntohs(tcp_header->dest));
	} else if (ip_header->protocol == IPPROTO_UDP) {
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

	if (ip_header->protocol == IPPROTO_TCP) {
		tcp_header = (struct tcphdr *)skb_transport_header(skb);
		return ((unsigned int)ntohs(tcp_header->source));
	} else if (ip_header->protocol == IPPROTO_UDP) {
		udp_header = (struct udphdr *)skb_transport_header(skb);
		return ((unsigned int)ntohs(udp_header->source));
	} else {
		return 0;
	}
}

SR_U8 sal_packet_ip_proto(void *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

	return (ip_header->protocol);
}

SR_U32 sal_packet_src_addr(void *skb)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);

	return ntohl(ip_header->saddr);
}

SR_U32 sal_packet_dest_addr(void *skb)
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

SR_U32 sal_get_exec_inode(SR_32 pid)
{
        struct task_struct *p;
        struct mm_struct *mm;
        struct file *exe_file;
 	
	if (!pid)
	   return 0;

	if (!(p = pid_task(find_vpid(pid), PIDTYPE_PID)))
	   return 0; // Not found

	mm = p->mm;
	if (!mm)
	   return 0;
	exe_file = mm->exe_file;
	if (!exe_file)
	   return 0;
	return exe_file->f_path.dentry->d_inode->i_ino;
}

void* sal_get_parent_dir(void* info)
{
    struct dentry *tmp_dir;
    disp_info_t* tmp_info;
  
    tmp_info = (disp_info_t*)info;
    tmp_dir = (struct dentry*)tmp_info->fileinfo.parent_info;
    
        if(!tmp_dir)
			return NULL;
    
	if(!SR_IS_ROOT(tmp_dir)){
		tmp_info->fileinfo.parent_info = tmp_dir->d_parent;
		tmp_info->fileinfo.parent_directory_inode = tmp_dir->d_inode->i_ino;
	/******************************************/
	/*                                        */
	/* DBG prints for integration only        */
	/* -> SHOULD BE REMOVED AFTER INTEGRETION */
	/*                                        */
	/******************************************/
		/*
		SR_U8 filename[SR_MAX_PATH_SIZE];
		memset(&filename, 0, sizeof(filename));
		strncpy(filename, tmp_dir->d_iname,
				MIN(sizeof(filename), 1+strlen(tmp_dir->d_iname)));	
		printk("[%s]FILE=%s, INODE=%ld \n",__func__,filename,tmp_dir->d_inode->i_ino);
		*/
		return tmp_info;
	}else{
		/*
		SR_U8 filename[SR_MAX_PATH_SIZE];
		memset(&filename, 0, sizeof(filename));
		strncpy(filename, tmp_dir->d_iname,
				MIN(sizeof(filename), 1+strlen(tmp_dir->d_iname)));	
		//printk("ROOTTTTTT [%s]FILE=%s, INODE=%ld \n",__func__,filename,tmp_dir->d_inode->i_ino);
		*/
		return NULL;
	}
}
	/******************************************/
	/*                                        */
	/* DBG prints for integration only        */
	/* -> SHOULD BE REMOVED AFTER INTEGRETION */
	/*                                        */
	/******************************************/
/*
SR_U32 sal_get_parent_dir(void* dir)
{
    struct dentry *tmp_dir;
    SR_U8 filename[SR_MAX_PATH_SIZE];
    
    if(!dir) return SR_ERROR;
    
    tmp_dir = (struct dentry*)dir;
  
    printk("[%s] PATH=",__func__);

	while(!IS_ROOT(tmp_dir)){
		memset(&filename, 0, sizeof(filename));
		strncpy(filename, tmp_dir->d_iname,
			MIN(sizeof(filename), 1+strlen(tmp_dir->d_iname)));
		printk("%s/",filename);
		tmp_dir=tmp_dir->d_parent;
	}
	printk("\n");
	return tmp_dir->d_inode->i_ino;
}
*/

void sal_update_time_counter(SR_TIME_COUNT *time_count)
{
	*time_count = jiffies;
}

SR_32 sal_elapsed_time_secs(SR_TIME_COUNT time_count)
{
	return (jiffies - time_count) / HZ;
}

SR_U64 get_curr_time_usec(void)
{
	struct timeval tv;
	do_gettimeofday(&tv);
	return ((tv.tv_sec * 1000000) + tv.tv_usec);
}
