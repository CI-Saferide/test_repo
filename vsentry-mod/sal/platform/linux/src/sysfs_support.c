/* file: sysfs_support.c
 * purpose: this file initialize the kernel module
*/
#ifdef SYSFS_SUPPORT
#include "sysfs_support.h"

#define SYSFS_MAX_USER_COMMAND 100

static unsigned char buf[SYSFS_MAX_USER_COMMAND];

static struct kobject *vsentry;

static ssize_t cls_can_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sal_sprintf(buf, "%s\n", get_sysfs_can());
}

static ssize_t cls_can_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{	
	int rule_num;
		
	if(strcmp(buf, "dump") == 0){
		dump_can_table();
		goto done;
		
	}else{
			
		rule_num = simple_strtol(buf,NULL,10);	
		pr_info("%s dump rule number: %d\n" ,__func__,rule_num);
		dump_can_rule((SR_16)rule_num);			
	}

done:	

	return count;
}

static ssize_t cls_file_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sal_sprintf(buf, "%s\n",get_sysfs_file());
}

static ssize_t cls_file_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	int rule_num;
		
	if(strcmp(buf, "dump") == 0){
		dump_file_table();
		goto done;
		
	}else{
			
		rule_num = simple_strtol(buf,NULL,10);
		pr_info("%s dump rule number: %d\n" ,__func__,rule_num);
		dump_file_rule((SR_16)rule_num);
	}

done:	

	return count;
}

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sal_sprintf(buf, "%s\n", (0 != vsentry_get_pid()? "enabled" : "disabled"));
}

static struct kobj_attribute CLS_file = 		__ATTR_RW(cls_file);
static struct kobj_attribute CLS_can = 			__ATTR_RW(cls_can);
static struct kobj_attribute STATE =			__ATTR_RO(state);

static struct dentry *root = NULL;

static SR_U8 ipv4_read_called_again = 0;

static ssize_t sysfs_ipv4_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t rt;

	if (count > sizeof(buf)) {
		pr_err("%s user command too long\n",__func__);
		return -EFAULT;
	}

	rt = simple_write_to_buffer(buf, sizeof(buf), ppos, user_buf, count);
	buf[count] = '\0';
	return rt;
}

static ssize_t sysfs_ipv4_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t rt = 0;
	int rule_num;
	SR_32 ip[4];
	SR_32 ip_addr;

	if (*ppos != 0) // check to avoid function calling itself endlessly
		return 0;

	if (ipv4_read_called_again) {

		ipv4_read_called_again = 0;

		if (strcmp(buf, "dump") == 0) { // all rules
			rt = dump_ipv4_table(user_buf, count, ppos, 0);
		} else if (strcmp(buf, "tree -s") == 0) { // src radix tree
			rt = dump_ipv4_tree(SR_DIR_SRC, user_buf, count, ppos, 0);
		} else if (strcmp(buf, "tree -d") == 0) { // dst radix tree
			rt = dump_ipv4_tree(SR_DIR_DST, user_buf, count, ppos, 0);
		}
	} else { // first call

		if (strcmp(buf, "dump") == 0) { // all rules
			rt = dump_ipv4_table(user_buf, count, ppos, 1);
		} else if (strcmp(buf, "tree -s") == 0) { // src radix tree
			rt = dump_ipv4_tree(SR_DIR_SRC, user_buf, count, ppos, 1);
		} else if (strcmp(buf, "tree -d") == 0) { // dst radix tree
			rt = dump_ipv4_tree(SR_DIR_DST, user_buf, count, ppos, 1);
		} else if (strstr(buf, "ip") != NULL) { // rules for a single ip

			sscanf(buf + 3, "%d.%d.%d.%d", ip, ip + 1, ip + 2, ip + 3);
			ip_addr = ip[0] | (ip[1] << 8) | (ip[2] << 16) | (ip[3] << 24);
			pr_info("%s dump rule/s for ip: %u.%u.%u.%u\n" ,__func__,ip[0],ip[1],ip[2],ip[3]);
			rt = dump_ipv4_ip(ip_addr, user_buf, count, ppos);

		} else { // single rule

			rule_num = simple_strtol(buf,NULL,10);
			pr_info("%s dump rule number: %d\n" ,__func__,rule_num);
			rt = dump_ipv4_rule((SR_16)rule_num, user_buf, count, ppos);
		}
	}

	if (*ppos != rt) // did not finish writing everything to user
		ipv4_read_called_again = 1;
	
	return rt;
}

static int default_open(struct inode *inode, struct file *file)
{
	return 0;
}

static struct file_operations sysfs_ipv4_ops = {
	.write =	sysfs_ipv4_write,
	.read  =	sysfs_ipv4_read,
	.open  =	default_open,
};

int sysfs_init(void){
	
	int rc = 0;
	
	vsentry = kobject_create_and_add("vsentry", kernel_kobj);
	if (!vsentry) {
		return -ENOMEM;
	}
	rc = sysfs_create_file(vsentry, &CLS_file.attr);
	if (rc) {
		pr_debug("Cannot create sysfs file 'vsentry'!\n");
		return rc;
	}
	rc = sysfs_create_file(vsentry, &CLS_can.attr);
	if (rc) {
		pr_debug("Cannot create sysfs file 'vsentry'!\n");
		return rc;
	}
	rc = sysfs_create_file(vsentry, &STATE.attr);
	if (rc) {
		pr_debug("Cannot create sysfs file 'vsentry'!\n");
		return rc;
	}

	root = debugfs_create_dir("vsentry", NULL);
	if (!root) {
		pr_err("%s failed to create vsentry directory\n",__func__);
		return -ENXIO;
	}
	if (!debugfs_create_file("cls_ipv4", 0644, root, NULL, &sysfs_ipv4_ops)) {
		pr_warn("%s failed to create cls_ipv4\n",__func__);
	}

	return rc;
}

void sysfs_deinit(){
	if (vsentry)
		kobject_put(vsentry);
	if (root)
		debugfs_remove_recursive(root);
}

#endif /* SYSFS_SUPPORT */
