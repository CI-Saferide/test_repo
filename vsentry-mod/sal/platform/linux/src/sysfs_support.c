/* file: sysfs_support.c
 * purpose: this file initialize the kernel module
*/
#ifdef SYSFS_SUPPORT
#include "sysfs_support.h"

#define SYSFS_MAX_USER_COMMAND 100

static unsigned char buf[SYSFS_MAX_USER_COMMAND];
static struct dentry *root = NULL;
static SR_U8 read_called_again = 0;

static ssize_t sysfs_state_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t rt, len;

	if (*ppos != 0) // check to avoid function calling itself endlessly
		return 0;

	len = sal_sprintf(buf, "%s\n", (0 != vsentry_get_pid()? "enabled" : "disabled"));

	rt = simple_read_from_buffer(user_buf, count, ppos, buf, len);
	if ((rt != len) || (*ppos != len))
		return rt;

	*ppos = rt;
	return rt;
}

static ssize_t sysfs_file_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t rt = 0;
	int rule_num;
		
	if (*ppos != 0) // check to avoid function calling itself endlessly
			return 0;

	if (read_called_again) {

		read_called_again = 0;

		if (strcmp(buf, "dump") == 0) {
			rt = dump_file_table(user_buf, count, ppos, 0);
		}
	} else { // first call

		if (strcmp(buf, "dump") == 0) {
			rt = dump_file_table(user_buf, count, ppos, 1);
		} else {
			rule_num = simple_strtol(buf,NULL,10);
			pr_info("%s dump rule number: %d\n" ,__func__,rule_num);
			rt = dump_file_rule((SR_16)rule_num, user_buf, count, ppos);
		}
	}

	if (*ppos != rt) // did not finish writing everything to user
		read_called_again = 1;

	return rt;
}

static ssize_t sysfs_can_read(struct file *file, char __user *user_buf, size_t count, loff_t *ppos)
{
	size_t rt = 0;
	int rule_num;

	if (*ppos != 0) // check to avoid function calling itself endlessly
		return 0;

	if (read_called_again) {

		read_called_again = 0;

		if (strcmp(buf, "dump") == 0) {
			rt = dump_can_table(user_buf, count, ppos, 0);
		}
	} else { // first call

		if (strcmp(buf, "dump") == 0) {
			rt = dump_can_table(user_buf, count, ppos, 1);
		} else {
			rule_num = simple_strtol(buf,NULL,10);
			pr_info("%s dump rule number: %d\n" ,__func__,rule_num);
			rt = dump_can_rule((SR_16)rule_num, user_buf, count, ppos);
		}
	}

	if (*ppos != rt) // did not finish writing everything to user
		read_called_again = 1;

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

	if (read_called_again) {

		read_called_again = 0;

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
		read_called_again = 1;
	
	return rt;
}

static ssize_t sysfs_write(struct file *file, const char __user *user_buf, size_t count, loff_t *ppos)
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

static int default_open(struct inode *inode, struct file *file)
{
	return 0;
}

static struct file_operations ipv4_ops = {
	.write =	sysfs_write,
	.read  =	sysfs_ipv4_read,
	.open  =	default_open,
};

static struct file_operations can_ops = {
	.write =	sysfs_write,
	.read  =	sysfs_can_read,
	.open  =	default_open,
};

static struct file_operations file_ops = {
	.write =	sysfs_write,
	.read  =	sysfs_file_read,
	.open  =	default_open,
};

static struct file_operations state_ops = {
	.read  =	sysfs_state_read,
	.open  =	default_open,
};

int sysfs_init(void){

	root = debugfs_create_dir("vsentry", NULL);
	if (!root) {
		pr_err("%s failed to create vsentry directory\n",__func__);
		return -ENXIO;
	}
	if (!debugfs_create_file("cls_ipv4", 0644, root, NULL, &ipv4_ops)) {
		pr_warn("%s failed to create cls_ipv4\n",__func__);
	}
	if (!debugfs_create_file("cls_can", 0644, root, NULL, &can_ops)) {
		pr_warn("%s failed to create cls_can\n",__func__);
	}
	if (!debugfs_create_file("cls_file", 0644, root, NULL, &file_ops)) {
		pr_warn("%s failed to create cls_file\n",__func__);
	}
	if (!debugfs_create_file("state", 0644, root, NULL, &state_ops)) {
		pr_warn("%s failed to create state\n",__func__);
	}

	return 0;
}

void sysfs_deinit(){
	if (root)
		debugfs_remove_recursive(root);
}

#endif /* SYSFS_SUPPORT */
