/* file: sysfs_support.c
 * purpose: this file initialize the kernel module
*/

#include "sysfs_support.h"

static struct kobject *vsentry;

static ssize_t cls_can_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", get_sysfs_can());
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
	return sprintf(buf, "%s\n",get_sysfs_file());
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

static ssize_t cls_ipv4_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", get_sysfs_ipv4());
}

static ssize_t cls_ipv4_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	int rule_num;
		
	if(strcmp(buf, "dump") == 0){
		dump_ipv4_table();
		goto done;
		
	}else{
			
		rule_num = simple_strtol(buf,NULL,10);	
		pr_info("%s dump rule number: %d\n" ,__func__,rule_num);
		dump_ipv4_rule((SR_16)rule_num);
	}

done:	

	return count;
}

static ssize_t state_show(struct kobject *kobj, struct kobj_attribute *attr, char *buf)
{
	return sprintf(buf, "%s\n", (0 != get_vsentry_pid()? "enabled" : "disabled"));
}

static ssize_t state_store(struct kobject *kobj, struct kobj_attribute *attr, const char *buf, size_t count)
{
	return count;
}

static struct kobj_attribute CLS_file = 		__ATTR_RW(cls_file);
static struct kobj_attribute CLS_can = 			__ATTR_RW(cls_can);
static struct kobj_attribute CLS_ipv4 =			__ATTR_RW(cls_ipv4);
static struct kobj_attribute STATE =			__ATTR_RW(state);

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
	rc = sysfs_create_file(vsentry, &CLS_ipv4.attr);
	if (rc) {
		pr_debug("Cannot create sysfs file 'vsentry'!\n");
		return rc;
	}
	rc = sysfs_create_file(vsentry, &STATE.attr);
	if (rc) {
		pr_debug("Cannot create sysfs file 'vsentry'!\n");
		return rc;
	}
	return rc;
}

void sysfs_deinit(){
	kobject_put(vsentry);	
}
