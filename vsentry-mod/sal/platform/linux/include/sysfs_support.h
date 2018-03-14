/* file: sysfs_support.h
 * purpose: this file used for sysfs related functions that invoked from module init */

#ifndef SYSFS_SUPPORT_H
#define SYSFS_SUPPORT_H

#include <linux/fs.h>
#include <linux/sysfs.h>

#include "sr_types.h"
#include "sal_linux.h"
#include "sysfs_cls_can.h"
#include "sysfs_cls_file.h"
#include "sysfs_cls_ipv4.h"

#define BUF_MAX PAGE_SIZE

int sysfs_init(void);
void sysfs_deinit(void);

int get_vsentry_pid(void);

#endif /* SYSFS_SUPPORT_H*/
