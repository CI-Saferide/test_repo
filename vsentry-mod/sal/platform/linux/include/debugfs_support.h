/* file: debugfs_support.h
 * purpose: this file used for debugfs related functions that invoked from module init */

#ifndef DEBUGFS_SUPPORT_H
#define DEBUGFS_SUPPORT_H

#include <linux/fs.h>
#include <linux/debugfs.h>

#include "sr_types.h"
#include "sal_linux.h"
#include "sr_control.h"
#include "debugfs_cls_can.h"
#include "debugfs_cls_file.h"
#include "debugfs_cls_ipv4.h"

#define BUF_MAX PAGE_SIZE

int debugfs_init(void);
void debugfs_deinit(void);

#endif /* DEBUGFS_SUPPORT_H*/
