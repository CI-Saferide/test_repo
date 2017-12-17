#ifndef SAL_LINUX_ENGINE_H
#define SAL_LINUX_ENGINE_H

#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <time.h>
#include <stdlib.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <stddef.h>
#include <fcntl.h>
#include <sys/mman.h>
#include  <sys/stat.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include <sr_sal_common.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/uio.h>
#include <net/if.h>
#include <signal.h>
#include <stdint.h>
#include <sys/statvfs.h>
#include <linux/can.h>
#include <linux/can/raw.h>

#define VS_FILE_NAME 	"/dev/vsentry"

#define UBUNTU "Ubuntu"

typedef enum {
	SAL_OS_UNKNOWN,	
	SAL_OS_LINUX_UBUNTU,	
	SAL_OS_MAX = SAL_OS_LINUX_UBUNTU,
	SAL_OS_TOTAL = (SAL_OS_MAX + 1),
} sal_os_t;

SR_U32 sal_get_os(sal_os_t *os);

#define DEFAULT_CAN0_INTERFACE "vcan0"	/* default virtual can interface, in case no config file detected */
#define DEFAULT_CAN1_INTERFACE "vcan1"	/* default virtual can interface, in case no config file detected */
#define DEFAULT_CAN2_INTERFACE "vcan2"	/* default virtual can interface, in case no config file detected */
#define DEFAULT_CAN3_INTERFACE "vcan3"	/* default virtual can interface, in case no config file detected */
#define DEFAULT_CAN4_INTERFACE "vcan4"	/* default virtual can interface, in case no config file detected */

SR_U64 sal_get_time(void);
SR_32 sal_get_process_name(SR_U32 pid, char *exe, SR_U32 size);

#endif /* SAL_LINUX_ENGINE_H*/
