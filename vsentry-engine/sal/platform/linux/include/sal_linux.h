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

#define VS_FILE_NAME 	"/dev/vsentry"

#define UBUNTO "Ubuntu"

typedef enum {
	SAL_OS_UNKNOWN,	
	SAL_OS_LINUX_UBUNTO,	
	SAL_OS_MAX = SAL_OS_LINUX_UBUNTO,
	SAL_OS_TOTAL = (SAL_OS_MAX + 1),
} sal_os_t;

SR_U32 sal_get_os(sal_os_t *os);

#endif /* SAL_LINUX_ENGINE_H*/
