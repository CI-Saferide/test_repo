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
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <sys/sysinfo.h>
#include <ctype.h>

#define VS_FILE_NAME 	"/dev/vsentry"
#define HOME_PREFIX     "/home/"

#define UBUNTU "Ubuntu"

typedef enum {
	SAL_OS_UNKNOWN,	
	SAL_OS_LINUX_UBUNTU,	
	SAL_OS_MAX = SAL_OS_LINUX_UBUNTU,
	SAL_OS_TOTAL = (SAL_OS_MAX + 1),
} sal_os_t;

SR_U32 sal_get_os(sal_os_t *os);

#define SR_MUTEX pthread_mutex_t
#define SR_MUTEX_INIT(l) pthread_mutex_init(l, NULL)
#define SR_MUTEX_LOCK(l) pthread_mutex_lock(l)
#define SR_MUTEX_UNLOCK(l) pthread_mutex_unlock(l)
#define SR_MUTEX_INIT_VALUE PTHREAD_MUTEX_INITIALIZER

#define SR_SLEEPLES_LOCK_DEF(name)
#define SR_SLEEPLES_LOCK_INIT(lock) 
#define SR_SLEEPLES_LOCK_FLAGS unsigned long
#define SR_SLEEPLES_LOCK(lock, flags) 
#define SR_SLEEPLES_UNLOCK(lock, flags)
#define SR_SLEEPLES_TRYLOCK(lock, flags) 1

#define IPV4_STR_MAX_LEN INET_ADDRSTRLEN

#define sal_print_crit(fmt, ...) \
	CEF_log_event(SR_CEF_CID_SYSTEM, "crit", SEVERITY_VERY_HIGH, fmt, ##__VA_ARGS__)
#define sal_print_err(fmt, ...) \
	CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_HIGH, fmt, ##__VA_ARGS__)
#define sal_print_info(fmt, ...)

SR_U64 sal_get_time(void);
SR_32 sal_get_process_name(SR_U32 pid, char *exe, SR_U32 size);
SR_U32 sal_get_ip_for_interface(char *interface);
SR_U32 sal_get_host_info(char *host_info, int size);

void sal_openlog(void);
void sal_closelog(void);
void sal_log(char *cef_buffer, SR_32 severity);
char *sal_get_home_user(void);
char *sal_get_str_ip_address(SR_U32 ip);

SR_32 sal_vsentry_fd_open(void);
int sal_get_vsentry_fd(void);
void sal_vsentry_fd_close(void);

SR_32 sal_get_memory(SR_U64 *mem, SR_U64 *free_mem);

SR_BOOL sal_is_string_numeric(char *s);
SR_BOOL sal_is_valid_file_name(char *file_name);

void sal_vsentry_unlock(void);
void sal_set_interrupt_cb(void (*cb)(int));

SR_32 sal_get_interface_id(char *interface, SR_U32 *if_id);
SR_32 sal_get_interface_name(SR_32 if_id, char *interface);

#endif /* SAL_LINUX_ENGINE_H*/
