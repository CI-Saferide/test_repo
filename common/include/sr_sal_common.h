#include "sr_types.h"

#define SR_MAX_LOG  512

#define SR_MAX_PATH_SIZE 256

#if defined (__KERNEL__) || defined (__linux)
#include "sal_linux.h"
#endif

void *sal_memcpy(void *dest, void *src, SR_32 len);
void *sal_memset(void *dest, SR_8 ch, SR_32 len);
SR_8 *sal_strcpy(SR_8 *dest, SR_8 *src);
SR_32 sal_sprintf(SR_8 *str, SR_8 *fmt, ...);
void sal_printf(SR_8 *fmt, ...);
SR_32 sal_task_stop(void *data);
SR_32 sal_task_start(void **data, SR_32 (*task_func)(void *data));
SR_32 sal_wake_up_process(void *data);
void sal_schedule_timeout(SR_U32 timeout);
void sal_schedule(void);
SR_8 *sal_strstr(SR_8 *haystack, SR_8 *needle);
SR_32 sal_get_uid(char *user_name);
SR_32 sal_socket(SR_32 domain, SR_32 type, SR_32 protocol);
SR_64 sal_gets_space(const SR_8* path);
