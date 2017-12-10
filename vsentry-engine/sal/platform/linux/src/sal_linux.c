#include "sr_sal_common.h"
#include "sal_linux.h"
#include "sr_tasks.h"
#include "engine_sal.h"

SR_32 sal_task_stop(void *data)
{
	pthread_t *thread = (pthread_t*)data;

	if (!thread) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"sal_task_stop: invalid argument %p\n", data);
		return SR_ERROR;
	}

	pthread_join(*thread, NULL);

	free(data);
	data = NULL;

	return SR_SUCCESS;
}

void* sal_wrapper_func(void *func)
{
	SR_32 (*task_func)(void *data) = func;

	task_func(NULL);

	return NULL;
}

SR_32 sal_task_start(void **data, SR_32 (*task_func)(void *data))
{
	pthread_t *thread = (pthread_t*)malloc(sizeof(pthread_t));

	if (pthread_create(thread, NULL, sal_wrapper_func, task_func) != 0) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"sal_task_start: failed to create new thread\n");
		free(thread);
		return SR_ERROR;
	}

	*data = (void*)thread;

	CEF_log_event(SR_CEF_CID_SYSTEM, "Info", SEVERITY_LOW,
		"sal_task_start: new task was created\n");

	return SR_SUCCESS;
}

void *sal_memcpy(void *dest, void *src, SR_32 len)
{
	return memcpy(dest, src, len);
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

void sal_schedule_timeout(SR_U32 timeout)
{
	usleep(timeout);
}

SR_32 sal_get_uid(char *user_name)
{
	struct passwd *pwd;
     
	if (!(pwd = getpwnam(user_name))) {
		fprintf(stderr, "Failed to allocate struct passwd for getpwnam_r.\n");
		return -1;
	}

	return pwd->pw_uid;
}


#define PROC_LEN 200
SR_U32 sal_get_os(sal_os_t *os)
{
	FILE *fin;
	char line[PROC_LEN];

	*os = SAL_OS_UNKNOWN;

	if (!(fin = fopen("/proc/version", "r"))) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s failed opening /proc/version\n");
		return SR_ERROR;
	}
	if (!fgets(line, PROC_LEN, fin)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s failed reading from /proc/version\n");
		return SR_ERROR;
	}
	if (strstr(line, UBUNTU)) {
		*os = SAL_OS_LINUX_UBUNTU;
		return SR_SUCCESS;
	}

	return SR_SUCCESS;
}

SR_32 sal_socket(SR_32 domain, SR_32 type, SR_32 protocol)
{
	return socket(domain, type, protocol);
}

/* 
	gets path for example: 
	path = /home/artur/
*/
SR_64 sal_gets_space(const SR_8* path) 
{
	struct statvfs stat;
	
	if (statvfs(path, &stat) != 0){
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"\nFailed statvfs !\n");
		return -1;
	}
	//the size in bytes
	return stat.f_bsize * stat.f_bavail;
}

SR_32 sal_rename(const SR_8 *old_filename, const SR_8 *new_filename)
{
	return (rename(old_filename, new_filename));
}

SR_U64 sal_get_time(void)
{
	time_t t;

	time(&t);

	return (SR_U64)t;
}

SR_32 sal_get_process_name(SR_U32 pid, char *exe, SR_U32 size)
{
	char buf[256];
	SR_U32 rc;

	sprintf(buf, "/proc/%d/exe", pid);
	rc = readlink(buf, exe, size);
	if (rc == -1)
		return SR_ERROR;
	if (rc > size)
		return SR_ERROR;
	exe[rc] = 0;

	return SR_SUCCESS;
}

/* The address is return in network order */
SR_U32 sal_get_ip_for_interface(char *interface)
{
	int fd;
	struct ifreq ifr;

	fd = socket(AF_INET, SOCK_DGRAM, 0);

 	ifr.ifr_addr.sa_family = AF_INET;
 	strncpy(ifr.ifr_name, interface, IFNAMSIZ-1);

	ioctl(fd, SIOCGIFADDR, &ifr);

	close(fd);

	return ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
}
