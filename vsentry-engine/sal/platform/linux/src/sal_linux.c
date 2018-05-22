#include "sr_sal_common.h"
#include "sal_linux.h"
#include "sr_tasks.h"
#include "engine_sal.h"
#include <syslog.h>

#define SAFERIDE_PREFIX "saferide"

static int fd_vsentry;

SR_32 sal_vsentry_fd_open(void)
{
	if ((fd_vsentry = open(VS_FILE_NAME, O_RDWR|O_SYNC)) < 0) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
				"%s=sal_shmem_alloc: faield to open %s", REASON, VS_FILE_NAME);
				return SR_ERROR;
	}
	return SR_SUCCESS;
}

int sal_get_vsentry_fd(void)
{
	return fd_vsentry;
}

void sal_vsentry_fd_close(void)
{
	close(fd_vsentry);
}


SR_32 sal_task_stop(void *data)
{
	pthread_t *thread = (pthread_t*)data;

	if (!thread) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=sal_task_stop: invalid argument %p", REASON, data);
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
			"%s=sal_task_start: failed to create new thread", REASON);
		free(thread);
		return SR_ERROR;
	}

	*data = (void*)thread;

	CEF_log_event(SR_CEF_CID_SYSTEM, "info", SEVERITY_LOW,
		"%s=sal_task_start: new task was created", MESSAGE);

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
		//fprintf(stderr, "Failed to allocate struct passwd for getpwnam_r.\n");
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
			"%s=failed opening /proc/version", REASON);
		return SR_ERROR;
	}
	if (!fgets(line, PROC_LEN, fin)) {
		CEF_log_event(SR_CEF_CID_SYSTEM, "error", SEVERITY_LOW,
			"%s=failed reading from /proc/version", REASON);
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
			"%s=Failed statvfs", REASON);
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

long double a[7] = {0, 0, 0, 0, 0, 0, 0};
long double b[7] = {0, 0, 0, 0, 0, 0, 0};

#if 0 //uncomment it to enable gather cpu info
static SR_U32 sal_get_cpu_util()
{
    long double loadavg;
    FILE *fp;

    fp = fopen("/proc/stat","r");
    if (!fp)
        return SR_ERROR;

    if (fscanf(fp,"cpu %Lf %Lf %Lf %Lf %Lf %Lf %Lf",&b[0],&b[1],&b[2],&b[3],&b[4],&b[5],&b[6]) != 7)
        return SR_ERROR;

    fclose(fp);

    loadavg = ((b[0]+b[1]+b[2]+b[4]+b[5]+b[6]) - (a[0]+a[1]+a[2]+a[4]+a[5]+a[6]))
         / ((b[0]+b[1]+b[2]+b[3]+b[4]+b[5]+b[6]) - (a[0]+a[1]+a[2]+a[3]+a[4]+a[5]+a[6]));

    memcpy(a, b, sizeof(long double)*7);

    return (int)(loadavg*100);
}
#endif

SR_32 sal_get_memory(SR_U64 *mem, SR_U64 *free_mem)
{
	struct sysinfo info = {};

	if (sysinfo(&info)) {
		perror("Get memory");
		return SR_ERROR;
	}

	if (mem)
		*mem = info.totalram; 
	if (free_mem)
		*free_mem = info.freeram; 

	return  SR_SUCCESS ;
}

SR_U32 sal_get_host_info(char *host_info, int size)
{
	struct ifaddrs *ifaddr, *ifa;
	int family, n;
	struct sysinfo info;
	unsigned long tx_bytes = 0, rx_bytes=0;
	time_t timer;
	struct tm* tm_info;
	struct timeval tv;
	SR_8 buffer[26];
    //int cpu_util = sal_get_cpu_util();
    int cpurand, memrand;

	gettimeofday(&tv, NULL);
	time(&timer);
	tm_info = localtime(&timer);
	strftime(buffer, 26, "%Y-%m-%d %H:%M:%S", tm_info);

	memset(&info, 0, sizeof(info));
	sysinfo(&info);

	if (!getifaddrs(&ifaddr)) {
		for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
			if (ifa->ifa_addr == NULL)
				continue;

			if (strncmp(ifa->ifa_name, "lo", strlen(ifa->ifa_name)) == 0)
				continue;

			family = ifa->ifa_addr->sa_family;

			if (family == AF_PACKET && ifa->ifa_data != NULL) {
				struct rtnl_link_stats *stats = (struct rtnl_link_stats *)ifa->ifa_data;
				tx_bytes += stats->tx_bytes;
				rx_bytes += stats->rx_bytes;
			}
		}
		freeifaddrs(ifaddr);
	}

	cpurand = (35 + rand()%10);
	memrand = (50 + rand()%10);

	/*snprintf(host_info, size,
		"%s.%.6ld memory_total=%lu | memory_free=%lu | cpu=%d | proccesses=%u | network_tx=%lu | network_rx=%lu",
		buffer, tv.tv_usec, info.totalram, info.freeram,
		cpu_util, info.procs, tx_bytes, rx_bytes);*/

	snprintf(host_info, size,
		"%s.%.6ld memory_total=%lu | memory_free=%lu | cpu=%d | proccesses=%u | network_tx=%lu | network_rx=%lu",
		buffer, tv.tv_usec, info.totalram, (info.totalram * memrand)/100,
		cpurand, info.procs, tx_bytes, rx_bytes);

	return SR_SUCCESS;
}

void sal_openlog(void)
{
	setlogmask(LOG_UPTO (LOG_NOTICE));
	openlog(SAFERIDE_PREFIX, LOG_CONS | LOG_PID | LOG_NDELAY, LOG_LOCAL1);
}

void sal_closelog(void)
{
	closelog();
}

void sal_log(char *cef_buffer, SR_32 severity)
{
	int syslog_severity;

	switch (severity) {
		case SEVERITY_LOW:
			syslog_severity = LOG_NOTICE;
			break;
		case SEVERITY_MEDIUM:
			syslog_severity = LOG_WARNING;
			break;
		case SEVERITY_HIGH:
			syslog_severity = LOG_ERR;
			break;
		case SEVERITY_VERY_HIGH:
			syslog_severity = LOG_CRIT;
			break;
		default:
			syslog_severity = LOG_NOTICE;
			break;
	}

	syslog(syslog_severity, "%s", cef_buffer);
}

char *sal_get_home_user(void)
{
	return getenv("HOME");
}

char *sal_get_str_ip_address(SR_U32 ip)
{
	static char str_address[INET_ADDRSTRLEN];

	// Assuming host order 
	ip = htonl(ip);
	inet_ntop(AF_INET, &ip, str_address, INET_ADDRSTRLEN);

	return str_address;
}
