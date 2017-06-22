#include "sr_sal_common.h"
#include "sal_linux.h"
#include "sr_tasks.h"

SR_32 sal_task_stop(void *data)
{
	pthread_t *thread = (pthread_t*)data;

	if (!thread) {
		sal_printf("sal_task_stop: invalid argument %p\n", data);
		return SR_ERROR;
	}

	pthread_join(*thread, NULL);

	free(data);
	data = NULL;

	return SR_SUCCESS;
}

void* sal_dummy_func(void *func)
{
	SR_32 (*task_func)(void *data) = func;

	task_func(NULL);

	return NULL;
}

SR_32 sal_task_start(void **data, SR_32 (*task_func)(void *data))
{
	pthread_t *thread = (pthread_t*)malloc(sizeof(pthread_t));

	//if (pthread_create(thread, NULL, task_func, NULL) != 0) {
	if (pthread_create(thread, NULL, sal_dummy_func, task_func) != 0) {
		sal_printf("sal_task_start: failed to create new thread\n");
		free(thread);
		return SR_ERROR;
	}

	data = (void*)thread;

	sal_printf("sal_task_start: new task was created\n");

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

void sal_printf(SR_8 *fmt, ...)
{
	va_list args;
	SR_8 msg[SR_MAX_LOG];

	va_start(args, fmt);
	vsnprintf(msg, SR_MAX_LOG-1, fmt, args);
	va_end(args);

	msg[SR_MAX_LOG - 1] = 0;
	printf("%s", msg);
}
