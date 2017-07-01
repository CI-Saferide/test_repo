/* file: sal_linux.c
 * purpose: this file implements the sal functions for linux os
*/

#include "sal_linux.h"
#include "sr_tasks.h"
#include "sr_sal_common.h"

SR_32 sal_task_stop(void *data)
{
	struct task_struct *thread = (struct task_struct *)data;

	if (!thread) {
		sal_printf("sal_task_stop: invalid argument %p\n", data);
		return SR_ERROR;
	}

	kthread_stop(thread);

	thread = NULL;

	return SR_SUCCESS;
}

SR_32 sal_task_start(void **data, SR_32 (*task_func)(void *data))
{
	struct task_struct *thread;

	thread = kthread_create(task_func, NULL, "vsentry kernel thread");
	if (IS_ERR(thread)) {
		sal_printf("sal_task_start: failed to create new thread\n");
		return SR_ERROR;
	}

	*data = thread;

	sal_printf("sal_task_start: new task was created 0x%p 0x%p\n", thread, data);

	return SR_SUCCESS;
}

void sal_schedule_timeout(SR_U32 timeout)
{
	schedule_timeout_interruptible(usecs_to_jiffies(timeout));
}

void sal_schedule(void)
{
	set_current_state(TASK_INTERRUPTIBLE);
	schedule();
}

void *sal_memcpy(void *dest, void *src, SR_32 len)
{
	return memcpy(dest, src, len);
}

void *sal_memset(void *dest, SR_8 ch, SR_32 len)
{
	return memset(dest, ch, len);
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
	int i;
	va_list args;
	SR_8 msg[SR_MAX_LOG];

	va_start(args, fmt);
	i = vsnprintf(msg, SR_MAX_LOG-1, fmt, args);
	va_end(args);

	msg[SR_MAX_LOG - 1] = 0;
	printk("%s", msg);
}

