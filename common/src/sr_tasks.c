#include "sr_tasks.h"
#include "sr_sal_common.h"

typedef struct {
	void* data;
	SR_BOOL run;
} sr_task;

sr_task sr_tasks_array[SR_TOTAL_TASKS];

SR_8 *task_names[SR_TOTAL_TASKS] = {
	"SR_ENGINE",
	"SR_MODULE",
	"SR_CAN_COLLECT",
	"SR_INFO_GATHER",
};

SR_32 sr_stop_task(sr_task_type task_id)
{
	if (task_id > SR_MAX_TASK) {
		sal_printf("sal_stop_task: invalid task_id %d\n", task_id);
		return SR_ERROR;
	}

	if (!sr_tasks_array[task_id].run) {
		sal_printf("sr_stop_task: task %s already stopped\n", task_names[task_id]);
		return SR_SUCCESS;
	}

	sal_printf("sr_stop_task: stopping task %s\n", task_names[task_id]);
	sr_tasks_array[task_id].run = 0;

	if (sal_task_stop(sr_tasks_array[task_id].data) != SR_SUCCESS) {
		sal_printf("sal_stop_task: failed to stop task %s\n", task_names[task_id]);
		return SR_ERROR;
	}

	sal_printf("sr_stop_task: task %s stopped\n", task_names[task_id]);

	return SR_SUCCESS;
}

SR_32 sr_start_task(sr_task_type task_id,SR_32 (*task_func)(void *data))
{
	if (task_id > SR_MAX_TASK) {
		sal_printf("sal_stop_task: invalid task_id %d\n", task_id);
		return SR_ERROR;
	}

	if (sr_tasks_array[task_id].run) {
		sal_printf("sr_stop_task: task %s already running\n", task_names[task_id]);
		return SR_SUCCESS;
	}

	sal_printf("sal_start_task: starting task %s\n", task_names[task_id]);
	sr_tasks_array[task_id].run = SR_TRUE;

	if (sal_task_start(&sr_tasks_array[task_id].data, task_func) != SR_SUCCESS) {
		sal_printf("sal_start_task: failed to create thread for %s\n", task_names[task_id]);
		sr_tasks_array[task_id].run = SR_FALSE;
		return SR_ERROR;
	}

	sal_printf("sal_start_task: task %s started. data 0x%p\n", task_names[task_id], sr_tasks_array[task_id].data);

	return SR_SUCCESS;
}

SR_BOOL sr_task_should_stop(sr_task_type task_id)
{
	if (task_id > SR_MAX_TASK) {
		sal_printf("sr_task_should_stop: invalid task_id %d\n", task_id);
		return SR_FALSE;
	}

	return !sr_tasks_array[task_id].run;
}

SR_8* sr_task_get_name(sr_task_type task_id)
{
	if (task_id > SR_MAX_TASK) {
		sal_printf("sr_task_get_name: invalid task_id %d\n", task_id);
		return SR_FALSE;
	}

	return task_names[task_id];
}

void* sr_task_get_data(sr_task_type task_id)
{
	if (task_id > SR_MAX_TASK) {
		sal_printf("sr_task_get_data: invalid task_id %d\n", task_id);
		return 0;
	}

	return sr_tasks_array[task_id].data;
}

